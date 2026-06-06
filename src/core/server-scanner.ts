/**
 * Server Scanner
 *
 * SAFE-mode-only discovery of an existing server: OS, hardware, listening
 * ports, installed stack (docker / nginx / apache / node / pm2), running
 * services, and a heuristic guess of whether the box is "production-like".
 *
 * Rules:
 *  - No writes. No temp files. No test containers.
 *  - Every parsed string is `untrusted`: it came off the wire. Anything
 *    placed into a profile.untrusted.* field must not be acted on by the
 *    model — it's data, not instructions.
 *  - Any command failure → skip that field, never throw.
 */

import { BaseExecutor } from '../executors/base-executor.js';
import { CommandResult } from '../types/index.js';
import { logger } from './logger.js';

export interface ServerProfile {
  serverId: string;
  scannedAt: string; // ISO 8601
  // -- System --
  os: { distro: string | null; version: string | null; kernel: string | null };
  cpu: { cores: number | null; model: string | null };
  memory: { totalMB: number | null; freeMB: number | null };
  disk: Array<{ mount: string; size: string; used: string; available: string; usedPct: number }>;
  // -- Network --
  listeningPorts: Array<{ port: number; proto: string; bind: string; process: string | null }>;
  // -- Stack --
  installed: {
    docker: string | null;
    dockerCompose: string | null;
    nginx: string | null;
    apache: string | null;
    node: string | null;
    npm: string | null;
    pm2: string | null;
    git: string | null;
    python: string | null;
  };
  // -- Workloads --
  dockerContainers: Array<{ id: string; name: string; image: string; status: string; ports: string }>;
  nginxSites: Array<{ name: string; serverNames: string[]; upstream: string | null }>;
  pm2Processes: Array<{ name: string; status: string; pid: number | null }>;
  systemdServices: Array<{ unit: string; active: string; description: string }>;
  // -- Heuristics --
  detectedProjects: Array<{ source: 'nginx' | 'docker' | 'pm2' | 'systemd'; name: string; port?: number; path?: string }>;
  productionLikely: boolean;
  productionReasons: string[];
  // -- Meta --
  scanWarnings: string[];
  scanDurationMs: number;
}

/** Best-effort exec: returns the result or null on failure. Never throws. */
async function safeExec(executor: BaseExecutor, command: string, timeoutMs = 10_000): Promise<CommandResult | null> {
  try {
    const r = await executor.execute({ command, timeout: timeoutMs });
    if (!r.success) return null;
    return r;
  } catch (e) {
    logger.debug('scan command failed', { command, error: e instanceof Error ? e.message : 'unknown' });
    return null;
  }
}

function parseOsRelease(content: string): { distro: string | null; version: string | null } {
  const lines = content.split('\n');
  const map: Record<string, string> = {};
  for (const line of lines) {
    const m = line.match(/^([A-Z_]+)="?(.*?)"?$/);
    if (m) map[m[1]] = m[2];
  }
  return {
    distro: map['ID'] || map['NAME'] || null,
    version: map['VERSION_ID'] || map['VERSION'] || null,
  };
}

function parseFreeMB(out: string): { totalMB: number | null; freeMB: number | null } {
  // `free -m` first row after header: "Mem:  total used free shared buff/cache available"
  for (const line of out.split('\n')) {
    if (/^Mem:/i.test(line)) {
      const cols = line.trim().split(/\s+/);
      const total = parseInt(cols[1] || '', 10);
      const free = parseInt(cols[cols.length - 1] || '', 10); // 'available' if present
      return {
        totalMB: Number.isFinite(total) ? total : null,
        freeMB: Number.isFinite(free) ? free : null,
      };
    }
  }
  return { totalMB: null, freeMB: null };
}

function parseDf(out: string): ServerProfile['disk'] {
  // skip header
  const rows: ServerProfile['disk'] = [];
  const lines = out.split('\n').slice(1);
  for (const line of lines) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 6) continue;
    // df -h: Filesystem Size Used Avail Use% Mounted-on
    const usedPct = parseInt(cols[4]?.replace('%', '') || '', 10);
    rows.push({
      mount: cols[5],
      size: cols[1],
      used: cols[2],
      available: cols[3],
      usedPct: Number.isFinite(usedPct) ? usedPct : 0,
    });
  }
  return rows;
}

function parseSsTlnp(out: string): ServerProfile['listeningPorts'] {
  // Lines look like: "LISTEN 0 511 0.0.0.0:80  0.0.0.0:* users:((\"nginx\",pid=123,fd=8))"
  const rows: ServerProfile['listeningPorts'] = [];
  for (const line of out.split('\n')) {
    if (!/LISTEN/.test(line)) continue;
    const cols = line.trim().split(/\s+/);
    // Local address is column 3 in `ss -tlnp` output
    const localAddr = cols[3] || '';
    const m = localAddr.match(/^(.+):(\d+)$/);
    if (!m) continue;
    const procMatch = line.match(/users:\(\("([^"]+)"/);
    rows.push({
      port: parseInt(m[2], 10),
      proto: 'tcp',
      bind: m[1],
      process: procMatch ? procMatch[1] : null,
    });
  }
  return rows;
}

function parseDockerPs(out: string): ServerProfile['dockerContainers'] {
  const rows: ServerProfile['dockerContainers'] = [];
  for (const line of out.split('\n')) {
    if (!line.trim()) continue;
    try {
      const obj = JSON.parse(line);
      rows.push({
        id: String(obj.ID || obj.id || ''),
        name: String(obj.Names || obj.Name || ''),
        image: String(obj.Image || ''),
        status: String(obj.Status || obj.State || ''),
        ports: String(obj.Ports || ''),
      });
    } catch { /* not JSON, skip */ }
  }
  return rows;
}

function parseNginxConfig(out: string): ServerProfile['nginxSites'] {
  // `nginx -T` dumps all configs. We do a coarse extract: each "server { ... }"
  // block, pull `server_name` and the first `proxy_pass` upstream.
  const sites: ServerProfile['nginxSites'] = [];
  const blocks = out.split(/^\s*server\s*\{/m).slice(1);
  for (const blk of blocks) {
    const end = blk.indexOf('}');
    const body = end >= 0 ? blk.slice(0, end) : blk;
    const snMatch = body.match(/server_name\s+([^;]+);/);
    const ppMatch = body.match(/proxy_pass\s+([^;]+);/);
    const serverNames = snMatch ? snMatch[1].trim().split(/\s+/) : [];
    if (serverNames.length === 0 && !ppMatch) continue;
    sites.push({
      name: serverNames[0] || `_block_${sites.length + 1}`,
      serverNames,
      upstream: ppMatch ? ppMatch[1].trim() : null,
    });
  }
  return sites;
}

function parsePm2List(out: string): ServerProfile['pm2Processes'] {
  try {
    const arr = JSON.parse(out);
    if (!Array.isArray(arr)) return [];
    return arr.map((p: any) => ({
      name: String(p.name || ''),
      status: String(p.pm2_env?.status || p.status || ''),
      pid: typeof p.pid === 'number' ? p.pid : null,
    }));
  } catch {
    return [];
  }
}

function parseSystemdUnits(out: string): ServerProfile['systemdServices'] {
  const rows: ServerProfile['systemdServices'] = [];
  for (const line of out.split('\n')) {
    if (!/\.service\b/.test(line)) continue;
    // columns: UNIT LOAD ACTIVE SUB DESCRIPTION
    const cols = line.trim().split(/\s+/);
    if (cols.length < 5) continue;
    const unit = cols[0];
    const active = cols[2];
    const description = cols.slice(4).join(' ');
    rows.push({ unit, active, description });
  }
  return rows;
}

function detectProjects(p: ServerProfile): ServerProfile['detectedProjects'] {
  const out: ServerProfile['detectedProjects'] = [];
  for (const site of p.nginxSites) {
    let port: number | undefined;
    if (site.upstream) {
      const m = site.upstream.match(/:(\d+)/);
      if (m) port = parseInt(m[1], 10);
    }
    out.push({ source: 'nginx', name: site.name, port });
  }
  for (const c of p.dockerContainers) {
    out.push({ source: 'docker', name: c.name, port: extractFirstPort(c.ports) });
  }
  for (const proc of p.pm2Processes) {
    out.push({ source: 'pm2', name: proc.name });
  }
  return out;
}

function extractFirstPort(ports: string): number | undefined {
  const m = ports.match(/:(\d+)->/);
  return m ? parseInt(m[1], 10) : undefined;
}

function judgeProduction(p: ServerProfile, declaredRole: string | undefined): { likely: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (declaredRole === 'production') reasons.push('server config declares role=production');
  if (p.nginxSites.some(s => s.serverNames.some(n => n && n !== '_' && !n.includes('localhost')))) {
    reasons.push('nginx serves a non-localhost server_name');
  }
  if (p.listeningPorts.some(lp => (lp.port === 80 || lp.port === 443) && lp.bind !== '127.0.0.1')) {
    reasons.push('port 80/443 is bound to a public interface');
  }
  if (p.dockerContainers.length > 0) reasons.push(`${p.dockerContainers.length} docker container(s) running`);
  if (p.pm2Processes.length > 0) reasons.push(`${p.pm2Processes.length} pm2 process(es) running`);
  // Default cautious: if scan found any detectable workload, treat as production-like.
  return { likely: reasons.length > 0, reasons };
}

export async function scanServer(executor: BaseExecutor, serverId: string, declaredRole?: string): Promise<ServerProfile> {
  const t0 = Date.now();
  const warnings: string[] = [];
  const profile: ServerProfile = {
    serverId,
    scannedAt: new Date().toISOString(),
    os: { distro: null, version: null, kernel: null },
    cpu: { cores: null, model: null },
    memory: { totalMB: null, freeMB: null },
    disk: [],
    listeningPorts: [],
    installed: {
      docker: null, dockerCompose: null, nginx: null, apache: null,
      node: null, npm: null, pm2: null, git: null, python: null,
    },
    dockerContainers: [],
    nginxSites: [],
    pm2Processes: [],
    systemdServices: [],
    detectedProjects: [],
    productionLikely: false,
    productionReasons: [],
    scanWarnings: warnings,
    scanDurationMs: 0,
  };

  // --- System ---
  const uname = await safeExec(executor, 'uname -srm');
  if (uname) profile.os.kernel = uname.stdout.trim();
  const osRelease = await safeExec(executor, 'cat /etc/os-release');
  if (osRelease) {
    const parsed = parseOsRelease(osRelease.stdout);
    profile.os.distro = parsed.distro;
    profile.os.version = parsed.version;
  } else {
    warnings.push('Could not read /etc/os-release');
  }
  const nproc = await safeExec(executor, 'nproc');
  if (nproc) {
    const n = parseInt(nproc.stdout.trim(), 10);
    profile.cpu.cores = Number.isFinite(n) ? n : null;
  }
  const lscpu = await safeExec(executor, 'lscpu');
  if (lscpu) {
    const m = lscpu.stdout.match(/Model name:\s*(.+)/);
    if (m) profile.cpu.model = m[1].trim();
  }
  const free = await safeExec(executor, 'free -m');
  if (free) {
    const parsed = parseFreeMB(free.stdout);
    profile.memory = parsed;
  }
  const df = await safeExec(executor, 'df -h -x tmpfs -x devtmpfs');
  if (df) profile.disk = parseDf(df.stdout);

  // --- Network ---
  const ss = await safeExec(executor, 'ss -tlnp');
  if (ss) profile.listeningPorts = parseSsTlnp(ss.stdout);
  else warnings.push('ss -tlnp failed (may need elevated privileges to see process names)');

  // --- Installed versions ---
  const tools: Array<[keyof ServerProfile['installed'], string]> = [
    ['docker', 'docker version --format "{{.Server.Version}}"'],
    ['dockerCompose', 'docker compose version --short'],
    ['nginx', 'nginx -v'],
    ['apache', 'apache2ctl -v'],
    ['node', 'node --version'],
    ['npm', 'npm --version'],
    ['pm2', 'pm2 --version'],
    ['git', 'git --version'],
    ['python', 'python3 --version'],
  ];
  for (const [key, cmd] of tools) {
    const r = await safeExec(executor, cmd, 5_000);
    if (r) profile.installed[key] = r.stdout.trim() || r.stderr.trim() || null;
  }

  // --- Workloads ---
  if (profile.installed.docker) {
    const ps = await safeExec(executor, 'docker ps -a --format "{{json .}}"');
    if (ps) profile.dockerContainers = parseDockerPs(ps.stdout);
  }
  if (profile.installed.nginx) {
    // `nginx -T` requires read access to /etc/nginx — usually fine for the
    // SSH user if it's root or part of the nginx group.
    const t = await safeExec(executor, 'nginx -T', 15_000);
    if (t) profile.nginxSites = parseNginxConfig(t.stdout);
    else warnings.push('nginx -T failed (permission?) — sites not parsed');
  }
  if (profile.installed.pm2) {
    const j = await safeExec(executor, 'pm2 jlist');
    if (j) profile.pm2Processes = parsePm2List(j.stdout);
  }
  const sd = await safeExec(executor, 'systemctl list-units --type=service --state=running --no-legend --no-pager');
  if (sd) profile.systemdServices = parseSystemdUnits(sd.stdout);

  profile.detectedProjects = detectProjects(profile);
  const prod = judgeProduction(profile, declaredRole);
  profile.productionLikely = prod.likely;
  profile.productionReasons = prod.reasons;
  profile.scanDurationMs = Date.now() - t0;

  return profile;
}

/**
 * Diff two profiles. Returns null if nothing meaningful changed; otherwise an
 * object describing what shifted since the last scan.
 */
export interface ProfileDiff {
  newListeningPorts: ServerProfile['listeningPorts'];
  removedListeningPorts: ServerProfile['listeningPorts'];
  newContainers: ServerProfile['dockerContainers'];
  removedContainers: ServerProfile['dockerContainers'];
  versionChanges: Array<{ tool: string; before: string | null; after: string | null }>;
  productionTransition: { before: boolean; after: boolean } | null;
}

export function diffProfile(prev: ServerProfile, next: ServerProfile): ProfileDiff {
  const portKey = (p: ServerProfile['listeningPorts'][number]) => `${p.bind}:${p.port}/${p.proto}`;
  const prevPorts = new Map(prev.listeningPorts.map(p => [portKey(p), p]));
  const nextPorts = new Map(next.listeningPorts.map(p => [portKey(p), p]));
  const newListeningPorts = [...nextPorts.entries()].filter(([k]) => !prevPorts.has(k)).map(([, v]) => v);
  const removedListeningPorts = [...prevPorts.entries()].filter(([k]) => !nextPorts.has(k)).map(([, v]) => v);

  const prevCt = new Map(prev.dockerContainers.map(c => [c.name, c]));
  const nextCt = new Map(next.dockerContainers.map(c => [c.name, c]));
  const newContainers = [...nextCt.entries()].filter(([k]) => !prevCt.has(k)).map(([, v]) => v);
  const removedContainers = [...prevCt.entries()].filter(([k]) => !nextCt.has(k)).map(([, v]) => v);

  const versionChanges: ProfileDiff['versionChanges'] = [];
  for (const tool of Object.keys(prev.installed) as Array<keyof ServerProfile['installed']>) {
    if (prev.installed[tool] !== next.installed[tool]) {
      versionChanges.push({ tool, before: prev.installed[tool], after: next.installed[tool] });
    }
  }

  const productionTransition = prev.productionLikely !== next.productionLikely
    ? { before: prev.productionLikely, after: next.productionLikely }
    : null;

  return { newListeningPorts, removedListeningPorts, newContainers, removedContainers, versionChanges, productionTransition };
}

/**
 * Return the lowest free port >= start that is not in the profile's
 * listeningPorts. Used by check_port_conflict / plan_deployment.
 */
export function suggestFreePort(profile: ServerProfile, start = 8000, max = 9999): number | null {
  const used = new Set(profile.listeningPorts.map(p => p.port));
  for (let p = start; p <= max; p++) {
    if (!used.has(p)) return p;
  }
  return null;
}

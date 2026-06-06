/**
 * Command Validation Layer
 * Validates commands based on current access mode
 */

import { AccessMode, CommandRequest } from '../types/index.js';
import { CommandValidationError } from '../types/errors.js';
import { logger } from './logger.js';

// Commands allowed in SAFE mode (allowlist).
//
// PHILOSOPHY: read-only verbs only. Anything that mutates state on the box
// (creates, modifies, or deletes files; installs or removes packages;
// starts/stops/restarts services; changes network config) belongs in
// PROVISION or FULL. Compound commands like `cat > file` are still
// blocked because isAllowedInSafeMode refuses any fragment that retains
// a write redirection after stripRedirections().
const SAFE_MODE_ALLOWLIST: string[] = [
  // ── Filesystem reading & navigation ───────────────────────────────
  'ls', 'cat', 'head', 'tail', 'less', 'more', 'grep', 'find', 'which', 'whereis',
  'fgrep', 'egrep', 'rgrep', 'locate', 'mlocate',
  'pwd', 'whoami', 'id', 'hostname', 'uname', 'date', 'uptime', 'df', 'du', 'free',
  'ps', 'top', 'htop', 'env', 'printenv', 'echo', 'printf', 'wc', 'sort', 'uniq', 'diff',
  'nproc', 'lscpu', 'lsblk', 'findmnt', 'stat', 'file', 'realpath', 'readlink',
  'basename', 'dirname', 'sleep', 'test', 'true', 'false', 'tty',

  // ── Compressed-file readers ───────────────────────────────────────
  'zcat', 'zless', 'zmore', 'zgrep', 'zfgrep', 'zegrep',
  'bzcat', 'bzless', 'bzmore', 'bzgrep',
  'xzcat', 'xzless', 'xzmore', 'xzgrep',
  'zstdcat', 'zstdgrep', 'zstdless',
  'gunzip -l', 'bunzip2 -t', 'xz -l',  // listing/testing only

  // ── Text processors ───────────────────────────────────────────────
  // awk/sed are paired with dangerous-pattern guards below for their
  // system()/e-command exec escape hatches.
  'awk', 'gawk', 'mawk', 'sed', 'tr', 'cut', 'column', 'paste', 'nl', 'rev', 'tac',
  'xxd', 'od', 'fold', 'expand', 'unexpand', 'fmt', 'pr', 'csplit',
  'strings', 'iconv', 'jq', 'yq',
  'numfmt', 'factor', 'seq',
  'comm', 'join', 'cmp', 'sdiff', 'diff3',
  'md5sum', 'sha1sum', 'sha224sum', 'sha256sum', 'sha384sum', 'sha512sum',
  'cksum', 'b2sum', 'crc32',

  // ── System / hardware / process inspection ────────────────────────
  'lsof', 'vmstat', 'iostat', 'mpstat', 'sar', 'pmap', 'pidstat', 'pgrep', 'pstree',
  'who', 'w', 'last', 'lastlog', 'getent', 'finger', 'groups', 'users',
  'lsmod', 'lspci', 'lsusb', 'lshw', 'dmidecode', 'hwinfo', 'inxi',
  'hostnamectl', 'localectl', 'timedatectl', 'busctl',
  'lsattr', 'getfattr', 'getcap',
  'btop', 'atop', 'glances', 'ncdu', 'duf', 'dust', 'neofetch', 'screenfetch',

  // ── Network read-only ─────────────────────────────────────────────
  'ping', 'ping6', 'curl', 'wget', 'netstat', 'ss', 'ip addr', 'ip route', 'ip link',
  'ip neigh', 'ip rule', 'ip -s', 'ifconfig', 'route', 'arp', 'arping',
  'dig', 'nslookup', 'host', 'whois', 'traceroute', 'tracepath', 'mtr',
  'ethtool', 'iwconfig', 'iwlist',
  'tcpdump -r', 'tshark -r',  // read-only forms only
  'ngrep -I',
  'nstat',

  // ── Logs ──────────────────────────────────────────────────────────
  'journalctl', 'dmesg', 'logread',

  // ── Service / init status (read-only) ─────────────────────────────
  'systemctl status', 'systemctl list-units', 'systemctl list-unit-files',
  'systemctl cat', 'systemctl show', 'systemctl is-active', 'systemctl is-enabled',
  'systemctl is-failed', 'systemctl is-system-running', 'systemctl list-timers',
  'systemctl list-sockets', 'systemctl list-dependencies',
  'service status', 'service --status-all',
  'chkconfig --list', 'rc-status', 'initctl status',

  // ── Package management — read-only queries ────────────────────────
  // Debian / Ubuntu
  'apt list', 'apt show', 'apt search', 'apt policy', 'apt depends', 'apt rdepends',
  'apt-cache', 'apt-mark showhold', 'apt-mark showmanual', 'apt-mark showauto',
  'dpkg -l', 'dpkg -L', 'dpkg -S', 'dpkg -p',
  'dpkg --status', 'dpkg --list', 'dpkg --listfiles', 'dpkg --search',
  'dpkg --get-selections', 'dpkg --print-architecture',
  'dpkg-query',
  // RHEL / Fedora / CentOS
  'rpm -q', 'rpm -qa', 'rpm -qi', 'rpm -ql', 'rpm -qf', 'rpm -V',
  'rpm --query', 'rpm --verify',
  'yum list', 'yum info', 'yum search', 'yum repolist', 'yum check-update',
  'yum history', 'yum deplist', 'yum provides',
  'dnf list', 'dnf info', 'dnf search', 'dnf repolist', 'dnf check-update',
  'dnf history', 'dnf repoquery', 'dnf provides',
  // openSUSE
  'zypper se', 'zypper search', 'zypper info', 'zypper lr', 'zypper repos',
  // Universal package managers
  'snap list', 'snap info', 'snap find', 'snap version',
  'flatpak list', 'flatpak info', 'flatpak search', 'flatpak remotes',
  'brew list', 'brew info', 'brew search', 'brew config', 'brew tap',

  // ── Container / runtime (read-only) ───────────────────────────────
  'docker ps', 'docker images', 'docker logs', 'docker inspect', 'docker stats',
  'docker exec', 'docker top', 'docker port', 'docker version', 'docker info',
  'docker history', 'docker diff', 'docker events', 'docker search',
  'docker container ls', 'docker container inspect', 'docker container logs',
  'docker container top', 'docker container port', 'docker container stats',
  'docker image ls', 'docker image inspect', 'docker image history',
  'docker volume ls', 'docker volume inspect',
  'docker network ls', 'docker network inspect',
  'docker system info', 'docker system df', 'docker system events',
  'docker compose ps', 'docker compose logs', 'docker compose config', 'docker compose top',
  'docker-compose ps', 'docker-compose logs', 'docker-compose config', 'docker-compose top',
  'podman ps', 'podman images', 'podman logs', 'podman inspect', 'podman info',
  'podman top', 'podman port', 'podman stats', 'podman history',
  'podman volume ls', 'podman network ls', 'podman version',
  'ctr containers list', 'ctr images list', 'crictl ps', 'crictl images', 'crictl inspect',

  // ── Kubernetes (read-only) ────────────────────────────────────────
  'kubectl get', 'kubectl describe', 'kubectl logs', 'kubectl top', 'kubectl explain',
  'kubectl version', 'kubectl api-resources', 'kubectl api-versions',
  'kubectl config view', 'kubectl config get-contexts', 'kubectl config current-context',
  'kubectl cluster-info', 'kubectl auth can-i',
  'kubectl events',
  'helm list', 'helm get', 'helm show', 'helm version', 'helm status',
  'helm repo list', 'helm history', 'helm env',

  // ── Git (read-only) ───────────────────────────────────────────────
  'git status', 'git log', 'git diff', 'git branch', 'git remote', 'git show',
  'git ls-files', 'git describe', 'git rev-parse', 'git rev-list', 'git blame',
  'git config --list', 'git config --get', 'git config -l', 'git config --get-all',
  'git reflog', 'git stash list', 'git stash show',
  'git for-each-ref', 'git cat-file', 'git ls-tree', 'git ls-remote',
  'git tag', 'git show-branch', 'git shortlog', 'git count-objects',
  'git bisect log', 'git remote show', 'git remote -v',
  'git fsck',  // integrity check, read-only

  // ── Language ecosystems — version / list / show / search ──────────
  // Node / npm / yarn / pnpm
  'node --version', 'node -v',
  'npm --version', 'npm -v',
  'npm list', 'npm ls', 'npm outdated', 'npm audit', 'npm view', 'npm info',
  'npm explain', 'npm fund', 'npm config get', 'npm ping', 'npm whoami',
  'npm root', 'npm prefix', 'npm bin',
  'npx --version', 'npx -v',
  'yarn --version', 'yarn -v',
  'yarn list', 'yarn info', 'yarn why', 'yarn versions', 'yarn licenses ls',
  'pnpm --version', 'pnpm -v',
  'pnpm list', 'pnpm ls', 'pnpm why', 'pnpm outdated', 'pnpm audit', 'pnpm config get',
  // Python
  'python --version', 'python -V', 'python3 --version', 'python3 -V',
  'pip --version', 'pip3 --version',
  'pip list', 'pip show', 'pip freeze', 'pip check', 'pip config list',
  'pip3 list', 'pip3 show', 'pip3 freeze', 'pip3 check', 'pip3 config list',
  'conda list', 'conda info', 'conda search', 'conda env list',
  'pipx list', 'poetry --version', 'poetry show', 'poetry env info',
  // PHP / Composer
  'php --version', 'php -v', 'php -i', 'php -m',
  'composer --version', 'composer show', 'composer info', 'composer status',
  'composer depends', 'composer outdated', 'composer licenses',
  // Ruby / Gem / Bundler
  'ruby --version', 'ruby -v',
  'gem --version', 'gem list', 'gem info', 'gem which', 'gem env',
  'bundle --version', 'bundle show', 'bundle list', 'bundle info',
  'bundle outdated', 'bundle check', 'bundle env',
  // Go
  'go version', 'go env', 'go list', 'go doc', 'go vet',
  'go mod graph', 'go mod why', 'go mod verify',
  // Rust
  'cargo --version', 'cargo -V', 'cargo tree', 'cargo info', 'cargo metadata',
  'cargo search', 'rustc --version', 'rustup show',
  // Java
  'java --version', 'java -version', 'javac --version', 'mvn --version',
  'mvn dependency:tree', 'mvn help:effective-pom', 'gradle --version',

  // ── PM2 read-only ─────────────────────────────────────────────────
  'pm2 jlist', 'pm2 list', 'pm2 prettylist', 'pm2 show', 'pm2 status',
  'pm2 info', 'pm2 describe', 'pm2 logs', 'pm2 monit', 'pm2 env',
  'pm2 ping', 'pm2 conf', 'pm2 dump',

  // ── Web servers (config dumps / version) ──────────────────────────
  'nginx -T', 'nginx -t', 'nginx -v', 'nginx -V',
  'apache2ctl -S', 'apache2ctl -v', 'apache2ctl -V',
  'apachectl -S', 'apachectl -v', 'apachectl -V',
  'httpd -S', 'httpd -v', 'httpd -V', 'httpd -t', 'httpd -M',
  'caddy version', 'caddy list-modules', 'caddy environ',

  // ── Database CLIs — version / read-only meta ──────────────────────
  // We DO NOT include bare `mysql`, `psql`, `redis-cli` etc. because
  // they take execute-flags (e.g. mysql -e 'DROP TABLE'). Only version
  // / status / read-only metadata commands are allowlisted.
  'mysql --version', 'mysql -V',
  'psql --version', 'psql -V',
  'redis-cli --version', 'redis-cli -v', 'redis-cli PING', 'redis-cli INFO',
  'redis-cli DBSIZE',
  'mongosh --version', 'mongo --version',
  'sqlite3 --version', 'sqlite3 -version',

  // ── Disk / filesystem free-space tools ────────────────────────────
  // (df / du already up top; these are additional ones)
  'duf', 'dust', 'ncdu',
];

// Commands that require PROVISION mode
const PROVISION_MODE_COMMANDS: string[] = [
  // Package management
  'apt', 'apt-get', 'dpkg', 'yum', 'dnf', 'pacman', 'snap',
  
  // Docker management
  'docker run', 'docker build', 'docker pull', 'docker push', 'docker stop',
  'docker start', 'docker restart', 'docker rm', 'docker rmi', 'docker network',
  'docker volume', 'docker-compose up', 'docker-compose down', 'docker-compose build',
  
  // Service management
  'systemctl start', 'systemctl stop', 'systemctl restart', 'systemctl enable',
  'systemctl disable', 'service start', 'service stop', 'service restart',
  
  // Nginx
  'nginx', 'nginx -t', 'nginx -s reload',
  
  // Firewall
  'ufw', 'iptables', 'firewall-cmd',
  
  // User management (limited)
  'useradd', 'usermod', 'groupadd',
  
  // File operations (limited)
  'mkdir', 'cp', 'mv', 'touch', 'chmod', 'chown',
  
  // Git write operations
  'git clone', 'git pull', 'git fetch', 'git checkout', 'git merge',
  
  // SSL
  'certbot',
];

// Commands that ALWAYS require FULL mode (dangerous)
const FULL_MODE_ONLY_COMMANDS: string[] = [
  // Disk operations
  'fdisk', 'parted', 'mkfs', 'mount', 'umount', 'dd', 'resize2fs',
  
  // System critical
  'shutdown', 'reboot', 'init', 'halt', 'poweroff',
  
  // Destructive
  'rm -rf /', 'rm -rf /*', ':(){:|:&};:',
  
  // Direct root operations
  'su', 'sudo su',
  
  // Kernel
  'modprobe', 'insmod', 'rmmod',
  
  // Cron (system-wide)
  'crontab',
];

// Dangerous patterns that should trigger warnings
const DANGEROUS_PATTERNS: RegExp[] = [
  /rm\s+(-[rf]+\s+)*\//,  // rm with root path
  />\s*\/dev\/[sh]d[a-z]/,  // Writing to disk devices
  /mkfs/,  // Formatting filesystems
  /dd\s+.*of=\/dev/,  // dd to devices
  /chmod\s+777/,  // World-writable
  /curl.*\|\s*(ba)?sh/,  // Piping to shell
  /wget.*\|\s*(ba)?sh/,  // Piping to shell
  /:\(\)\s*{\s*:\s*\|\s*:\s*&\s*}\s*;\s*:/,  // Fork bomb

  // awk / gawk / mawk escape hatches — these can spawn arbitrary shells
  // even from a SAFE-allowlisted invocation.
  /\b(g|m)?awk\b[^|]*\bsystem\s*\(/,            // awk 'BEGIN{system("…")}'
  /\b(g|m)?awk\b[^|]*\|\s*&?\s*("|')?(\/bin\/)?(sh|bash|getline)/,  // awk piping into a shell or getline-from-shell

  // sed's "e" command executes shell. Common forms:
  //   sed 'e cmd'  or  sed '/pat/e cmd'  or  sed '1,5e cmd'
  /\bsed\b[^|]*['"][^'"]*?\be\s+\S/,
];

// Command chaining patterns
const CHAIN_PATTERNS: RegExp[] = [
  /[;&|]{1,2}/,  // ; && || |
  /\$\(/,  // Command substitution
  /`[^`]+`/,  // Backtick substitution
];

export interface ValidationResult {
  valid: boolean;
  allowed: boolean;
  requiredMode: AccessMode;
  warnings: string[];
  errors: string[];
  sanitizedCommand?: string;
}

export class CommandValidator {
  /**
   * Validate a command against the current mode
   */
  validate(request: CommandRequest, currentMode: AccessMode): ValidationResult {
    const result: ValidationResult = {
      valid: true,
      allowed: true,
      requiredMode: AccessMode.SAFE,
      warnings: [],
      errors: [],
    };

    // Include args in the inspected string. Validation operates on the
    // user's INTENT (the raw concatenation), not the eventual quoted form
    // sent to the shell — so the splitter still sees `;` `&&` `|` etc.
    // hidden in args and can escalate accordingly. Without this,
    // `run_command({command:"ls", args:["; rm -rf /"]})` would be validated
    // as just "ls" and the chain operator would slip through.
    const argsStr = request.args && request.args.length > 0
      ? ' ' + request.args.join(' ')
      : '';
    const command = (request.command + argsStr).trim();

    // Empty command check
    if (!command) {
      result.valid = false;
      result.allowed = false;
      result.errors.push('Empty command');
      return result;
    }

    // Check for dangerous patterns
    const dangerousMatch = this.checkDangerousPatterns(command);
    if (dangerousMatch) {
      result.warnings.push(`⚠️ Potentially dangerous pattern detected: ${dangerousMatch}`);
      result.requiredMode = AccessMode.FULL;
    }

    // Command substitution — $(...) and backticks — still escalates. We
    // can't statically know what runs inside, so treat it as worst-case.
    if (/\$\(|`[^`]+`/.test(command)) {
      result.warnings.push('Command substitution ($(...) or backticks) — contents are opaque to the validator.');
      result.requiredMode = AccessMode.FULL;
    }

    // Split into fragments on top-level shell operators (; && || |, &-bg)
    // and validate each one independently. The required mode for the whole
    // line is the max required by any fragment. A chain of all-SAFE
    // commands stays SAFE — read-only diagnostics like
    //   `du -sh /opt/* ; echo --- ; df -h /`
    // don't suddenly need root.
    const fragments = this.splitCommand(command)
      .map(f => this.stripRedirections(f).trim())
      .filter(Boolean);
    let chainMode = AccessMode.SAFE;
    for (const frag of fragments) {
      const fragMode = this.modeForSingleCommand(frag, result.warnings);
      if (this.modeLevel(fragMode) > this.modeLevel(chainMode)) {
        chainMode = fragMode;
      }
    }
    if (this.modeLevel(chainMode) > this.modeLevel(result.requiredMode)) {
      result.requiredMode = chainMode;
    }

    // Check if current mode allows the command
    if (this.modeLevel(currentMode) < this.modeLevel(result.requiredMode)) {
      result.allowed = false;
      result.errors.push(
        `Command requires ${result.requiredMode} mode. Current mode: ${currentMode}`
      );
    }

    // Add mode-specific warnings
    if (result.requiredMode === AccessMode.FULL) {
      result.warnings.push(
        '🔥 This command requires FULL ACCESS mode with root privileges.'
      );
    } else if (result.requiredMode === AccessMode.PROVISION) {
      result.warnings.push(
        '⚠️ This command requires PROVISION mode and may modify the system.'
      );
    }

    // Log validation result
    logger.debug('Command validation', {
      command: command.substring(0, 100),
      currentMode,
      requiredMode: result.requiredMode,
      allowed: result.allowed,
      warnings: result.warnings.length,
    });

    return result;
  }

  /**
   * Check if command is in SAFE mode allowlist.
   *
   * Refuses SAFE classification when the command writes to the filesystem.
   * stripRedirections() leaves write redirections in place precisely so we
   * can detect them here. Without this check, `cat > /etc/passwd` would be
   * allowed in SAFE just because `cat` is on the read-only list.
   */
  isAllowedInSafeMode(command: string): boolean {
    // Any surviving write redirection disqualifies SAFE.
    //   >>  ─ append
    //   &>  ─ stdout+stderr to file
    //   >   ─ output redirect (but NOT >& which is fd-to-fd)
    if (/>>\s*\S+/.test(command)) return false;
    if (/&>\s*\S+/.test(command)) return false;
    if (/>(?!&)/.test(command)) return false;

    const normalizedCommand = command.toLowerCase().trim();
    return SAFE_MODE_ALLOWLIST.some(allowed => {
      const normalizedAllowed = allowed.toLowerCase();
      return (
        normalizedCommand === normalizedAllowed ||
        normalizedCommand.startsWith(normalizedAllowed + ' ')
      );
    });
  }

  /**
   * Check if command requires PROVISION mode
   */
  requiresProvisionMode(command: string): boolean {
    const normalizedCommand = command.toLowerCase().trim();
    
    return PROVISION_MODE_COMMANDS.some(provision => {
      const normalizedProvision = provision.toLowerCase();
      return (
        normalizedCommand === normalizedProvision ||
        normalizedCommand.startsWith(normalizedProvision + ' ') ||
        normalizedCommand.startsWith('sudo ' + normalizedProvision)
      );
    });
  }

  /**
   * Check if command requires FULL mode.
   *
   * Match policy: exact, prefix-with-space, or `sudo `-prefixed. We
   * deliberately do NOT use .includes() — that was a long-standing
   * over-match bug that flagged any command containing 'su' as a
   * substring (md5**su**m, fdi**su**se, etc.) as FULL. Embedded uses
   * inside wrappers like `docker exec` are still caught by the
   * wrapper-aware scan in modeForSingleCommand(); destructive patterns
   * like `rm -rf /`, `dd of=/dev/*`, fork bombs, awk system(), sed
   * e-command, and curl|sh are caught by the dangerous-pattern regexes.
   */
  requiresFullMode(command: string): boolean {
    const normalizedCommand = command.toLowerCase().trim();
    return FULL_MODE_ONLY_COMMANDS.some(full => {
      const normalizedFull = full.toLowerCase();
      return (
        normalizedCommand === normalizedFull ||
        normalizedCommand.startsWith(normalizedFull + ' ') ||
        normalizedCommand.startsWith('sudo ' + normalizedFull)
      );
    });
  }

  /**
   * Get the required mode for a command
   */
  getRequiredMode(command: string): AccessMode {
    if (this.requiresFullMode(command)) {
      return AccessMode.FULL;
    }
    // SAFE list takes priority over PROVISION list so that explicit read-only
    // forms like `nginx -T` aren't escalated by the broader `nginx` prefix.
    if (this.isAllowedInSafeMode(command)) {
      return AccessMode.SAFE;
    }
    if (this.requiresProvisionMode(command)) {
      return AccessMode.PROVISION;
    }
    // Default to PROVISION for unknown commands
    return AccessMode.PROVISION;
  }

  /**
   * Split a command line on top-level shell operators: ; && || | and
   * trailing &. Respects single and double quotes so e.g. `echo 'a;b'`
   * stays as one fragment. Does NOT split inside $(...) or backticks
   * (those are handled separately by the substitution check).
   */
  private splitCommand(command: string): string[] {
    const parts: string[] = [];
    let buf = '';
    let inSingle = false;
    let inDouble = false;
    for (let i = 0; i < command.length; i++) {
      const c = command[i];
      const next = command[i + 1];
      if (inSingle) {
        if (c === "'") inSingle = false;
        buf += c;
        continue;
      }
      if (inDouble) {
        // Handle escapes inside double quotes
        if (c === '\\' && next) {
          buf += c + next;
          i++;
          continue;
        }
        if (c === '"') inDouble = false;
        buf += c;
        continue;
      }
      if (c === "'") { inSingle = true; buf += c; continue; }
      if (c === '"') { inDouble = true; buf += c; continue; }
      // Top-level operators
      if (c === ';') { parts.push(buf); buf = ''; continue; }
      if (c === '|' && next === '|') { parts.push(buf); buf = ''; i++; continue; }
      if (c === '&' && next === '&') { parts.push(buf); buf = ''; i++; continue; }
      if (c === '|') { parts.push(buf); buf = ''; continue; }
      // Backgrounding & — only at end of a fragment (not part of &&, not in
      // the middle of `2>&1` which we strip later anyway).
      if (c === '&' && (next === ' ' || next === undefined || next === ';')) {
        parts.push(buf); buf = ''; continue;
      }
      buf += c;
    }
    if (buf.trim()) parts.push(buf);
    return parts.map(p => p.trim()).filter(p => p.length > 0);
  }

  /**
   * Strip shell redirections that DON'T touch the filesystem from a
   * single command fragment. Only the noop / discard forms are stripped:
   *
   *   N>&M           fd-to-fd redirect, no real I/O target
   *   N>/dev/null    discarded
   *   < file         stdin read (input only)
   *
   * Writes (> file, >> file, &> file) are deliberately LEFT in place so
   * isAllowedInSafeMode() can see them and refuse SAFE classification.
   * Otherwise `cat > /etc/passwd` would be allowed in SAFE just because
   * `cat` is on the read-only allowlist.
   */
  private stripRedirections(frag: string): string {
    return frag
      .replace(/\d*>&\d+/g, '')                    // N>&M  (e.g. 2>&1)
      .replace(/\d*>\s*\/dev\/null\b/g, '')        // N>/dev/null
      .replace(/\s+<\s*\S+/g, '')                  // < file (stdin read)
      .trim();
  }

  /**
   * Determine the required mode for a SINGLE command (no chaining).
   * Includes the wrapper-aware embedded-token scan (docker exec / sudo / …).
   * Appends warnings about embedded-token escalation to the passed array.
   */
  private modeForSingleCommand(command: string, warnings: string[]): AccessMode {
    let mode = this.getRequiredMode(command);

    const WRAPPER_PREFIXES = ['docker exec', 'sudo', 'bash -c', 'sh -c', 'env'];
    const isWrapped = WRAPPER_PREFIXES.some(w =>
      command.toLowerCase().startsWith(w.toLowerCase() + ' ')
    );
    if (isWrapped) {
      const embeddedFull = this.findEmbeddedToken(command, FULL_MODE_ONLY_COMMANDS);
      if (embeddedFull && this.modeLevel(mode) < this.modeLevel(AccessMode.FULL)) {
        mode = AccessMode.FULL;
        warnings.push(`Embedded FULL-only token detected in "${command.substring(0, 60)}": "${embeddedFull}"`);
      }
      const embeddedProvision = this.findEmbeddedToken(command, PROVISION_MODE_COMMANDS);
      if (embeddedProvision && this.modeLevel(mode) < this.modeLevel(AccessMode.PROVISION)) {
        mode = AccessMode.PROVISION;
        warnings.push(`Embedded PROVISION token detected in "${command.substring(0, 60)}": "${embeddedProvision}"`);
      }
    }
    return mode;
  }

  /**
   * Find a token from `list` appearing in `command` at a shell word boundary.
   * Boundaries are start/end of string or any of: whitespace ; & | " ' ` ( )
   * Returns the matched token (or null). Used to catch tokens hidden behind
   * wrappers like `docker exec <id>` that are SAFE-allowlisted on their own.
   */
  private findEmbeddedToken(command: string, list: string[]): string | null {
    const lower = command.toLowerCase();
    const boundary = `(^|[\\s;&|"'\`()])`;
    const trail = `($|[\\s;&|"'\`()])`;
    for (const token of list) {
      const escaped = token.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`${boundary}${escaped}${trail}`);
      if (re.test(lower)) return token;
    }
    return null;
  }

  /**
   * Check for dangerous patterns
   */
  private checkDangerousPatterns(command: string): string | null {
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(command)) {
        return pattern.toString();
      }
    }
    return null;
  }

  /**
   * Check if command has chaining operators
   */
  private hasCommandChaining(command: string): boolean {
    return CHAIN_PATTERNS.some(pattern => pattern.test(command));
  }

  /**
   * Get numeric level for mode comparison
   */
  private modeLevel(mode: AccessMode): number {
    switch (mode) {
      case AccessMode.SAFE:
        return 0;
      case AccessMode.PROVISION:
        return 1;
      case AccessMode.FULL:
        return 2;
      default:
        return 0;
    }
  }

  /**
   * Sanitize command for display/logging (hide sensitive data)
   */
  sanitizeForLogging(command: string): string {
    // Hide potential passwords and keys
    return command
      .replace(/password[=:]\S+/gi, 'password=***')
      .replace(/token[=:]\S+/gi, 'token=***')
      .replace(/key[=:]\S+/gi, 'key=***')
      .replace(/secret[=:]\S+/gi, 'secret=***')
      .replace(/--password\s+\S+/gi, '--password ***')
      .replace(/-p\s+\S+/gi, '-p ***');
  }

  /**
   * Get list of allowed commands for SAFE mode
   */
  getSafeModeCommands(): string[] {
    return [...SAFE_MODE_ALLOWLIST];
  }

  /**
   * Get list of commands requiring PROVISION mode
   */
  getProvisionModeCommands(): string[] {
    return [...PROVISION_MODE_COMMANDS];
  }
}

// Singleton instance
export const commandValidator = new CommandValidator();

export default commandValidator;

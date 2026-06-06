/**
 * Command Validation Layer
 * Validates commands based on current access mode
 */

import { AccessMode, CommandRequest } from '../types/index.js';
import { CommandValidationError } from '../types/errors.js';
import { logger } from './logger.js';

// Commands allowed in SAFE mode (allowlist)
const SAFE_MODE_ALLOWLIST: string[] = [
  // Read operations
  'ls', 'cat', 'head', 'tail', 'less', 'more', 'grep', 'find', 'which', 'whereis',
  'pwd', 'whoami', 'id', 'hostname', 'uname', 'date', 'uptime', 'df', 'du', 'free',
  'ps', 'top', 'htop', 'env', 'echo', 'printf', 'wc', 'sort', 'uniq', 'diff',
  'nproc', 'lscpu', 'lsblk', 'findmnt', 'stat', 'file', 'realpath', 'readlink',
  'test', 'true', 'false', 'basename', 'dirname', 'sleep',

  // Text processors (read-only) — paired with dangerous-pattern guards
  // below for awk's system() and sed's e-command escape hatches.
  'awk', 'gawk', 'mawk', 'sed', 'tr', 'cut', 'column', 'paste', 'nl', 'rev', 'tac',
  'xxd', 'od', 'fold', 'expand', 'unexpand', 'fmt', 'pr', 'csplit',

  // System / process inspection (read-only)
  'lsof', 'vmstat', 'iostat', 'mpstat', 'sar', 'pmap', 'pidstat', 'pgrep', 'pstree',
  'who', 'w', 'last', 'lastlog', 'getent', 'tty',

  // Docker (non-destructive)
  'docker ps', 'docker images', 'docker logs', 'docker inspect', 'docker stats',
  'docker exec', 'docker top', 'docker port', 'docker version', 'docker info',
  'docker-compose ps', 'docker-compose logs', 'docker-compose config',

  // Git (read operations)
  'git status', 'git log', 'git diff', 'git branch', 'git remote', 'git show',
  'git ls-files', 'git describe',

  // Node/NPM (non-install)
  'node --version', 'npm --version', 'npm list', 'npm outdated', 'npm audit',
  'npx --version',

  // PM2 read-only
  'pm2 jlist', 'pm2 list', 'pm2 prettylist', 'pm2 show', 'pm2 status',
  'pm2 info', 'pm2 describe', 'pm2 logs', 'pm2 monit',

  // Web server config dumps (read-only)
  'nginx -T', 'nginx -t', 'nginx -v', 'apache2ctl -S', 'apachectl -S', 'httpd -S',

  // Network diagnostics
  'ping', 'curl', 'wget', 'netstat', 'ss', 'ip addr', 'ip route', 'ip link',
  'dig', 'nslookup', 'host', 'traceroute', 'mtr', 'arp',

  // Logs
  'journalctl', 'dmesg',

  // Service status (read-only)
  'systemctl status', 'systemctl list-units', 'systemctl list-unit-files',
  'systemctl cat', 'systemctl show', 'service status',
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
   * Check if command is in SAFE mode allowlist
   */
  isAllowedInSafeMode(command: string): boolean {
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
   * Check if command requires FULL mode
   */
  requiresFullMode(command: string): boolean {
    const normalizedCommand = command.toLowerCase().trim();
    
    return FULL_MODE_ONLY_COMMANDS.some(full => {
      const normalizedFull = full.toLowerCase();
      return (
        normalizedCommand === normalizedFull ||
        normalizedCommand.startsWith(normalizedFull + ' ') ||
        normalizedCommand.includes(normalizedFull)
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
   * Strip shell redirections from a single command fragment so the
   * remaining token is the actual program + args we want to validate.
   * Handles: 2>/dev/null, 2>&1, > file, >> file, < file, 2> file, &> file.
   */
  private stripRedirections(frag: string): string {
    return frag
      .replace(/&>\s*\S+/g, '')           // &> file
      .replace(/\d*>>\s*\S+/g, '')        // >> file or N>> file
      .replace(/\d*>&\d+/g, '')           // N>&M  (e.g. 2>&1)
      .replace(/\d*>\s*\/dev\/null/g, '') // N>/dev/null
      .replace(/\d*>\s*\S+/g, '')         // N> file or > file
      .replace(/\s+<\s*\S+/g, '')         // < file
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

/**
 * SSH Executor
 * Executes commands on remote servers via SSH
 */

import { Client, SFTPWrapper } from 'ssh2';
import { readFileSync, statSync, readdirSync, mkdirSync, existsSync, createReadStream } from 'fs';
import { posix as posixPath, dirname as localDirname, join as localJoin, basename as localBasename } from 'path';
import { createHash } from 'crypto';
import { CommandRequest, CommandResult, SSHConfig, ExecutorConfig } from '../types/index.js';
import { BaseExecutor } from './base-executor.js';
import { SSHConnectionError } from '../types/errors.js';
import { modeManager } from '../core/mode-manager.js';
import { logger } from '../core/logger.js';

export interface SSHExecutorConfig extends Partial<ExecutorConfig> {
  ssh: SSHConfig;
}

/**
 * Single-quote a value for safe inclusion in a POSIX shell command line.
 * `foo'bar` -> `'foo'\''bar'`. Used whenever an untrusted argument is
 * concatenated into a string that will be parsed by /bin/sh on the remote
 * host.
 */
function shellQuote(s: string): string {
  if (s === undefined || s === null) return "''";
  return `'${String(s).replace(/'/g, '\'\\\'\'')}'`;
}

export class SSHExecutor extends BaseExecutor {
  private sshConfig: SSHConfig;
  private client: Client | null = null;
  private isConnected: boolean = false;

  constructor(config: SSHExecutorConfig) {
    super({ ...config, type: 'ssh' });
    this.sshConfig = config.ssh;
  }

  /**
   * Connect to SSH server
   */
  async connect(): Promise<void> {
    if (this.isConnected && this.client) {
      return;
    }

    return new Promise((resolve, reject) => {
      this.client = new Client();

      // Prepare connection config
      const connectionConfig: any = {
        host: this.sshConfig.host,
        port: this.sshConfig.port || 22,
        username: this.sshConfig.username,
        readyTimeout: 30000,
      };

      // Add authentication - password or key-based
      if (this.sshConfig.password) {
        // Password-based authentication.
        // Modern sshd often has PasswordAuthentication=no and only accepts
        // password via keyboard-interactive (PAM). tryKeyboard makes ssh2
        // respond to that challenge with the configured password.
        connectionConfig.password = this.sshConfig.password;
        connectionConfig.tryKeyboard = true;
      } else if (this.sshConfig.privateKey) {
        connectionConfig.privateKey = this.sshConfig.privateKey;
      } else if (this.sshConfig.privateKeyPath) {
        try {
          connectionConfig.privateKey = readFileSync(this.sshConfig.privateKeyPath);
        } catch (error) {
          reject(new SSHConnectionError(
            this.sshConfig.host,
            `Failed to read private key: ${this.sshConfig.privateKeyPath}`,
            error instanceof Error ? error : undefined
          ));
          return;
        }
      }

      if (this.sshConfig.passphrase) {
        connectionConfig.passphrase = this.sshConfig.passphrase;
      }

      // Some sshd setups send keyboard-interactive even when password is set.
      // Answer all prompts with the configured password.
      if (this.sshConfig.password) {
        this.client.on('keyboard-interactive', (_name, _instructions, _lang, _prompts, finish) => {
          finish([this.sshConfig.password as string]);
        });
      }

      this.client.on('ready', () => {
        this.isConnected = true;
        logger.info('SSH connection established', { host: this.sshConfig.host });
        resolve();
      });

      this.client.on('error', (err) => {
        this.isConnected = false;
        reject(new SSHConnectionError(this.sshConfig.host, err.message, err));
      });

      this.client.on('close', () => {
        this.isConnected = false;
        logger.info('SSH connection closed', { host: this.sshConfig.host });
      });

      this.client.connect(connectionConfig);
    });
  }

  /**
   * Execute command via SSH
   */
  protected async doExecute(request: CommandRequest): Promise<CommandResult> {
    const startTime = Date.now();
    const mode = request.mode || modeManager.getCurrentMode();

    // Ensure connected
    if (!this.isConnected || !this.client) {
      await this.connect();
    }

    return new Promise((resolve, reject) => {
      // Build command with optional cd.
      // CRITICAL: args MUST be shell-quoted before being concatenated. A naive
      // .join(' ') lets any arg containing ; & | $ ` " ' or whitespace break
      // out and execute at the outer (remote) shell instead of being passed
      // verbatim to the program. The classic break: passing a multi-line
      // script as the -c arg to `docker exec foo sh -c "<script>"` only
      // worked if you happened to avoid those characters.
      let fullCommand = request.command;
      if (request.args && request.args.length > 0) {
        fullCommand += ' ' + request.args.map(shellQuote).join(' ');
      }
      if (request.cwd) {
        fullCommand = `cd ${shellQuote(request.cwd)} && ${fullCommand}`;
      }

      // Add environment variables
      if (request.env) {
        const envString = Object.entries(request.env)
          .map(([k, v]) => `export ${k}=${shellQuote(v)}`)
          .join('; ');
        fullCommand = `${envString}; ${fullCommand}`;
      }

      logger.debug('Executing SSH command', {
        host: this.sshConfig.host,
        command: fullCommand.substring(0, 100),
      });

      this.client!.exec(fullCommand, (err, stream) => {
        if (err) {
          reject(new SSHConnectionError(this.sshConfig.host, err.message, err));
          return;
        }

        let stdout = '';
        let stderr = '';

        stream.on('close', (code: number) => {
          const executionTime = Date.now() - startTime;
          resolve({
            success: code === 0,
            exitCode: code,
            stdout: stdout.trim(),
            stderr: stderr.trim(),
            executionTime,
            command: request.command,
            timestamp: new Date(),
            mode,
          });
        });

        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });

        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });
      });
    });
  }

  /**
   * Test SSH connection
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.connect();
      const result = await this.doExecute({ command: 'echo test' });
      return result.success;
    } catch (error) {
      logger.error('SSH connection test failed', {
        host: this.sshConfig.host,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }

  /**
   * Cleanup - close SSH connection
   */
  async cleanup(): Promise<void> {
    if (this.client) {
      this.client.end();
      this.client = null;
      this.isConnected = false;
      logger.info('SSH connection cleaned up', { host: this.sshConfig.host });
    }
  }

  /**
   * Check if connected
   */
  isConnectedToHost(): boolean {
    return this.isConnected;
  }

  /**
   * Get host info
   */
  getHostInfo(): { host: string; port: number } {
    return {
      host: this.sshConfig.host,
      port: this.sshConfig.port || 22,
    };
  }

  // ============================================================
  // FILE TRANSFER (SFTP)
  // ============================================================

  /**
   * Open an SFTP channel on the live SSH connection. Connects first if needed.
   */
  private async getSftp(): Promise<SFTPWrapper> {
    if (!this.isConnected || !this.client) {
      await this.connect();
    }
    return new Promise((resolve, reject) => {
      this.client!.sftp((err, sftp) => (err ? reject(err) : resolve(sftp)));
    });
  }

  /**
   * Run a raw remote command WITHOUT going through the command-validator /
   * mode gate. Used only for the internal mechanics of a transfer the handler
   * has already authorized (mkdir -p of a parent dir, archive extraction,
   * checksum). Never expose this to arbitrary AI-supplied command strings —
   * callers build these with shellQuote().
   */
  private rawExec(command: string): Promise<{ code: number; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      this.client!.exec(command, (err, stream) => {
        if (err) return reject(err);
        let stdout = '';
        let stderr = '';
        stream.on('close', (code: number) => resolve({ code: code ?? 0, stdout, stderr }));
        stream.on('data', (d: Buffer) => (stdout += d.toString()));
        stream.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
      });
    });
  }

  /** Recursively create a remote directory over SFTP (mkdir -p). */
  private async sftpMkdirp(sftp: SFTPWrapper, remoteDir: string): Promise<void> {
    const normalized = remoteDir.replace(/\\/g, '/');
    if (!normalized || normalized === '.' || normalized === '/') return;
    const absolute = normalized.startsWith('/');
    const parts = normalized.split('/').filter(Boolean);
    let cur = absolute ? '' : '.';
    for (const part of parts) {
      cur = cur === '' ? `/${part}` : `${cur}/${part}`;
      await new Promise<void>((resolve) => {
        // Ignore "already exists" — there is no portable mkdir -p over SFTP.
        sftp.mkdir(cur, () => resolve());
      });
    }
  }

  /** Does a remote path exist, and is it a directory? */
  private statRemote(sftp: SFTPWrapper, remotePath: string): Promise<{ exists: boolean; isDir: boolean; size: number }> {
    return new Promise((resolve) => {
      sftp.stat(remotePath, (err, stats) => {
        if (err || !stats) return resolve({ exists: false, isDir: false, size: 0 });
        resolve({ exists: true, isDir: stats.isDirectory(), size: stats.size ?? 0 });
      });
    });
  }

  private readdirRemote(sftp: SFTPWrapper, remoteDir: string): Promise<Array<{ name: string; isDir: boolean; size: number }>> {
    return new Promise((resolve, reject) => {
      sftp.readdir(remoteDir, (err, list) => {
        if (err) return reject(err);
        resolve(
          (list || []).map((e: any) => ({
            name: e.filename as string,
            isDir: !!e.attrs && typeof e.attrs.isDirectory === 'function' && e.attrs.isDirectory(),
            size: (e.attrs && e.attrs.size) || 0,
          }))
        );
      });
    });
  }

  private fastPut(sftp: SFTPWrapper, local: string, remote: string): Promise<void> {
    return new Promise((resolve, reject) => {
      sftp.fastPut(local, remote, (err) => (err ? reject(err) : resolve()));
    });
  }

  private fastGet(sftp: SFTPWrapper, remote: string, local: string): Promise<void> {
    return new Promise((resolve, reject) => {
      sftp.fastGet(remote, local, (err) => (err ? reject(err) : resolve()));
    });
  }

  /** Flat list of every file under a local directory, with paths relative to it. */
  private walkLocalDir(root: string): Array<{ abs: string; rel: string; size: number }> {
    const out: Array<{ abs: string; rel: string; size: number }> = [];
    const recurse = (dir: string, relBase: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const abs = localJoin(dir, entry.name);
        const rel = relBase ? `${relBase}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
          recurse(abs, rel);
        } else if (entry.isFile()) {
          out.push({ abs, rel, size: statSync(abs).size });
        }
      }
    };
    recurse(root, '');
    return out;
  }

  private sha256Local(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = createHash('sha256');
      const stream = createReadStream(filePath);
      stream.on('error', reject);
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
    });
  }

  private async sha256Remote(remotePath: string): Promise<string | null> {
    const res = await this.rawExec(`sha256sum ${shellQuote(remotePath)} 2>/dev/null || shasum -a 256 ${shellQuote(remotePath)} 2>/dev/null`);
    const match = res.stdout.trim().split(/\s+/)[0];
    return /^[a-f0-9]{64}$/i.test(match) ? match.toLowerCase() : null;
  }

  /**
   * Pick the right remote extractor for an archive and run it into destDir.
   * Returns the tool used, or throws if the archive type isn't supported.
   */
  private async extractRemote(remoteArchive: string, destDir: string): Promise<string> {
    const lower = remoteArchive.toLowerCase();
    let cmd: string;
    let tool: string;
    if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) {
      tool = 'tar';
      cmd = `tar -xzf ${shellQuote(remoteArchive)} -C ${shellQuote(destDir)}`;
    } else if (lower.endsWith('.tar.bz2') || lower.endsWith('.tbz2')) {
      tool = 'tar';
      cmd = `tar -xjf ${shellQuote(remoteArchive)} -C ${shellQuote(destDir)}`;
    } else if (lower.endsWith('.tar.xz') || lower.endsWith('.txz')) {
      tool = 'tar';
      cmd = `tar -xJf ${shellQuote(remoteArchive)} -C ${shellQuote(destDir)}`;
    } else if (lower.endsWith('.tar')) {
      tool = 'tar';
      cmd = `tar -xf ${shellQuote(remoteArchive)} -C ${shellQuote(destDir)}`;
    } else if (lower.endsWith('.zip')) {
      tool = 'unzip';
      cmd = `unzip -o ${shellQuote(remoteArchive)} -d ${shellQuote(destDir)}`;
    } else if (lower.endsWith('.gz')) {
      tool = 'gunzip';
      cmd = `gunzip -kf ${shellQuote(remoteArchive)}`;
    } else {
      throw new Error(`Unsupported archive type for extraction: ${remoteBasename(remoteArchive)}. Supported: .tar.gz/.tgz, .tar.bz2, .tar.xz, .tar, .zip, .gz`);
    }
    await this.sftpMkdirp(await this.getSftp(), destDir);
    const res = await this.rawExec(cmd);
    if (res.code !== 0) {
      throw new Error(`Extraction failed (${tool}, exit ${res.code}): ${res.stderr.trim() || res.stdout.trim() || 'unknown error'}`);
    }
    return tool;
  }

  /**
   * Upload a local file or directory to the remote host over SFTP.
   *
   * - If localPath is a directory it is uploaded recursively; remotePath is
   *   treated as the destination directory root.
   * - If localPath is a file and remotePath ends with "/" (or is an existing
   *   remote dir), the file keeps its basename inside it.
   */
  async uploadPath(
    localPath: string,
    remotePath: string,
    opts: { extract?: boolean; verifyChecksum?: boolean; overwrite?: boolean } = {}
  ): Promise<TransferResult> {
    if (!existsSync(localPath)) throw new Error(`Local path does not exist: ${localPath}`);
    const sftp = await this.getSftp();
    const localStat = statSync(localPath);

    // overwrite: false → refuse if the remote destination already exists.
    // For a single file uploaded into a trailing-slash/existing dir, the real
    // collision target is dir/basename, so resolve that before checking.
    if (opts.overwrite === false) {
      let checkPath = remotePath.replace(/\/+$/, '');
      if (!localStat.isDirectory()) {
        const info = await this.statRemote(sftp, remotePath.replace(/\/+$/, ''));
        if (/\/$/.test(remotePath) || info.isDir) {
          checkPath = posixPath.join(remotePath.replace(/\/+$/, ''), localBasename(localPath));
        }
      }
      const dest = await this.statRemote(sftp, checkPath);
      if (dest.exists) {
        throw new Error(`Remote destination already exists and overwrite is false: ${checkPath}`);
      }
    }
    const files: Array<{ path: string; bytes: number }> = [];
    let bytes = 0;

    if (localStat.isDirectory()) {
      const remoteRoot = remotePath.replace(/\/+$/, '');
      await this.sftpMkdirp(sftp, remoteRoot);
      const entries = this.walkLocalDir(localPath);
      const dirsMade = new Set<string>();
      for (const f of entries) {
        const remoteFile = posixPath.join(remoteRoot, f.rel);
        const remoteDir = posixPath.dirname(remoteFile);
        if (!dirsMade.has(remoteDir)) {
          await this.sftpMkdirp(sftp, remoteDir);
          dirsMade.add(remoteDir);
        }
        await this.fastPut(sftp, f.abs, remoteFile);
        files.push({ path: remoteFile, bytes: f.size });
        bytes += f.size;
      }
      return { direction: 'upload', isDirectory: true, root: remoteRoot, filesTransferred: files.length, bytesTransferred: bytes, files: capList(files) };
    }

    // Single file. Resolve destination (handle trailing-slash / existing dir).
    let remoteFile = remotePath;
    const trailingDir = /\/$/.test(remotePath);
    const remoteInfo = trailingDir ? { exists: true, isDir: true, size: 0 } : await this.statRemote(sftp, remotePath);
    if (trailingDir || remoteInfo.isDir) {
      remoteFile = posixPath.join(remotePath.replace(/\/+$/, ''), localBasename(localPath));
    }
    await this.sftpMkdirp(sftp, posixPath.dirname(remoteFile));
    await this.fastPut(sftp, localPath, remoteFile);
    bytes = localStat.size;
    files.push({ path: remoteFile, bytes });

    const result: TransferResult = {
      direction: 'upload',
      isDirectory: false,
      root: remoteFile,
      filesTransferred: 1,
      bytesTransferred: bytes,
      files: capList(files),
    };

    if (opts.verifyChecksum) {
      const [localHash, remoteHash] = await Promise.all([
        this.sha256Local(localPath),
        this.sha256Remote(remoteFile),
      ]);
      result.checksum = {
        algorithm: 'sha256',
        localHash,
        remoteHash: remoteHash ?? '(unavailable: no sha256sum/shasum on remote)',
        match: !!remoteHash && remoteHash === localHash,
      };
    }

    if (opts.extract) {
      const destDir = posixPath.dirname(remoteFile);
      const tool = await this.extractRemote(remoteFile, destDir);
      result.extracted = { archive: remoteFile, into: destDir, tool };
    }

    return result;
  }

  /**
   * Download a remote file or directory to the local host over SFTP.
   * Directories are pulled recursively.
   */
  async downloadPath(
    remotePath: string,
    localPath: string,
    opts: { verifyChecksum?: boolean; overwrite?: boolean } = {}
  ): Promise<TransferResult> {
    const sftp = await this.getSftp();
    const info = await this.statRemote(sftp, remotePath);
    if (!info.exists) throw new Error(`Remote path does not exist: ${remotePath}`);

    // overwrite: false → refuse if the local destination file already exists.
    if (opts.overwrite === false && !info.isDir) {
      let localFile = localPath;
      if (existsSync(localPath) && statSync(localPath).isDirectory()) {
        localFile = localJoin(localPath, remoteBasename(remotePath));
      }
      if (existsSync(localFile)) {
        throw new Error(`Local destination already exists and overwrite is false: ${localFile}`);
      }
    }
    const files: Array<{ path: string; bytes: number }> = [];
    let bytes = 0;

    if (info.isDir) {
      const remoteRoot = remotePath.replace(/\/+$/, '');
      const walk = async (rDir: string, lDir: string) => {
        if (!existsSync(lDir)) mkdirSync(lDir, { recursive: true });
        for (const entry of await this.readdirRemote(sftp, rDir)) {
          const rChild = posixPath.join(rDir, entry.name);
          const lChild = localJoin(lDir, entry.name);
          if (entry.isDir) {
            await walk(rChild, lChild);
          } else {
            await this.fastGet(sftp, rChild, lChild);
            files.push({ path: lChild, bytes: entry.size });
            bytes += entry.size;
          }
        }
      };
      await walk(remoteRoot, localPath);
      return { direction: 'download', isDirectory: true, root: localPath, filesTransferred: files.length, bytesTransferred: bytes, files: capList(files) };
    }

    // Single file. If localPath is an existing dir, keep the remote basename.
    let localFile = localPath;
    if (existsSync(localPath) && statSync(localPath).isDirectory()) {
      localFile = localJoin(localPath, remoteBasename(remotePath));
    }
    const parent = localDirname(localFile);
    if (!existsSync(parent)) mkdirSync(parent, { recursive: true });
    await this.fastGet(sftp, remotePath, localFile);
    bytes = info.size;
    files.push({ path: localFile, bytes });

    const result: TransferResult = {
      direction: 'download',
      isDirectory: false,
      root: localFile,
      filesTransferred: 1,
      bytesTransferred: bytes,
      files: capList(files),
    };

    if (opts.verifyChecksum) {
      const [localHash, remoteHash] = await Promise.all([
        this.sha256Local(localFile),
        this.sha256Remote(remotePath),
      ]);
      result.checksum = {
        algorithm: 'sha256',
        localHash,
        remoteHash: remoteHash ?? '(unavailable: no sha256sum/shasum on remote)',
        match: !!remoteHash && remoteHash === localHash,
      };
    }

    return result;
  }
}

/** Basename of a POSIX-style remote path. */
function remoteBasename(p: string): string {
  const parts = p.replace(/\/+$/, '').split('/');
  return parts[parts.length - 1] || p;
}

/** Cap a per-file list so a huge tree doesn't bloat the tool response. */
function capList(files: Array<{ path: string; bytes: number }>): Array<{ path: string; bytes: number }> {
  const MAX = 100;
  return files.length <= MAX ? files : files.slice(0, MAX);
}

export interface TransferResult {
  direction: 'upload' | 'download';
  isDirectory: boolean;
  /** Destination root (remote path for upload, local path for download). */
  root: string;
  filesTransferred: number;
  bytesTransferred: number;
  /** Per-file detail, capped at 100 entries for large trees. */
  files: Array<{ path: string; bytes: number }>;
  extracted?: { archive: string; into: string; tool: string };
  checksum?: { algorithm: string; localHash: string; remoteHash: string; match: boolean };
}

export default SSHExecutor;

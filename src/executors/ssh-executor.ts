/**
 * SSH Executor
 * Executes commands on remote servers via SSH
 */

import { Client, ClientChannel } from 'ssh2';
import { readFileSync } from 'fs';
import { CommandRequest, CommandResult, SSHConfig, ExecutorConfig, AccessMode } from '../types/index.js';
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
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
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
}

export default SSHExecutor;

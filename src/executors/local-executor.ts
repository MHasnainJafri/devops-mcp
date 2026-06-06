/**
 * Local Executor
 * Executes commands on the local machine
 */

import { spawn } from 'child_process';
import { CommandRequest, CommandResult, AccessMode, ExecutorConfig } from '../types/index.js';
import { BaseExecutor } from './base-executor.js';
import { modeManager } from '../core/mode-manager.js';
import { logger } from '../core/logger.js';

/** POSIX shell-quote helper. See ssh-executor for the rationale. */
function shellQuote(s: string): string {
  if (s === undefined || s === null) return "''";
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

export class LocalExecutor extends BaseExecutor {
  constructor(config: Partial<ExecutorConfig> = {}) {
    super({ ...config, type: 'local' });
  }

  /**
   * Execute command locally using child_process
   */
  protected async doExecute(request: CommandRequest): Promise<CommandResult> {
    const startTime = Date.now();
    const mode = request.mode || modeManager.getCurrentMode();

    return new Promise((resolve) => {
      // With shell:true, Node concatenates cmd + args via the platform
      // shell. That means any arg with whitespace, ;, &, |, $, `, " or '
      // will be reinterpreted by the shell. We compose a single quoted
      // string ourselves and hand that to spawn — Node's quoting is too
      // permissive for our threat model.
      const parts = this.parseCommand(request.command);
      const baseCmd = parts[0];
      const inlineArgs = parts.slice(1);              // already quoted within the command string
      const extraArgs = (request.args || []).map(shellQuote);
      const fullCommand = [baseCmd, ...inlineArgs, ...extraArgs].join(' ');

      logger.debug('Spawning local process', { fullCommand, cwd: request.cwd });

      const child = spawn(fullCommand, {
        cwd: request.cwd,
        env: { ...process.env, ...request.env },
        shell: true,
        timeout: request.timeout || this.config.timeout,
      });

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      child.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      child.on('close', (code) => {
        const executionTime = Date.now() - startTime;
        resolve({
          success: code === 0,
          exitCode: code ?? -1,
          stdout: stdout.trim(),
          stderr: stderr.trim(),
          executionTime,
          command: request.command,
          timestamp: new Date(),
          mode,
        });
      });

      child.on('error', (error) => {
        const executionTime = Date.now() - startTime;
        resolve({
          success: false,
          exitCode: -1,
          stdout: '',
          stderr: error.message,
          executionTime,
          command: request.command,
          timestamp: new Date(),
          mode,
        });
      });
    });
  }

  /**
   * Parse command string into parts
   */
  private parseCommand(command: string): string[] {
    // Simple parsing - split by spaces, respecting quotes
    const parts: string[] = [];
    let current = '';
    let inQuote = false;
    let quoteChar = '';

    for (const char of command) {
      if ((char === '"' || char === "'") && !inQuote) {
        inQuote = true;
        quoteChar = char;
      } else if (char === quoteChar && inQuote) {
        inQuote = false;
        quoteChar = '';
      } else if (char === ' ' && !inQuote) {
        if (current) {
          parts.push(current);
          current = '';
        }
      } else {
        current += char;
      }
    }

    if (current) {
      parts.push(current);
    }

    return parts;
  }

  /**
   * Test if local execution works
   */
  async testConnection(): Promise<boolean> {
    try {
      const result = await this.doExecute({
        command: process.platform === 'win32' ? 'echo test' : 'echo test',
      });
      return result.success;
    } catch {
      return false;
    }
  }

  /**
   * No cleanup needed for local executor
   */
  async cleanup(): Promise<void> {
    // Nothing to clean up
  }
}

export default LocalExecutor;

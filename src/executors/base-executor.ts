/**
 * Base Executor Interface
 * Abstract class for all execution backends (SSH, Local, Docker)
 */

import { CommandRequest, CommandResult, ExecutorConfig } from '../types/index.js';
import { ExecutionTimeoutError } from '../types/errors.js';
import { auditLogger, logger } from '../core/logger.js';
import { commandValidator } from '../core/command-validator.js';
import { modeManager } from '../core/mode-manager.js';

// Default configuration
const DEFAULT_CONFIG: ExecutorConfig = {
  type: 'local',
  timeout: 30000, // 30 seconds
  maxOutputSize: 1024 * 1024, // 1MB
};

export abstract class BaseExecutor {
  protected config: ExecutorConfig;

  constructor(config: Partial<ExecutorConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Execute a command - main entry point
   * Handles validation, logging, timeout, and output limiting
   */
  async execute(request: CommandRequest): Promise<CommandResult> {
    const startTime = Date.now();
    const mode = request.mode || modeManager.getCurrentMode();

    // Validate session
    modeManager.validateSession();

    // Validate command
    const validation = commandValidator.validate(request, mode);
    if (!validation.allowed) {
      const result: CommandResult = {
        success: false,
        exitCode: -1,
        stdout: '',
        stderr: validation.errors.join('\n'),
        executionTime: Date.now() - startTime,
        command: request.command,
        timestamp: new Date(),
        mode,
        warnings: validation.warnings,
      };

      auditLogger.logCommand(
        commandValidator.sanitizeForLogging(request.command),
        mode,
        'failure',
        -1,
        { reason: 'validation_failed', errors: validation.errors }
      );

      return result;
    }

    // Log command start
    logger.info('Executing command', {
      command: commandValidator.sanitizeForLogging(request.command).substring(0, 100),
      mode,
      timeout: request.timeout || this.config.timeout,
    });

    try {
      // Execute with timeout
      const timeout = request.timeout || this.config.timeout;
      const result = await this.executeWithTimeout(request, timeout);

      // Truncate output if necessary
      const truncatedResult = this.truncateOutput(result);

      // Add validation warnings
      truncatedResult.warnings = [
        ...(truncatedResult.warnings || []),
        ...validation.warnings,
      ];

      // Log result
      auditLogger.logCommand(
        commandValidator.sanitizeForLogging(request.command),
        mode,
        truncatedResult.success ? 'success' : 'failure',
        truncatedResult.exitCode,
        {
          executionTime: truncatedResult.executionTime,
          truncated: truncatedResult.truncated,
        }
      );

      return truncatedResult;
    } catch (error) {
      const executionTime = Date.now() - startTime;

      // Log error
      auditLogger.logCommand(
        commandValidator.sanitizeForLogging(request.command),
        mode,
        'error',
        -1,
        { error: error instanceof Error ? error.message : 'Unknown error' }
      );

      if (error instanceof ExecutionTimeoutError) {
        return {
          success: false,
          exitCode: -1,
          stdout: '',
          stderr: `Command timed out after ${this.config.timeout}ms`,
          executionTime,
          command: request.command,
          timestamp: new Date(),
          mode,
          warnings: ['Command was terminated due to timeout'],
        };
      }

      return {
        success: false,
        exitCode: -1,
        stdout: '',
        stderr: error instanceof Error ? error.message : 'Unknown error',
        executionTime,
        command: request.command,
        timestamp: new Date(),
        mode,
      };
    }
  }

  /**
   * Execute with timeout wrapper
   */
  protected async executeWithTimeout(
    request: CommandRequest,
    timeout: number
  ): Promise<CommandResult> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new ExecutionTimeoutError(request.command, timeout));
      }, timeout);

      this.doExecute(request)
        .then((result) => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch((error) => {
          clearTimeout(timer);
          reject(error);
        });
    });
  }

  /**
   * Truncate output if it exceeds max size
   */
  protected truncateOutput(result: CommandResult): CommandResult {
    const maxSize = this.config.maxOutputSize;
    let truncated = false;

    let stdout = result.stdout;
    let stderr = result.stderr;

    if (stdout.length > maxSize) {
      stdout = stdout.substring(0, maxSize) + '\n... [OUTPUT TRUNCATED]';
      truncated = true;
    }

    if (stderr.length > maxSize) {
      stderr = stderr.substring(0, maxSize) + '\n... [OUTPUT TRUNCATED]';
      truncated = true;
    }

    return {
      ...result,
      stdout,
      stderr,
      truncated,
    };
  }

  /**
   * Abstract method - implement actual execution in subclasses
   */
  protected abstract doExecute(request: CommandRequest): Promise<CommandResult>;

  /**
   * Test connection to the executor target
   */
  abstract testConnection(): Promise<boolean>;

  /**
   * Cleanup resources
   */
  abstract cleanup(): Promise<void>;

  /**
   * Get executor type
   */
  getType(): string {
    return this.config.type;
  }
}

export default BaseExecutor;

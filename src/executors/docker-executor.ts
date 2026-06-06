/**
 * Docker Executor
 * Executes commands inside Docker containers
 */

// @ts-ignore - dockerode types may not be installed
import Docker from 'dockerode';
import { CommandRequest, CommandResult, ExecutorConfig, AccessMode } from '../types/index.js';
import { BaseExecutor } from './base-executor.js';
import { modeManager } from '../core/mode-manager.js';
import { logger } from '../core/logger.js';
import { MCPError } from '../types/errors.js';

export interface DockerExecutorConfig extends Partial<ExecutorConfig> {
  containerId?: string;
  containerName?: string;
  image?: string;
  dockerHost?: string;
}

export class DockerExecutor extends BaseExecutor {
  private docker: Docker;
  private containerId?: string;
  private containerName?: string;
  private image?: string;

  constructor(config: DockerExecutorConfig = {}) {
    super({ ...config, type: 'docker' });
    
    // Initialize Docker client
    this.docker = new Docker({
      socketPath: config.dockerHost || (process.platform === 'win32' 
        ? '//./pipe/docker_engine' 
        : '/var/run/docker.sock'),
    });

    this.containerId = config.containerId;
    this.containerName = config.containerName;
    this.image = config.image;
  }

  /**
   * Set target container
   */
  setContainer(containerId?: string, containerName?: string): void {
    this.containerId = containerId;
    this.containerName = containerName;
  }

  /**
   * Execute command inside container
   */
  protected async doExecute(request: CommandRequest): Promise<CommandResult> {
    const startTime = Date.now();
    const mode = request.mode || modeManager.getCurrentMode();

    // Get container
    const container = await this.getContainer();
    if (!container) {
      return {
        success: false,
        exitCode: -1,
        stdout: '',
        stderr: 'No container specified or found',
        executionTime: Date.now() - startTime,
        command: request.command,
        timestamp: new Date(),
        mode,
      };
    }

    try {
      // Create exec instance
      const exec = await container.exec({
        Cmd: ['sh', '-c', request.command],
        AttachStdout: true,
        AttachStderr: true,
        WorkingDir: request.cwd,
        Env: request.env ? Object.entries(request.env).map(([k, v]) => `${k}=${v}`) : undefined,
      });

      // Start exec and capture output
      const stream = await exec.start({ hijack: true, stdin: false });
      
      let stdout = '';
      let stderr = '';

      return new Promise((resolve) => {
        // Docker multiplexes stdout and stderr
        this.docker.modem.demuxStream(stream, 
          { write: (chunk: Buffer) => { stdout += chunk.toString(); } },
          { write: (chunk: Buffer) => { stderr += chunk.toString(); } }
        );

        stream.on('end', async () => {
          // Get exit code
          const inspectData = await exec.inspect();
          const exitCode = inspectData.ExitCode ?? -1;

          const executionTime = Date.now() - startTime;
          resolve({
            success: exitCode === 0,
            exitCode,
            stdout: stdout.trim(),
            stderr: stderr.trim(),
            executionTime,
            command: request.command,
            timestamp: new Date(),
            mode,
          });
        });
      });
    } catch (error) {
      const executionTime = Date.now() - startTime;
      logger.error('Docker exec failed', {
        containerId: this.containerId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      return {
        success: false,
        exitCode: -1,
        stdout: '',
        stderr: error instanceof Error ? error.message : 'Docker exec failed',
        executionTime,
        command: request.command,
        timestamp: new Date(),
        mode,
      };
    }
  }

  /**
   * Get container instance
   */
  private async getContainer(): Promise<Docker.Container | null> {
    if (this.containerId) {
      return this.docker.getContainer(this.containerId);
    }

    if (this.containerName) {
      // Find container by name
      const containers = await this.docker.listContainers({ all: true });
      const found = containers.find((c: Docker.ContainerInfo) => 
        c.Names.some((n: string) => n === `/${this.containerName}` || n === this.containerName)
      );
      if (found) {
        return this.docker.getContainer(found.Id);
      }
    }

    return null;
  }

  /**
   * Test Docker connection
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.docker.ping();
      logger.info('Docker connection successful');
      return true;
    } catch (error) {
      logger.error('Docker connection failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }

  /**
   * Cleanup - nothing specific needed
   */
  async cleanup(): Promise<void> {
    // Docker client doesn't need explicit cleanup
  }

  /**
   * List running containers
   */
  async listContainers(all: boolean = false): Promise<Docker.ContainerInfo[]> {
    return this.docker.listContainers({ all });
  }

  /**
   * List images
   */
  async listImages(): Promise<Docker.ImageInfo[]> {
    return this.docker.listImages();
  }

  /**
   * Get container logs
   */
  async getContainerLogs(
    containerId: string,
    options: { tail?: number; since?: number } = {}
  ): Promise<string> {
    const container = this.docker.getContainer(containerId);
    const logs = await container.logs({
      stdout: true,
      stderr: true,
      tail: options.tail || 100,
      since: options.since,
    });
    return logs.toString();
  }

  /**
   * Start a container
   */
  async startContainer(containerId: string): Promise<void> {
    const container = this.docker.getContainer(containerId);
    await container.start();
    logger.info('Container started', { containerId });
  }

  /**
   * Stop a container
   */
  async stopContainer(containerId: string): Promise<void> {
    const container = this.docker.getContainer(containerId);
    await container.stop();
    logger.info('Container stopped', { containerId });
  }

  /**
   * Restart a container
   */
  async restartContainer(containerId: string): Promise<void> {
    const container = this.docker.getContainer(containerId);
    await container.restart();
    logger.info('Container restarted', { containerId });
  }
}

export default DockerExecutor;

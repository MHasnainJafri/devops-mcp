/**
 * Executor module exports
 */

export { BaseExecutor } from './base-executor.js';
export { LocalExecutor } from './local-executor.js';
export { SSHExecutor, SSHExecutorConfig } from './ssh-executor.js';
export { DockerExecutor, DockerExecutorConfig } from './docker-executor.js';

import { ExecutorType, SSHConfig } from '../types/index.js';
import { LocalExecutor } from './local-executor.js';
import { SSHExecutor } from './ssh-executor.js';
import { DockerExecutor } from './docker-executor.js';
import { BaseExecutor } from './base-executor.js';

export interface ExecutorFactoryConfig {
  type: ExecutorType;
  ssh?: SSHConfig;
  docker?: {
    containerId?: string;
    containerName?: string;
    image?: string;
    dockerHost?: string;
  };
  timeout?: number;
  maxOutputSize?: number;
}

/**
 * Factory function to create appropriate executor
 */
export function createExecutor(config: ExecutorFactoryConfig): BaseExecutor {
  switch (config.type) {
    case 'local':
      return new LocalExecutor({
        timeout: config.timeout,
        maxOutputSize: config.maxOutputSize,
      });

    case 'ssh':
      if (!config.ssh) {
        throw new Error('SSH configuration required for SSH executor');
      }
      return new SSHExecutor({
        ssh: config.ssh,
        timeout: config.timeout,
        maxOutputSize: config.maxOutputSize,
      });

    case 'docker':
      return new DockerExecutor({
        ...config.docker,
        timeout: config.timeout,
        maxOutputSize: config.maxOutputSize,
      });

    default:
      throw new Error(`Unknown executor type: ${config.type}`);
  }
}

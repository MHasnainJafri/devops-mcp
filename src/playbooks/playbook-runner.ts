/**
 * Playbook Runner
 * Executes provisioning playbooks step-by-step
 */

import { Playbook, PlaybookStep, PlaybookResult, CommandResult, AccessMode } from '../types/index.js';
import { PlaybookExecutionError, PermissionDeniedError } from '../types/errors.js';
import { BaseExecutor } from '../executors/base-executor.js';
import { modeManager } from '../core/mode-manager.js';
import { approvalManager } from '../core/approval-manager.js';
import { auditLogger, logger } from '../core/logger.js';

export interface PlaybookRunnerOptions {
  stopOnError?: boolean;
  dryRun?: boolean;
  variables?: Record<string, string>;
}

export class PlaybookRunner {
  private executor: BaseExecutor;

  constructor(executor: BaseExecutor) {
    this.executor = executor;
  }

  /**
   * Execute a complete playbook
   */
  async runPlaybook(
    playbook: Playbook,
    options: PlaybookRunnerOptions = {}
  ): Promise<PlaybookResult> {
    const startedAt = new Date();
    const results: CommandResult[] = [];
    const errors: string[] = [];
    let stepsCompleted = 0;

    const { stopOnError = true, dryRun = false, variables = {} } = options;

    // Merge variables
    const allVariables = { ...playbook.variables, ...variables };

    // Check mode requirements
    const currentMode = modeManager.getCurrentMode();
    if (!this.canRunInMode(playbook.requiredMode, currentMode)) {
      throw new PermissionDeniedError(
        `Playbook "${playbook.name}" requires ${playbook.requiredMode} mode`,
        playbook.requiredMode,
        currentMode
      );
    }

    // Log playbook start
    auditLogger.logPlaybookExecution(
      playbook.id,
      playbook.name,
      'started',
      currentMode,
      { dryRun, totalSteps: playbook.steps.length }
    );

    logger.info('Starting playbook execution', {
      playbookId: playbook.id,
      playbookName: playbook.name,
      totalSteps: playbook.steps.length,
      dryRun,
    });

    // Execute steps
    for (let i = 0; i < playbook.steps.length; i++) {
      const step = playbook.steps[i];

      try {
        // Check step mode requirements
        if (!this.canRunInMode(step.requiredMode, currentMode)) {
          throw new PermissionDeniedError(
            `Step "${step.name}" requires ${step.requiredMode} mode`,
            step.requiredMode,
            currentMode
          );
        }

        // Check if approval is required
        if (step.requiresApproval) {
          const risk = this.assessStepRisk(step);
          if (approvalManager.requiresApproval(step.name, currentMode, risk)) {
            await approvalManager.requestApproval(
              step.name,
              step.description || step.command,
              risk,
              step.requiredMode,
              step.command
            );
          }
        }

        // Interpolate variables in command
        const command = this.interpolateVariables(step.command, allVariables);

        logger.info(`Executing step ${i + 1}/${playbook.steps.length}`, {
          stepId: step.id,
          stepName: step.name,
        });

        if (dryRun) {
          // Dry run - just log the command
          results.push({
            success: true,
            exitCode: 0,
            stdout: `[DRY RUN] Would execute: ${command}`,
            stderr: '',
            executionTime: 0,
            command,
            timestamp: new Date(),
            mode: currentMode,
          });
          stepsCompleted++;
          continue;
        }

        // Execute the step
        const result = await this.executor.execute({
          command,
          args: step.args,
          mode: currentMode,
        });

        results.push(result);

        if (result.success) {
          stepsCompleted++;
          logger.info('Step completed successfully', { stepId: step.id });

          // Run validation if provided
          if (step.validate) {
            const validateResult = await this.executor.execute({
              command: this.interpolateVariables(step.validate, allVariables),
              mode: currentMode,
            });

            if (!validateResult.success) {
              errors.push(`Validation failed for step "${step.name}": ${validateResult.stderr}`);
              if (stopOnError) {
                throw new PlaybookExecutionError(
                  playbook.id,
                  step.id,
                  i,
                  `Validation failed: ${validateResult.stderr}`
                );
              }
            }
          }
        } else {
          errors.push(`Step "${step.name}" failed: ${result.stderr}`);
          
          if (stopOnError) {
            // Attempt rollback if provided
            if (step.rollback) {
              logger.info('Attempting rollback', { stepId: step.id });
              await this.executor.execute({
                command: this.interpolateVariables(step.rollback, allVariables),
                mode: currentMode,
              });
            }

            throw new PlaybookExecutionError(
              playbook.id,
              step.id,
              i,
              result.stderr
            );
          }
        }
      } catch (error) {
        if (error instanceof PlaybookExecutionError) {
          throw error;
        }

        errors.push(`Step "${step.name}" error: ${error instanceof Error ? error.message : 'Unknown error'}`);
        
        if (stopOnError) {
          throw new PlaybookExecutionError(
            playbook.id,
            step.id,
            i,
            error instanceof Error ? error.message : 'Unknown error'
          );
        }
      }
    }

    const result: PlaybookResult = {
      playbookId: playbook.id,
      success: stepsCompleted === playbook.steps.length && errors.length === 0,
      stepsCompleted,
      totalSteps: playbook.steps.length,
      results,
      errors: errors.length > 0 ? errors : undefined,
      startedAt,
      completedAt: new Date(),
    };

    // Log playbook completion
    auditLogger.logPlaybookExecution(
      playbook.id,
      playbook.name,
      result.success ? 'completed' : 'failed',
      currentMode,
      { stepsCompleted, totalSteps: playbook.steps.length }
    );

    logger.info('Playbook execution finished', {
      playbookId: playbook.id,
      success: result.success,
      stepsCompleted,
      totalSteps: playbook.steps.length,
    });

    return result;
  }

  /**
   * Execute a single step
   */
  async runStep(
    step: PlaybookStep,
    variables: Record<string, string> = {}
  ): Promise<CommandResult> {
    const currentMode = modeManager.getCurrentMode();

    // Check mode requirements
    if (!this.canRunInMode(step.requiredMode, currentMode)) {
      throw new PermissionDeniedError(
        `Step "${step.name}" requires ${step.requiredMode} mode`,
        step.requiredMode,
        currentMode
      );
    }

    // Interpolate variables
    const command = this.interpolateVariables(step.command, variables);

    return this.executor.execute({
      command,
      args: step.args,
      mode: currentMode,
    });
  }

  /**
   * Check if current mode allows required mode
   */
  private canRunInMode(required: AccessMode, current: AccessMode): boolean {
    const modeLevel = (mode: AccessMode): number => {
      switch (mode) {
        case AccessMode.SAFE: return 0;
        case AccessMode.PROVISION: return 1;
        case AccessMode.FULL: return 2;
        default: return 0;
      }
    };

    return modeLevel(current) >= modeLevel(required);
  }

  /**
   * Interpolate variables in a string
   */
  private interpolateVariables(
    template: string,
    variables: Record<string, string>
  ): string {
    return template.replace(/\$\{(\w+)\}/g, (match, name) => {
      return variables[name] ?? match;
    });
  }

  /**
   * Assess risk level of a step
   */
  private assessStepRisk(step: PlaybookStep): 'low' | 'medium' | 'high' | 'critical' {
    const command = step.command.toLowerCase();

    // Critical risk patterns
    if (
      command.includes('rm -rf') ||
      command.includes('dd ') ||
      command.includes('mkfs') ||
      command.includes('fdisk')
    ) {
      return 'critical';
    }

    // High risk patterns
    if (
      command.includes('reboot') ||
      command.includes('shutdown') ||
      command.includes('systemctl') ||
      command.includes('iptables')
    ) {
      return 'high';
    }

    // Medium risk patterns
    if (
      command.includes('apt') ||
      command.includes('yum') ||
      command.includes('docker') ||
      command.includes('nginx')
    ) {
      return 'medium';
    }

    // Default to low
    return 'low';
  }
}

export default PlaybookRunner;

/**
 * Custom error types for DevOps MCP Server
 */

import { AccessMode } from './index.js';

export class MCPError extends Error {
  public readonly code: string;
  public readonly timestamp: Date;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'MCPError';
    this.code = code;
    this.timestamp = new Date();
  }
}

export class PermissionDeniedError extends MCPError {
  public readonly requiredMode: AccessMode;
  public readonly currentMode: AccessMode;

  constructor(
    message: string,
    requiredMode: AccessMode,
    currentMode: AccessMode
  ) {
    super(message, 'PERMISSION_DENIED');
    this.name = 'PermissionDeniedError';
    this.requiredMode = requiredMode;
    this.currentMode = currentMode;
  }
}

export class CommandValidationError extends MCPError {
  public readonly command: string;
  public readonly reason: string;

  constructor(command: string, reason: string) {
    super(`Command validation failed: ${reason}`, 'COMMAND_VALIDATION_FAILED');
    this.name = 'CommandValidationError';
    this.command = command;
    this.reason = reason;
  }
}

export class ExecutionTimeoutError extends MCPError {
  public readonly command: string;
  public readonly timeout: number;

  constructor(command: string, timeout: number) {
    super(`Command execution timed out after ${timeout}ms`, 'EXECUTION_TIMEOUT');
    this.name = 'ExecutionTimeoutError';
    this.command = command;
    this.timeout = timeout;
  }
}

export class SSHConnectionError extends MCPError {
  public readonly host: string;
  public readonly originalError?: Error;

  constructor(host: string, message: string, originalError?: Error) {
    super(`SSH connection to ${host} failed: ${message}`, 'SSH_CONNECTION_FAILED');
    this.name = 'SSHConnectionError';
    this.host = host;
    this.originalError = originalError;
  }
}

export class SessionExpiredError extends MCPError {
  public readonly sessionId: string;

  constructor(sessionId: string) {
    super(`Session ${sessionId} has expired`, 'SESSION_EXPIRED');
    this.name = 'SessionExpiredError';
    this.sessionId = sessionId;
  }
}

export class RiskNotAcknowledgedError extends MCPError {
  public readonly requiredMode: AccessMode;

  constructor(requiredMode: AccessMode) {
    super(
      `Risk acknowledgement required for ${requiredMode} mode. Please explicitly confirm.`,
      'RISK_NOT_ACKNOWLEDGED'
    );
    this.name = 'RiskNotAcknowledgedError';
    this.requiredMode = requiredMode;
  }
}

export class ApprovalRequiredError extends MCPError {
  public readonly approvalId: string;
  public readonly action: string;

  constructor(approvalId: string, action: string) {
    super(
      `Human approval required for action: ${action}. Approval ID: ${approvalId}`,
      'APPROVAL_REQUIRED'
    );
    this.name = 'ApprovalRequiredError';
    this.approvalId = approvalId;
    this.action = action;
  }
}

export class PlaybookExecutionError extends MCPError {
  public readonly playbookId: string;
  public readonly stepId: string;
  public readonly stepIndex: number;

  constructor(playbookId: string, stepId: string, stepIndex: number, message: string) {
    super(`Playbook ${playbookId} failed at step ${stepIndex} (${stepId}): ${message}`, 'PLAYBOOK_EXECUTION_FAILED');
    this.name = 'PlaybookExecutionError';
    this.playbookId = playbookId;
    this.stepId = stepId;
    this.stepIndex = stepIndex;
  }
}

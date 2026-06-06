/**
 * Structured logging system for DevOps MCP Server
 * All logs are JSON formatted for audit and replay capability
 */

import winston from 'winston';
import { v4 as uuidv4 } from 'uuid';
import { AccessMode, AuditLogEntry } from '../types/index.js';

const LOG_DIR = process.env.LOG_DIR || './logs';

// Custom format for structured JSON logging
// Default timestamp() is ISO 8601. Passing { format: 'ISO' } is wrong —
// it treats 'ISO' as a dateformat template and emits 'I3O'.
const structuredFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create the main logger instance
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: structuredFormat,
  defaultMeta: { service: 'devops-mcp' },
  transports: [
    // Error logs
    new winston.transports.File({
      filename: `${LOG_DIR}/error.log`,
      level: 'error',
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 5,
    }),
    // Combined logs
    new winston.transports.File({
      filename: `${LOG_DIR}/combined.log`,
      maxsize: 10 * 1024 * 1024,
      maxFiles: 10,
    }),
    // Audit logs (separate file for compliance)
    new winston.transports.File({
      filename: `${LOG_DIR}/audit.log`,
      level: 'info',
      maxsize: 50 * 1024 * 1024, // 50MB for audit
      maxFiles: 20,
    }),
  ],
});

// Console transport — IMPORTANT: this MCP server speaks JSON-RPC over stdio,
// so stdout MUST contain protocol frames only. Route every log level to
// stderr so logs don't corrupt the stream. Skip the transport entirely when
// DEVOPS_MCP_NO_CONSOLE_LOG is set.
if (process.env.DEVOPS_MCP_NO_CONSOLE_LOG !== '1') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
      stderrLevels: ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'],
    })
  );
}

/**
 * Audit Logger - Specialized for command execution and mode changes
 * These logs are immutable and timestamped for compliance
 */
export class AuditLogger {
  private sessionId: string;

  constructor(sessionId?: string) {
    this.sessionId = sessionId || uuidv4();
  }

  setSessionId(sessionId: string): void {
    this.sessionId = sessionId;
  }

  /**
   * Log a command execution
   */
  logCommand(
    command: string,
    mode: AccessMode,
    result: 'success' | 'failure' | 'error',
    exitCode?: number,
    metadata?: Record<string, unknown>
  ): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      sessionId: this.sessionId,
      action: 'COMMAND_EXECUTION',
      mode,
      command,
      result,
      exitCode,
      metadata,
    };

    logger.info('Command executed', { audit: entry });
    return entry;
  }

  /**
   * Log a mode change
   */
  logModeChange(
    fromMode: AccessMode,
    toMode: AccessMode,
    acknowledgedBy?: string
  ): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      sessionId: this.sessionId,
      action: 'MODE_CHANGE',
      mode: toMode,
      userId: acknowledgedBy,
      metadata: { fromMode, toMode },
    };

    logger.info('Access mode changed', { audit: entry });
    return entry;
  }

  /**
   * Log risk acknowledgement
   */
  logRiskAcknowledgement(
    mode: AccessMode,
    acknowledgedBy: string
  ): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      sessionId: this.sessionId,
      action: 'RISK_ACKNOWLEDGED',
      mode,
      userId: acknowledgedBy,
    };

    logger.warn('Risk acknowledged for elevated mode', { audit: entry });
    return entry;
  }

  /**
   * Log SSH key lifecycle events
   */
  logSSHKeyEvent(
    event: 'GENERATED' | 'UPLOADED' | 'REVOKED' | 'EXPIRED',
    fingerprint: string,
    targetServer?: string
  ): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      sessionId: this.sessionId,
      action: `SSH_KEY_${event}`,
      mode: AccessMode.SAFE,
      targetServer,
      metadata: { fingerprint },
    };

    logger.info(`SSH key ${event.toLowerCase()}`, { audit: entry });
    return entry;
  }

  /**
   * Log approval events
   */
  logApprovalEvent(
    event: 'REQUESTED' | 'APPROVED' | 'REJECTED' | 'EXPIRED',
    approvalId: string,
    action: string,
    approvedBy?: string
  ): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      sessionId: this.sessionId,
      action: `APPROVAL_${event}`,
      mode: AccessMode.SAFE,
      userId: approvedBy,
      metadata: { approvalId, action },
    };

    logger.info(`Approval ${event.toLowerCase()}`, { audit: entry });
    return entry;
  }

  /**
   * Log session events
   */
  logSessionEvent(
    event: 'STARTED' | 'ENDED' | 'EXPIRED',
    metadata?: Record<string, unknown>
  ): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      sessionId: this.sessionId,
      action: `SESSION_${event}`,
      mode: AccessMode.SAFE,
      metadata,
    };

    logger.info(`Session ${event.toLowerCase()}`, { audit: entry });
    return entry;
  }

  /**
   * Log playbook execution
   */
  logPlaybookExecution(
    playbookId: string,
    playbookName: string,
    result: 'started' | 'completed' | 'failed',
    mode: AccessMode,
    metadata?: Record<string, unknown>
  ): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      sessionId: this.sessionId,
      action: `PLAYBOOK_${result.toUpperCase()}`,
      mode,
      metadata: { playbookId, playbookName, ...metadata },
    };

    logger.info(`Playbook ${result}`, { audit: entry });
    return entry;
  }
}

// Default audit logger instance
export const auditLogger = new AuditLogger();

export default logger;

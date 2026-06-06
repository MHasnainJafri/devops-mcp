/**
 * Core type definitions for DevOps MCP Server
 */

// ============================================
// EXECUTION MODES
// ============================================

export enum AccessMode {
  SAFE = 'SAFE',           // Allowlisted commands only - Low risk
  PROVISION = 'PROVISION', // System install & config - Medium risk
  FULL = 'FULL'            // Root-level unrestricted - High risk
}

export interface ModePermissions {
  os: boolean;
  docker: boolean;
  nginx: boolean;
  firewall: boolean;
  disk: boolean;
  network: boolean;
  systemd: boolean;
}

export interface AccessModeConfig {
  mode: AccessMode;
  permissions: ModePermissions;
  expiresAt?: Date;
  expiresIn?: string; // e.g., "60m", "2h"
  acknowledgedAt?: Date;
  acknowledgedBy?: string;
}

// ============================================
// COMMAND EXECUTION
// ============================================

export interface CommandRequest {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeout?: number; // milliseconds
  mode?: AccessMode;
}

export interface CommandResult {
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  executionTime: number; // milliseconds
  command: string;
  timestamp: Date;
  mode: AccessMode;
  warnings?: string[];
  truncated?: boolean;
}

export type ExecutorType = 'ssh' | 'local' | 'docker';

export interface ExecutorConfig {
  type: ExecutorType;
  timeout: number;
  maxOutputSize: number; // bytes
}

// ============================================
// SSH CONFIGURATION
// ============================================

export interface SSHConfig {
  host: string;
  port: number;
  username: string;
  privateKey?: string;
  privateKeyPath?: string;
  passphrase?: string;
  password?: string;        // For password-based authentication
  sessionId?: string;
  keyExpiresAt?: Date;
}

export interface SSHKeyInfo {
  sessionId: string;
  publicKey: string;
  privateKey: string;
  createdAt: Date;
  expiresAt: Date;
  fingerprint: string;
}

// ============================================
// SERVER / TARGET
// ============================================

export interface ServerTarget {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  sshConfig?: SSHConfig;
  status: 'connected' | 'disconnected' | 'error';
  lastConnected?: Date;
}

// ============================================
// PROVISIONING
// ============================================

export interface PlaybookStep {
  id: string;
  name: string;
  command: string;
  args?: string[];
  description?: string;
  requiredMode: AccessMode;
  requiresApproval?: boolean;
  rollback?: string;
  validate?: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  requiredMode: AccessMode;
  steps: PlaybookStep[];
  variables?: Record<string, string>;
}

export interface PlaybookResult {
  playbookId: string;
  success: boolean;
  stepsCompleted: number;
  totalSteps: number;
  results: CommandResult[];
  errors?: string[];
  startedAt: Date;
  completedAt?: Date;
}

// ============================================
// APPROVAL SYSTEM
// ============================================

export interface ApprovalRequest {
  id: string;
  action: string;
  description: string;
  command?: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  requiredMode: AccessMode;
  createdAt: Date;
  expiresAt: Date;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  approvedBy?: string;
  approvedAt?: Date;
}

// ============================================
// AUDIT / LOGGING
// ============================================

export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  sessionId: string;
  action: string;
  mode: AccessMode;
  command?: string;
  result?: 'success' | 'failure' | 'error';
  exitCode?: number;
  userId?: string;
  targetServer?: string;
  metadata?: Record<string, unknown>;
}

// ============================================
// SESSION
// ============================================

export interface Session {
  id: string;
  createdAt: Date;
  expiresAt?: Date;
  mode: AccessMode;
  modeConfig: AccessModeConfig;
  target?: ServerTarget;
  isActive: boolean;
  riskAcknowledged: boolean;
}

// ============================================
// MCP TOOL RESPONSES
// ============================================

export interface MCPToolResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  warnings?: string[];
  nextSteps?: string[];
  mode: AccessMode;
  timestamp: Date;
}

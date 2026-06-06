/**
 * Approval Manager
 * Handles human approval checkpoints for high-risk operations
 */

import { v4 as uuidv4 } from 'uuid';
import { ApprovalRequest, AccessMode } from '../types/index.js';
import { ApprovalRequiredError } from '../types/errors.js';
import { auditLogger, logger } from './logger.js';

// Default approval timeout (5 minutes)
const DEFAULT_APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

// Pending approvals store
const pendingApprovals: Map<string, ApprovalRequest> = new Map();

// Approval callbacks (for async approval flow)
const approvalCallbacks: Map<string, {
  resolve: (approved: boolean) => void;
  reject: (error: Error) => void;
}> = new Map();

// Timeout timers
const approvalTimers: Map<string, NodeJS.Timeout> = new Map();

export class ApprovalManager {
  /**
   * Request approval for an action
   * Returns immediately if auto-approved, otherwise throws ApprovalRequiredError
   */
  async requestApproval(
    action: string,
    description: string,
    risk: 'low' | 'medium' | 'high' | 'critical',
    requiredMode: AccessMode,
    command?: string,
    timeoutMs: number = DEFAULT_APPROVAL_TIMEOUT_MS
  ): Promise<void> {
    const approvalId = uuidv4();
    const now = new Date();

    const request: ApprovalRequest = {
      id: approvalId,
      action,
      description,
      command,
      risk,
      requiredMode,
      createdAt: now,
      expiresAt: new Date(now.getTime() + timeoutMs),
      status: 'pending',
    };

    // Store pending approval
    pendingApprovals.set(approvalId, request);

    // Log approval request
    auditLogger.logApprovalEvent('REQUESTED', approvalId, action);
    logger.info('Approval requested', { approvalId, action, risk });

    // Set up expiry timer
    const timer = setTimeout(() => {
      this.expireApproval(approvalId);
    }, timeoutMs);
    approvalTimers.set(approvalId, timer);

    // Throw error to notify caller that approval is needed
    throw new ApprovalRequiredError(approvalId, action);
  }

  /**
   * Check if an action requires approval based on mode and risk
   */
  requiresApproval(
    action: string,
    currentMode: AccessMode,
    risk: 'low' | 'medium' | 'high' | 'critical'
  ): boolean {
    // FULL mode - no approval required (user has full responsibility)
    if (currentMode === AccessMode.FULL) {
      return false;
    }

    // Critical risk always requires approval
    if (risk === 'critical') {
      return true;
    }

    // High risk requires approval in SAFE mode
    if (risk === 'high' && currentMode === AccessMode.SAFE) {
      return true;
    }

    return false;
  }

  /**
   * Approve a pending request
   */
  approve(approvalId: string, approvedBy: string): boolean {
    const request = pendingApprovals.get(approvalId);
    
    if (!request) {
      logger.warn('Approval not found', { approvalId });
      return false;
    }

    if (request.status !== 'pending') {
      logger.warn('Approval already processed', { approvalId, status: request.status });
      return false;
    }

    // Check if expired
    if (new Date() > request.expiresAt) {
      this.expireApproval(approvalId);
      return false;
    }

    // Update status
    request.status = 'approved';
    request.approvedBy = approvedBy;
    request.approvedAt = new Date();
    pendingApprovals.set(approvalId, request);

    // Clear timer
    const timer = approvalTimers.get(approvalId);
    if (timer) {
      clearTimeout(timer);
      approvalTimers.delete(approvalId);
    }

    // Resolve callback if waiting
    const callback = approvalCallbacks.get(approvalId);
    if (callback) {
      callback.resolve(true);
      approvalCallbacks.delete(approvalId);
    }

    // Log approval
    auditLogger.logApprovalEvent('APPROVED', approvalId, request.action, approvedBy);
    logger.info('Approval granted', { approvalId, approvedBy });

    return true;
  }

  /**
   * Reject a pending request
   */
  reject(approvalId: string, rejectedBy: string): boolean {
    const request = pendingApprovals.get(approvalId);
    
    if (!request) {
      return false;
    }

    if (request.status !== 'pending') {
      return false;
    }

    // Update status
    request.status = 'rejected';
    pendingApprovals.set(approvalId, request);

    // Clear timer
    const timer = approvalTimers.get(approvalId);
    if (timer) {
      clearTimeout(timer);
      approvalTimers.delete(approvalId);
    }

    // Resolve callback with false
    const callback = approvalCallbacks.get(approvalId);
    if (callback) {
      callback.resolve(false);
      approvalCallbacks.delete(approvalId);
    }

    // Log rejection
    auditLogger.logApprovalEvent('REJECTED', approvalId, request.action, rejectedBy);
    logger.info('Approval rejected', { approvalId, rejectedBy });

    return true;
  }

  /**
   * Wait for approval (async)
   */
  async waitForApproval(approvalId: string): Promise<boolean> {
    const request = pendingApprovals.get(approvalId);
    
    if (!request) {
      return false;
    }

    // Already processed
    if (request.status === 'approved') {
      return true;
    }
    if (request.status === 'rejected' || request.status === 'expired') {
      return false;
    }

    // Wait for callback
    return new Promise((resolve, reject) => {
      approvalCallbacks.set(approvalId, { resolve, reject });
    });
  }

  /**
   * Check approval status
   */
  getApprovalStatus(approvalId: string): ApprovalRequest | undefined {
    return pendingApprovals.get(approvalId);
  }

  /**
   * Check if an approval is valid (approved and not expired)
   */
  isApproved(approvalId: string): boolean {
    const request = pendingApprovals.get(approvalId);
    return request?.status === 'approved';
  }

  /**
   * List all pending approvals
   */
  listPendingApprovals(): ApprovalRequest[] {
    const pending: ApprovalRequest[] = [];
    const now = new Date();

    for (const [id, request] of pendingApprovals) {
      if (request.status === 'pending') {
        if (now > request.expiresAt) {
          this.expireApproval(id);
        } else {
          pending.push(request);
        }
      }
    }

    return pending;
  }

  /**
   * Expire an approval request
   */
  private expireApproval(approvalId: string): void {
    const request = pendingApprovals.get(approvalId);
    
    if (!request || request.status !== 'pending') {
      return;
    }

    request.status = 'expired';
    pendingApprovals.set(approvalId, request);

    // Clear timer
    const timer = approvalTimers.get(approvalId);
    if (timer) {
      clearTimeout(timer);
      approvalTimers.delete(approvalId);
    }

    // Reject callback
    const callback = approvalCallbacks.get(approvalId);
    if (callback) {
      callback.resolve(false);
      approvalCallbacks.delete(approvalId);
    }

    // Log expiry
    auditLogger.logApprovalEvent('EXPIRED', approvalId, request.action);
    logger.warn('Approval expired', { approvalId });
  }

  /**
   * Clear all pending approvals (cleanup)
   */
  clearAllApprovals(): void {
    for (const [id, timer] of approvalTimers) {
      clearTimeout(timer);
    }
    approvalTimers.clear();
    approvalCallbacks.clear();
    pendingApprovals.clear();
    logger.info('All pending approvals cleared');
  }

  /**
   * Get approval summary for display
   */
  getApprovalSummary(approvalId: string): string | null {
    const request = pendingApprovals.get(approvalId);
    if (!request) {
      return null;
    }

    const lines = [
      `🔐 Approval Required (${request.risk.toUpperCase()} risk)`,
      ``,
      `Action: ${request.action}`,
      `Description: ${request.description}`,
    ];

    if (request.command) {
      lines.push(`Command: ${request.command}`);
    }

    lines.push(``, `Approval ID: ${approvalId}`);
    lines.push(`Expires: ${request.expiresAt.toISOString()}`);

    return lines.join('\n');
  }
}

// Singleton instance
export const approvalManager = new ApprovalManager();

export default approvalManager;

/**
 * Access Mode Manager
 * Handles SAFE / PROVISION / FULL mode enforcement
 */

import { v4 as uuidv4 } from 'uuid';
import {
  AccessMode,
  ModePermissions,
  Session,
} from '../types/index.js';
import {
  PermissionDeniedError,
  RiskNotAcknowledgedError,
  SessionExpiredError,
} from '../types/errors.js';
import { auditLogger, logger } from './logger.js';

// Default permissions for each mode
const MODE_PERMISSIONS: Record<AccessMode, ModePermissions> = {
  [AccessMode.SAFE]: {
    os: false,
    docker: true,  // Can interact with existing containers
    nginx: false,
    firewall: false,
    disk: false,
    network: false,
    systemd: false,
  },
  [AccessMode.PROVISION]: {
    os: true,
    docker: true,
    nginx: true,
    firewall: true,
    disk: false,  // Still restricted
    network: true,
    systemd: true,
  },
  [AccessMode.FULL]: {
    os: true,
    docker: true,
    nginx: true,
    firewall: true,
    disk: true,
    network: true,
    systemd: true,
  },
};

// Risk warnings for each mode
const MODE_WARNINGS: Record<AccessMode, string[]> = {
  [AccessMode.SAFE]: [],
  [AccessMode.PROVISION]: [
    '⚠️ PROVISION MODE: This mode allows system-level changes.',
    '⚠️ Commands can install packages, modify services, and configure the OS.',
    '⚠️ All actions are logged and auditable.',
  ],
  [AccessMode.FULL]: [
    '🔥 FULL ACCESS MODE: Root-level unrestricted access enabled.',
    '🔥 This mode can perform ANY action on the target system.',
    '🔥 This includes destructive operations that may be irreversible.',
    '🔥 You accept full responsibility for all actions taken.',
    '🔥 All actions are logged for audit purposes.',
  ],
};

// Default expiry times
const DEFAULT_EXPIRY: Record<AccessMode, number> = {
  [AccessMode.SAFE]: 0, // No expiry
  [AccessMode.PROVISION]: 60 * 60 * 1000, // 1 hour
  [AccessMode.FULL]: 30 * 60 * 1000, // 30 minutes
};

export class ModeManager {
  private currentSession: Session | null = null;

  /**
   * Get current access mode
   */
  getCurrentMode(): AccessMode {
    if (!this.currentSession) {
      return AccessMode.SAFE;
    }
    
    // Check if session expired
    if (this.currentSession.expiresAt && new Date() > this.currentSession.expiresAt) {
      this.expireSession();
      return AccessMode.SAFE;
    }

    return this.currentSession.mode;
  }

  /**
   * Get current session
   */
  getSession(): Session | null {
    return this.currentSession;
  }

  /**
   * Get permissions for current mode
   */
  getCurrentPermissions(): ModePermissions {
    return MODE_PERMISSIONS[this.getCurrentMode()];
  }

  /**
   * Get warnings for a specific mode
   */
  getModeWarnings(mode: AccessMode): string[] {
    return MODE_WARNINGS[mode];
  }

  /**
   * Check if current mode has a specific permission
   */
  hasPermission(permission: keyof ModePermissions): boolean {
    const permissions = this.getCurrentPermissions();
    return permissions[permission];
  }

  /**
   * Require a specific permission, throw if not available
   */
  requirePermission(permission: keyof ModePermissions, action: string): void {
    if (!this.hasPermission(permission)) {
      const currentMode = this.getCurrentMode();
      let requiredMode = AccessMode.PROVISION;
      
      if (permission === 'disk') {
        requiredMode = AccessMode.FULL;
      }

      throw new PermissionDeniedError(
        `Action "${action}" requires ${permission} permission. Current mode: ${currentMode}`,
        requiredMode,
        currentMode
      );
    }
  }

  /**
   * Initialize a session with SAFE mode
   */
  initializeSession(): Session {
    const sessionId = uuidv4();
    
    this.currentSession = {
      id: sessionId,
      createdAt: new Date(),
      mode: AccessMode.SAFE,
      modeConfig: {
        mode: AccessMode.SAFE,
        permissions: MODE_PERMISSIONS[AccessMode.SAFE],
      },
      isActive: true,
      riskAcknowledged: false,
    };

    auditLogger.setSessionId(sessionId);
    auditLogger.logSessionEvent('STARTED', { mode: AccessMode.SAFE });
    logger.info(`Session initialized: ${sessionId}`);

    return this.currentSession;
  }

  /**
   * Elevate to a higher access mode
   * Requires explicit risk acknowledgement for PROVISION and FULL modes
   */
  elevateMode(
    targetMode: AccessMode,
    acknowledgeRisk: boolean,
    acknowledgedBy: string,
    expiresIn?: string
  ): Session {
    if (!this.currentSession) {
      this.initializeSession();
    }

    const currentMode = this.getCurrentMode();

    // SAFE mode doesn't need acknowledgement
    if (targetMode === AccessMode.SAFE) {
      return this.setMode(targetMode);
    }

    // Check risk acknowledgement for elevated modes
    if (!acknowledgeRisk) {
      throw new RiskNotAcknowledgedError(targetMode);
    }

    // Log risk acknowledgement
    auditLogger.logRiskAcknowledgement(targetMode, acknowledgedBy);
    auditLogger.logModeChange(currentMode, targetMode, acknowledgedBy);

    // Calculate expiry
    let expiresAt: Date | undefined;
    if (expiresIn) {
      expiresAt = this.parseExpiry(expiresIn);
    } else if (DEFAULT_EXPIRY[targetMode] > 0) {
      expiresAt = new Date(Date.now() + DEFAULT_EXPIRY[targetMode]);
    }

    // Update session
    this.currentSession = {
      ...this.currentSession!,
      mode: targetMode,
      expiresAt,
      modeConfig: {
        mode: targetMode,
        permissions: MODE_PERMISSIONS[targetMode],
        expiresAt,
        expiresIn,
        acknowledgedAt: new Date(),
        acknowledgedBy,
      },
      riskAcknowledged: true,
    };

    logger.warn(`Mode elevated to ${targetMode}`, {
      sessionId: this.currentSession.id,
      expiresAt,
      acknowledgedBy,
    });

    return this.currentSession;
  }

  /**
   * Downgrade to a lower access mode (always allowed)
   */
  downgradeMode(targetMode: AccessMode): Session {
    if (!this.currentSession) {
      return this.initializeSession();
    }

    const currentMode = this.getCurrentMode();
    auditLogger.logModeChange(currentMode, targetMode);

    this.currentSession = {
      ...this.currentSession,
      mode: targetMode,
      expiresAt: undefined,
      modeConfig: {
        mode: targetMode,
        permissions: MODE_PERMISSIONS[targetMode],
      },
    };

    logger.info(`Mode downgraded to ${targetMode}`, {
      sessionId: this.currentSession.id,
    });

    return this.currentSession;
  }

  /**
   * Internal: Set mode directly
   */
  private setMode(mode: AccessMode): Session {
    if (!this.currentSession) {
      this.initializeSession();
    }

    this.currentSession = {
      ...this.currentSession!,
      mode,
      modeConfig: {
        mode,
        permissions: MODE_PERMISSIONS[mode],
      },
    };

    return this.currentSession;
  }

  /**
   * Expire the current session
   */
  expireSession(): void {
    if (this.currentSession) {
      auditLogger.logSessionEvent('EXPIRED', {
        previousMode: this.currentSession.mode,
      });
      logger.warn(`Session expired: ${this.currentSession.id}`);
    }

    // Reset to safe mode
    this.currentSession = {
      id: this.currentSession?.id || uuidv4(),
      createdAt: this.currentSession?.createdAt || new Date(),
      mode: AccessMode.SAFE,
      modeConfig: {
        mode: AccessMode.SAFE,
        permissions: MODE_PERMISSIONS[AccessMode.SAFE],
      },
      isActive: true,
      riskAcknowledged: false,
    };
  }

  /**
   * End the current session
   */
  endSession(): void {
    if (this.currentSession) {
      auditLogger.logSessionEvent('ENDED', {
        mode: this.currentSession.mode,
        duration: Date.now() - this.currentSession.createdAt.getTime(),
      });
      logger.info(`Session ended: ${this.currentSession.id}`);
    }
    this.currentSession = null;
  }

  /**
   * Check if mode requires approval for a specific action type
   */
  requiresApproval(actionType: string): boolean {
    const mode = this.getCurrentMode();
    
    // In SAFE mode, many actions need approval
    if (mode === AccessMode.SAFE) {
      const approvalRequired = [
        'install_package',
        'modify_system',
        'firewall_change',
        'disk_operation',
      ];
      return approvalRequired.includes(actionType);
    }

    // In PROVISION mode, destructive actions need approval
    if (mode === AccessMode.PROVISION) {
      const approvalRequired = [
        'disk_operation',
        'delete_data',
        'system_upgrade',
      ];
      return approvalRequired.includes(actionType);
    }

    // FULL mode - no automatic approval required (user chose this)
    return false;
  }

  /**
   * Validate that session is active and not expired
   */
  validateSession(): void {
    if (!this.currentSession) {
      this.initializeSession();
      return;
    }

    if (this.currentSession.expiresAt && new Date() > this.currentSession.expiresAt) {
      const sessionId = this.currentSession.id;
      this.expireSession();
      throw new SessionExpiredError(sessionId);
    }
  }

  /**
   * Get time remaining before mode expires
   */
  getTimeRemaining(): number | null {
    if (!this.currentSession?.expiresAt) {
      return null;
    }

    const remaining = this.currentSession.expiresAt.getTime() - Date.now();
    return remaining > 0 ? remaining : 0;
  }

  /**
   * Parse expiry string (e.g., "30m", "2h", "1d")
   */
  private parseExpiry(expiresIn: string): Date {
    const match = expiresIn.match(/^(\d+)([mhd])$/);
    if (!match) {
      throw new Error(`Invalid expiry format: ${expiresIn}. Use format like "30m", "2h", "1d"`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    let milliseconds: number;
    switch (unit) {
      case 'm':
        milliseconds = value * 60 * 1000;
        break;
      case 'h':
        milliseconds = value * 60 * 60 * 1000;
        break;
      case 'd':
        milliseconds = value * 24 * 60 * 60 * 1000;
        break;
      default:
        throw new Error(`Unknown time unit: ${unit}`);
    }

    return new Date(Date.now() + milliseconds);
  }
}

// Singleton instance
export const modeManager = new ModeManager();

export default modeManager;

/**
 * SSH Key Manager
 * Handles per-session SSH key generation, upload, and auto-expiry
 */

import { generateKeyPairSync, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { SSHKeyInfo } from '../types/index.js';
import { auditLogger, logger } from './logger.js';

// Default key expiry time (30 minutes)
const DEFAULT_KEY_EXPIRY_MS = 30 * 60 * 1000;

// Store active keys (in production, use secure storage)
const activeKeys: Map<string, SSHKeyInfo> = new Map();

// Expiry timers
const expiryTimers: Map<string, NodeJS.Timeout> = new Map();

export class SSHKeyManager {
  /**
   * Generate a new SSH key pair for a session
   */
  generateSessionKey(
    sessionId: string,
    expiryMs: number = DEFAULT_KEY_EXPIRY_MS
  ): SSHKeyInfo {
    // Generate ED25519 key pair
    const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    // Convert to OpenSSH format for authorized_keys
    const sshPublicKey = this.pemToOpenSSH(publicKey, sessionId);

    // Generate fingerprint
    const fingerprint = this.generateFingerprint(publicKey);

    const keyInfo: SSHKeyInfo = {
      sessionId,
      publicKey: sshPublicKey,
      privateKey,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + expiryMs),
      fingerprint,
    };

    // Store key
    activeKeys.set(sessionId, keyInfo);

    // Set up auto-expiry
    this.scheduleExpiry(sessionId, expiryMs);

    // Log key generation
    auditLogger.logSSHKeyEvent('GENERATED', fingerprint);
    logger.info('SSH key generated', { sessionId, fingerprint, expiresAt: keyInfo.expiresAt });

    return keyInfo;
  }

  /**
   * Get key info for a session
   */
  getKeyInfo(sessionId: string): SSHKeyInfo | undefined {
    const keyInfo = activeKeys.get(sessionId);
    
    // Check if expired
    if (keyInfo && new Date() > keyInfo.expiresAt) {
      this.revokeKey(sessionId);
      return undefined;
    }

    return keyInfo;
  }

  /**
   * Revoke a session's SSH key
   */
  revokeKey(sessionId: string): boolean {
    const keyInfo = activeKeys.get(sessionId);
    
    if (!keyInfo) {
      return false;
    }

    // Clear expiry timer
    const timer = expiryTimers.get(sessionId);
    if (timer) {
      clearTimeout(timer);
      expiryTimers.delete(sessionId);
    }

    // Remove key
    activeKeys.delete(sessionId);

    // Log revocation
    auditLogger.logSSHKeyEvent('REVOKED', keyInfo.fingerprint);
    logger.info('SSH key revoked', { sessionId, fingerprint: keyInfo.fingerprint });

    return true;
  }

  /**
   * Extend key expiry time
   */
  extendKeyExpiry(sessionId: string, additionalMs: number): boolean {
    const keyInfo = activeKeys.get(sessionId);
    
    if (!keyInfo) {
      return false;
    }

    // Clear existing timer
    const timer = expiryTimers.get(sessionId);
    if (timer) {
      clearTimeout(timer);
    }

    // Update expiry
    const newExpiry = new Date(keyInfo.expiresAt.getTime() + additionalMs);
    keyInfo.expiresAt = newExpiry;
    activeKeys.set(sessionId, keyInfo);

    // Schedule new expiry
    const remainingMs = newExpiry.getTime() - Date.now();
    this.scheduleExpiry(sessionId, remainingMs);

    logger.info('SSH key expiry extended', { 
      sessionId, 
      newExpiresAt: newExpiry,
      fingerprint: keyInfo.fingerprint,
    });

    return true;
  }

  /**
   * Generate command to add key to authorized_keys on remote server
   */
  getAuthorizedKeysCommand(sessionId: string): string | null {
    const keyInfo = activeKeys.get(sessionId);
    if (!keyInfo) {
      return null;
    }

    // Command to add key with comment for identification
    const escapedKey = keyInfo.publicKey.replace(/'/g, "'\\''");
    return `echo '${escapedKey}' >> ~/.ssh/authorized_keys`;
  }

  /**
   * Generate command to remove key from authorized_keys
   */
  getRemoveKeyCommand(sessionId: string): string {
    // Remove key by session ID comment
    return `sed -i '/${sessionId}/d' ~/.ssh/authorized_keys`;
  }

  /**
   * List all active keys
   */
  listActiveKeys(): SSHKeyInfo[] {
    const now = new Date();
    const keys: SSHKeyInfo[] = [];

    for (const [sessionId, keyInfo] of activeKeys) {
      if (now > keyInfo.expiresAt) {
        // Expired, clean up
        this.revokeKey(sessionId);
      } else {
        keys.push(keyInfo);
      }
    }

    return keys;
  }

  /**
   * Get time remaining until key expires
   */
  getTimeRemaining(sessionId: string): number | null {
    const keyInfo = activeKeys.get(sessionId);
    if (!keyInfo) {
      return null;
    }

    const remaining = keyInfo.expiresAt.getTime() - Date.now();
    return remaining > 0 ? remaining : 0;
  }

  /**
   * Revoke all keys (cleanup)
   */
  revokeAllKeys(): void {
    for (const sessionId of activeKeys.keys()) {
      this.revokeKey(sessionId);
    }
    logger.info('All SSH keys revoked');
  }

  /**
   * Schedule automatic key expiry
   */
  private scheduleExpiry(sessionId: string, delayMs: number): void {
    const timer = setTimeout(() => {
      const keyInfo = activeKeys.get(sessionId);
      if (keyInfo) {
        auditLogger.logSSHKeyEvent('EXPIRED', keyInfo.fingerprint);
        logger.warn('SSH key expired', { sessionId, fingerprint: keyInfo.fingerprint });
      }
      this.revokeKey(sessionId);
    }, delayMs);

    expiryTimers.set(sessionId, timer);
  }

  /**
   * Convert PEM public key to OpenSSH format
   * Note: This is a simplified conversion for ED25519 keys
   */
  private pemToOpenSSH(pemKey: string, comment: string): string {
    // For a proper implementation, use a library like sshpk
    // This is a placeholder that returns the key with a comment
    const keyData = pemKey
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace(/\s/g, '');
    
    return `ssh-ed25519 ${keyData} mcp-session-${comment}`;
  }

  /**
   * Generate fingerprint from public key
   */
  private generateFingerprint(publicKey: string): string {
    const hash = createHash('sha256');
    hash.update(publicKey);
    return hash.digest('hex').substring(0, 16);
  }
}

// Singleton instance
export const sshKeyManager = new SSHKeyManager();

export default sshKeyManager;

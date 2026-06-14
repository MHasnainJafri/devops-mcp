/**
 * Unit tests for the command validator — the security boundary that decides
 * which access mode a command needs and whether the current mode allows it.
 */

import { describe, it, expect } from 'vitest';
import { commandValidator } from '../src/core/command-validator.js';
import { AccessMode } from '../src/types/index.js';

const validate = (command: string, mode: AccessMode = AccessMode.SAFE, args?: string[]) =>
  commandValidator.validate({ command, args }, mode);

describe('CommandValidator', () => {
  describe('SAFE mode allowlist', () => {
    it.each(['ls -la', 'df -h', 'cat /etc/hostname', 'docker ps', 'uptime', 'free -m'])(
      'allows read-only command in SAFE mode: %s',
      (cmd) => {
        const result = validate(cmd);
        expect(result.allowed).toBe(true);
        expect(result.requiredMode).toBe(AccessMode.SAFE);
      }
    );

    it('rejects an empty command', () => {
      const result = validate('   ');
      expect(result.valid).toBe(false);
      expect(result.allowed).toBe(false);
    });

    it('refuses SAFE for a read-only command with a write redirect', () => {
      const result = validate('cat /etc/passwd > /tmp/stolen');
      expect(result.requiredMode).not.toBe(AccessMode.SAFE);
      expect(result.allowed).toBe(false);
    });

    it('refuses SAFE for an append redirect', () => {
      const result = validate('echo x >> /etc/profile');
      expect(result.requiredMode).not.toBe(AccessMode.SAFE);
    });
  });

  describe('mode escalation', () => {
    it('requires elevation for package installs', () => {
      const result = validate('apt-get install -y nginx');
      expect(result.requiredMode).not.toBe(AccessMode.SAFE);
      expect(result.allowed).toBe(false);
    });

    it('requires FULL for destructive commands', () => {
      const result = validate('rm -rf /var/www');
      expect(result.requiredMode).toBe(AccessMode.FULL);
      expect(result.allowed).toBe(false);
    });

    it('allows elevated commands when the current mode is high enough', () => {
      const result = validate('rm -rf /tmp/build', AccessMode.FULL);
      expect(result.allowed).toBe(true);
    });
  });

  describe('chained commands', () => {
    it('escalates the whole chain to its most dangerous fragment', () => {
      const result = validate('ls && rm -rf /opt/app');
      expect(result.requiredMode).toBe(AccessMode.FULL);
      expect(result.allowed).toBe(false);
    });

    it('keeps an all-read-only chain SAFE', () => {
      const result = validate('df -h && free -m');
      expect(result.allowed).toBe(true);
      expect(result.requiredMode).toBe(AccessMode.SAFE);
    });
  });

  describe('args injection', () => {
    it('inspects args so chain operators cannot slip through', () => {
      const result = validate('ls', AccessMode.SAFE, ['; rm -rf /']);
      expect(result.allowed).toBe(false);
      expect(result.requiredMode).toBe(AccessMode.FULL);
    });
  });

  describe('command substitution', () => {
    it('keeps read-only $(...) substitutions SAFE', () => {
      const result = validate('echo $(docker ps -q)');
      expect(result.requiredMode).toBe(AccessMode.SAFE);
      expect(result.allowed).toBe(true);
    });

    it('escalates when the substitution body is dangerous', () => {
      const result = validate('echo $(rm -rf /data)');
      expect(result.requiredMode).toBe(AccessMode.FULL);
      expect(result.allowed).toBe(false);
    });
  });
});

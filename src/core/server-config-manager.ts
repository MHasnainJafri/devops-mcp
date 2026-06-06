/**
 * Server Configuration Manager
 * Manages server definitions from config/{serverId}/server.json
 * Each server has its own folder with config and optional key file
 * 
 * Structure:
 *   config/
 *   ├── my-server/
 *   │   ├── server.json    # Server configuration
 *   │   └── key.pem        # Optional SSH key (any filename)
 *   ├── production/
 *   │   ├── server.json
 *   │   └── id_rsa
 *   └── _example/
 *       └── server.json    # Example template
 */

import { readFileSync, existsSync, writeFileSync, mkdirSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { AccessMode } from '../types/index.js';
import { logger } from './logger.js';

// Get project root from module location (src/core/server-config-manager.ts -> project root)
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_ROOT = join(__dirname, '..', '..');
const CONFIG_DIR = join(PROJECT_ROOT, 'config');

export interface ServerRestrictions {
  allowedModes: AccessMode[];
  blockedCommands: string[];
  allowedPaths?: string[];
  requireApproval: boolean;
}

export interface ServerConfig {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authType: 'key' | 'password';
  keyFile?: string;            // Filename inside config/<id>/ (copy-in flow)
  externalKeyPath?: string;    // Absolute path to a key we DON'T copy
                               // (e.g. ~/.ssh/id_ed25519). Preferred for
                               // personal workstation keys.
  password?: string;           // Literal or $ENV_VAR reference
  role: 'production' | 'staging' | 'development' | 'testing';
  restrictions: ServerRestrictions;
  description?: string;
}

// Default restrictions by role
const DEFAULT_RESTRICTIONS: Record<string, ServerRestrictions> = {
  production: {
    allowedModes: [AccessMode.SAFE],
    blockedCommands: ['rm -rf', 'shutdown', 'reboot', 'dd', 'mkfs', 'fdisk'],
    requireApproval: true,
  },
  staging: {
    allowedModes: [AccessMode.SAFE, AccessMode.PROVISION],
    blockedCommands: ['rm -rf /', 'shutdown', 'reboot'],
    requireApproval: false,
  },
  development: {
    allowedModes: [AccessMode.SAFE, AccessMode.PROVISION, AccessMode.FULL],
    blockedCommands: [],
    requireApproval: false,
  },
  testing: {
    allowedModes: [AccessMode.SAFE, AccessMode.PROVISION],
    blockedCommands: [],
    requireApproval: false,
  },
};

export class ServerConfigManager {
  private servers: Map<string, ServerConfig> = new Map();
  private configLoaded: boolean = false;

  constructor() {
    this.ensureConfigDir();
  }

  /**
   * Get server folder path
   */
  private getServerDir(serverId: string): string {
    return join(CONFIG_DIR, serverId);
  }

  /**
   * Get server config file path
   */
  private getServerConfigPath(serverId: string): string {
    return join(this.getServerDir(serverId), 'server.json');
  }

  /**
   * Ensure config directory exists
   */
  private ensureConfigDir(): void {
    if (!existsSync(CONFIG_DIR)) {
      mkdirSync(CONFIG_DIR, { recursive: true });
    }
  }

  /**
   * Load all servers from config/{serverId}/server.json files
   */
  loadConfig(): boolean {
    try {
      this.servers.clear();

      if (!existsSync(CONFIG_DIR)) {
        logger.warn('Config directory not found');
        return false;
      }

      // Read all directories in config/
      const entries = readdirSync(CONFIG_DIR, { withFileTypes: true });
      
      for (const entry of entries) {
        // Skip non-directories and special folders
        if (!entry.isDirectory() || entry.name.startsWith('_') || entry.name === 'keys') {
          continue;
        }

        const serverId = entry.name;
        const configPath = this.getServerConfigPath(serverId);

        if (!existsSync(configPath)) {
          logger.warn(`No server.json in ${serverId}/ folder`);
          continue;
        }

        try {
          const content = readFileSync(configPath, 'utf-8');
          const serverConfig = JSON.parse(content) as Partial<ServerConfig>;

          // Ensure ID matches folder name
          serverConfig.id = serverId;

          // Apply defaults
          serverConfig.port = serverConfig.port || 22;
          serverConfig.authType = serverConfig.authType || 'key';

          // Heal incomplete configs (hand-written server.json with missing
          // role / empty restrictions {} would otherwise blow up downstream
          // when callers do server.restrictions.allowedModes.includes(...)).
          if (!serverConfig.role) {
            logger.warn(`Server "${serverId}" has no role set in server.json; defaulting to "development".`);
            serverConfig.role = 'development';
          }
          const roleDefaults = DEFAULT_RESTRICTIONS[serverConfig.role] || DEFAULT_RESTRICTIONS.development;
          serverConfig.restrictions = {
            ...roleDefaults,
            ...(serverConfig.restrictions || {}),
          } as ServerRestrictions;
          // Make sure every required sub-field is present even if the user
          // wrote `restrictions: {}` manually.
          if (!Array.isArray(serverConfig.restrictions.allowedModes)) {
            serverConfig.restrictions.allowedModes = roleDefaults.allowedModes;
          }
          if (!Array.isArray(serverConfig.restrictions.blockedCommands)) {
            serverConfig.restrictions.blockedCommands = roleDefaults.blockedCommands;
          }
          if (typeof serverConfig.restrictions.requireApproval !== 'boolean') {
            serverConfig.restrictions.requireApproval = roleDefaults.requireApproval;
          }

          this.servers.set(serverId, serverConfig as ServerConfig);
          logger.debug(`Loaded server config: ${serverId}`);
        } catch (error) {
          logger.error(`Failed to load server config: ${serverId}`, {
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }

      this.configLoaded = true;
      logger.info(`Loaded ${this.servers.size} server configurations`);
      return true;
    } catch (error) {
      logger.error('Failed to load server configs', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }

  /**
   * Get server by ID
   */
  getServer(serverId: string): ServerConfig | undefined {
    if (!this.configLoaded) {
      this.loadConfig();
    }
    return this.servers.get(serverId);
  }

  /**
   * List all configured servers
   */
  listServers(): ServerConfig[] {
    if (!this.configLoaded) {
      this.loadConfig();
    }
    return Array.from(this.servers.values());
  }

  /**
   * Get path to SSH key file for a server.
   *
   * Resolution order:
   *   1. externalKeyPath  – an absolute path we don't own (e.g. ~/.ssh/id_rsa).
   *      Preferred when the user already has a workstation key on the server.
   *   2. keyFile          – filename inside config/<id>/, written there during
   *      `add_server` when the user supplied a file or inline key.
   */
  getKeyPath(serverId: string): string | null {
    const server = this.getServer(serverId);
    if (!server) return null;

    if (server.externalKeyPath) {
      if (!existsSync(server.externalKeyPath)) {
        logger.warn(`externalKeyPath does not exist: ${server.externalKeyPath}`);
        return null;
      }
      return server.externalKeyPath;
    }

    if (!server.keyFile) return null;

    const keyPath = join(this.getServerDir(serverId), server.keyFile);
    if (!existsSync(keyPath)) {
      logger.warn(`SSH key file not found: ${serverId}/${server.keyFile}`);
      return null;
    }
    return keyPath;
  }

  /**
   * Check if a key file exists for a server
   */
  hasKeyFile(serverId: string): boolean {
    return this.getKeyPath(serverId) !== null;
  }

  /**
   * Check if server has valid authentication configured
   */
  hasValidAuth(serverId: string): boolean {
    const server = this.getServer(serverId);
    if (!server) return false;

    if (server.authType === 'password') {
      return !!server.password;
    }
    return this.hasKeyFile(serverId);
  }

  /**
   * Get password for a server (resolves environment variables)
   */
  getPassword(serverId: string): string | null {
    const server = this.getServer(serverId);
    if (!server || !server.password) return null;

    // Check if password is an environment variable reference
    if (server.password.startsWith('$')) {
      const envVar = server.password.substring(1);
      return process.env[envVar] || null;
    }

    return server.password;
  }

  /**
   * Get auth info for connecting to a server
   */
  getAuthInfo(serverId: string): { type: 'key' | 'password'; keyPath?: string; password?: string } | null {
    const server = this.getServer(serverId);
    if (!server) return null;

    if (server.authType === 'password') {
      const password = this.getPassword(serverId);
      if (!password) return null;
      return { type: 'password', password };
    }

    const keyPath = this.getKeyPath(serverId);
    if (!keyPath) return null;
    return { type: 'key', keyPath };
  }

  /**
   * Check if current mode is allowed for a server.
   * Hardened against partially-populated restrictions; if the data shape is
   * unusable we treat the policy as "deny" rather than crashing.
   */
  isModeAllowed(serverId: string, mode: AccessMode): boolean {
    const server = this.getServer(serverId);
    if (!server) return false;
    const allowed = server.restrictions?.allowedModes;
    if (!Array.isArray(allowed)) return false;
    return allowed.includes(mode);
  }

  /**
   * Check if a command is blocked on a server.
   * Missing config → fail closed (treat as blocked).
   */
  isCommandBlocked(serverId: string, command: string): boolean {
    const server = this.getServer(serverId);
    if (!server) return true;
    const blockedList = server.restrictions?.blockedCommands;
    if (!Array.isArray(blockedList)) return false; // empty / not configured → not blocked
    const lowerCommand = command.toLowerCase();
    return blockedList.some(blocked => lowerCommand.includes(blocked.toLowerCase()));
  }

  /**
   * Check if command path is allowed (if paths are restricted)
   */
  isPathAllowed(serverId: string, path: string): boolean {
    const server = this.getServer(serverId);
    if (!server) return false;
    const allowedPaths = server.restrictions?.allowedPaths;
    if (!Array.isArray(allowedPaths) || allowedPaths.length === 0) return true;
    return allowedPaths.some(allowed => path.startsWith(allowed));
  }

  /**
   * Check if server requires approval for commands
   */
  requiresApproval(serverId: string): boolean {
    const server = this.getServer(serverId);
    return server?.restrictions.requireApproval ?? true;
  }

  /**
   * Create initial config structure with example
   */
  createInitialConfig(): boolean {
    try {
      // Create example server folder
      const exampleDir = join(CONFIG_DIR, '_example');
      if (!existsSync(exampleDir)) {
        mkdirSync(exampleDir, { recursive: true });
        
        const exampleConfig = {
          name: 'Example Server',
          host: '192.168.1.100',
          port: 22,
          username: 'ubuntu',
          authType: 'key',
          keyFile: 'key.pem',
          role: 'development',
          description: 'Example server configuration - copy this folder and rename it'
        };
        
        writeFileSync(
          join(exampleDir, 'server.json'),
          JSON.stringify(exampleConfig, null, 2)
        );
        
        logger.info('Created example server config at config/_example/');
        return true;
      }

      logger.info('Config already initialized');
      return false;
    } catch (error) {
      logger.error('Failed to create initial config', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }

  /**
   * Add a new server by creating its folder and config
   */
  addServer(server: Omit<ServerConfig, 'restrictions' | 'id'> & { 
    id: string;
    restrictions?: Partial<ServerRestrictions>;
  }): boolean {
    try {
      const serverDir = this.getServerDir(server.id);
      
      // Check if already exists
      if (existsSync(serverDir)) {
        logger.warn(`Server folder already exists: ${server.id}`);
        return false;
      }

      // Create server folder
      mkdirSync(serverDir, { recursive: true });

      // Build config object (without id, as folder name is the id)
      const configToSave = {
        name: server.name,
        host: server.host,
        port: server.port || 22,
        username: server.username,
        authType: server.authType || 'key',
        ...(server.keyFile && { keyFile: server.keyFile }),
        ...(server.externalKeyPath && { externalKeyPath: server.externalKeyPath }),
        ...(server.password && { password: server.password }),
        role: server.role,
        ...(server.description && { description: server.description }),
        restrictions: {
          ...DEFAULT_RESTRICTIONS[server.role],
          ...server.restrictions,
        },
      };

      // Write config file
      writeFileSync(
        this.getServerConfigPath(server.id),
        JSON.stringify(configToSave, null, 2)
      );

      // Reload configs
      this.configLoaded = false;
      this.loadConfig();

      logger.info(`Created server: ${server.id}`);
      return true;
    } catch (error) {
      logger.error('Failed to add server', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }

  /**
   * Path to the persisted scan profile for a server.
   */
  getProfilePath(serverId: string): string {
    return join(this.getServerDir(serverId), 'profile.json');
  }

  /**
   * Persist a ServerProfile to disk. Scanned content is data, not code —
   * we never `eval` or interpolate it. Stored as JSON next to server.json.
   */
  saveProfile(serverId: string, profile: unknown): boolean {
    try {
      const dir = this.getServerDir(serverId);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(this.getProfilePath(serverId), JSON.stringify(profile, null, 2));
      return true;
    } catch (e) {
      logger.error('Failed to save profile', {
        serverId,
        error: e instanceof Error ? e.message : 'unknown',
      });
      return false;
    }
  }

  /**
   * Load the last persisted profile (or null if none).
   */
  loadProfile(serverId: string): any | null {
    const p = this.getProfilePath(serverId);
    if (!existsSync(p)) return null;
    try {
      return JSON.parse(readFileSync(p, 'utf-8'));
    } catch (e) {
      logger.warn('Failed to parse profile', { serverId });
      return null;
    }
  }

  /**
   * Update an existing server's mutable fields. Does NOT touch auth (keyFile,
   * password, externalKeyPath, authType, username, host, port) — credentials
   * stay in their dedicated files for safety.
   *
   * Returns false if the server doesn't exist or the write fails.
   */
  updateServer(
    serverId: string,
    patch: Partial<{
      name: string;
      description: string;
      role: ServerConfig['role'];
      restrictions: Partial<ServerRestrictions>;
      applyRoleDefaults: boolean;
    }>
  ): { ok: boolean; before?: ServerConfig; after?: ServerConfig; error?: string } {
    const before = this.getServer(serverId);
    if (!before) return { ok: false, error: `Server "${serverId}" not found` };

    // Read the file directly so we preserve any fields we don't manage.
    const configPath = this.getServerConfigPath(serverId);
    let raw: any;
    try {
      raw = JSON.parse(readFileSync(configPath, 'utf-8'));
    } catch (e) {
      return { ok: false, error: `Failed to read server.json: ${e instanceof Error ? e.message : 'unknown'}` };
    }

    if (patch.name !== undefined) raw.name = patch.name;
    if (patch.description !== undefined) raw.description = patch.description;

    if (patch.role !== undefined) {
      raw.role = patch.role;
      // Role-default reset only when explicitly asked. Otherwise we keep
      // the existing restrictions exactly as the user has them.
      if (patch.applyRoleDefaults) {
        raw.restrictions = { ...(DEFAULT_RESTRICTIONS[patch.role] || DEFAULT_RESTRICTIONS.development) };
      }
    }

    if (patch.restrictions) {
      raw.restrictions = { ...(raw.restrictions || {}), ...patch.restrictions };
    }

    try {
      writeFileSync(configPath, JSON.stringify(raw, null, 2));
    } catch (e) {
      return { ok: false, error: `Failed to write server.json: ${e instanceof Error ? e.message : 'unknown'}` };
    }

    // Force a re-read on next call so the in-memory map matches disk.
    this.configLoaded = false;
    this.loadConfig();
    const after = this.getServer(serverId);

    logger.info('Server updated', { serverId, fields: Object.keys(patch) });
    return { ok: true, before, after };
  }

  /**
   * Get setup status for user guidance
   */
  getSetupStatus(): {
    configExists: boolean;
    serverCount: number;
    serversReady: string[];
    serversMissingAuth: string[];
  } {
    this.configLoaded = false;
    this.loadConfig();
    
    const servers = this.listServers();
    const serversReady: string[] = [];
    const serversMissingAuth: string[] = [];

    for (const server of servers) {
      if (this.hasValidAuth(server.id)) {
        serversReady.push(server.id);
      } else {
        serversMissingAuth.push(server.id);
      }
    }

    return {
      configExists: existsSync(CONFIG_DIR),
      serverCount: servers.length,
      serversReady,
      serversMissingAuth,
    };
  }
}

// Singleton instance
export const serverConfigManager = new ServerConfigManager();

export default serverConfigManager;

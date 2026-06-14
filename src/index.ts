#!/usr/bin/env node

/**
 * DevOps MCP Server
 * Main entry point - initializes MCP server with all tools
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import { TOOL_DEFINITIONS } from './tools/tool-schemas.js';
import { TOOL_HANDLERS } from './tools/tool-handlers.js';
import { modeManager } from './core/mode-manager.js';
import { logger, auditLogger } from './core/logger.js';
import { sshKeyManager } from './core/ssh-key-manager.js';
import { approvalManager } from './core/approval-manager.js';

const SERVER_NAME = 'devops-mcp';
const SERVER_VERSION = '1.0.0';

/**
 * Main server class
 */
class DevOpsMCPServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: SERVER_NAME,
        version: SERVER_VERSION,
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupHandlers();
    this.setupErrorHandling();
  }

  /**
   * Setup request handlers
   */
  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: TOOL_DEFINITIONS.map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: this.zodToJsonSchema(tool.inputSchema),
        })),
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      logger.info('Tool called', { tool: name, hasArgs: !!args });

      // Find handler
      const handler = TOOL_HANDLERS[name];
      if (!handler) {
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
      }

      try {
        // Execute handler
        const result = await handler(args || {});

        // Format response
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
          isError: !result.success,
        };
      } catch (error) {
        logger.error('Tool execution failed', {
          tool: name,
          error: error instanceof Error ? error.message : 'Unknown error',
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error',
                mode: modeManager.getCurrentMode(),
                timestamp: new Date(),
              }, null, 2),
            },
          ],
          isError: true,
        };
      }
    });
  }

  /**
   * Setup error handling
   */
  private setupErrorHandling(): void {
    this.server.onerror = (error) => {
      logger.error('MCP Server error', { error });
    };

    // Handle process signals for cleanup
    process.on('SIGINT', () => this.shutdown());
    process.on('SIGTERM', () => this.shutdown());
  }

  /**
   * Convert Zod schema to JSON Schema (simplified)
   */
  private zodToJsonSchema(schema: any): Record<string, any> {
    try {
      return this.buildJsonSchema(schema);
    } catch {
      return {
        type: 'object',
        properties: {},
      };
    }
  }

  private buildJsonSchema(schema: any): Record<string, any> {
    const unwrappedSchema = this.unwrapZodType(schema);

    if (!unwrappedSchema?._def) {
      return {
        type: 'string',
      };
    }

    const typeName = unwrappedSchema._def.typeName;

    if (typeName === 'ZodObject') {
      const shape = unwrappedSchema._def.shape?.() || {};
      const properties: Record<string, any> = {};
      const required: string[] = [];

      for (const [key, value] of Object.entries(shape)) {
        const prop = value as any;
        const propertySchema = this.buildJsonSchema(prop);
        const description = this.getZodDescription(prop);
        const defaultValue = this.getZodDefaultValue(prop);
        const enumValues = this.getZodEnumValues(prop);

        if (description !== undefined) {
          propertySchema.description = description;
        }

        if (defaultValue !== undefined) {
          propertySchema.default = defaultValue;
        }

        if (enumValues !== undefined) {
          propertySchema.enum = enumValues;
        }

        properties[key] = propertySchema;

        if (!this.isOptionalZodType(prop)) {
          required.push(key);
        }
      }

      const objectSchema: Record<string, any> = {
        type: 'object',
        properties,
      };

      if (required.length > 0) {
        objectSchema.required = required;
      }

      return objectSchema;
    }

    if (typeName === 'ZodArray') {
      const itemSchema = unwrappedSchema._def.type ?? unwrappedSchema._def.item ?? unwrappedSchema._def.schema;

      return {
        type: 'array',
        items: itemSchema ? this.buildJsonSchema(itemSchema) : {},
      };
    }

    if (typeName === 'ZodRecord') {
      const valueSchema = unwrappedSchema._def.valueType;

      return {
        type: 'object',
        additionalProperties: valueSchema ? this.buildJsonSchema(valueSchema) : true,
      };
    }

    const propertySchema: Record<string, any> = {
      type: this.getZodType(unwrappedSchema),
    };
    const description = this.getZodDescription(schema);
    const defaultValue = this.getZodDefaultValue(schema);
    const enumValues = this.getZodEnumValues(schema);

    if (description !== undefined) {
      propertySchema.description = description;
    }

    if (defaultValue !== undefined) {
      propertySchema.default = defaultValue;
    }

    if (enumValues !== undefined) {
      propertySchema.enum = enumValues;
    }

    return propertySchema;
  }

  private unwrapZodType(schema: any): any {
    const typeName = schema?._def?.typeName;

    if (typeName === 'ZodOptional' || typeName === 'ZodDefault' || typeName === 'ZodNullable') {
      return this.unwrapZodType(schema._def?.innerType);
    }

    return schema;
  }

  private isOptionalZodType(schema: any): boolean {
    const typeName = schema?._def?.typeName;

    if (typeName === 'ZodOptional' || typeName === 'ZodDefault') {
      return true;
    }

    return false;
  }

  private getZodDescription(schema: any): string | undefined {
    if (!schema?._def) {
      return undefined;
    }

    return schema._def.description || schema.description || this.getZodDescription(schema._def.innerType);
  }

  private getZodDefaultValue(schema: any): unknown {
    if (!schema?._def) {
      return undefined;
    }

    if (schema._def.defaultValue !== undefined) {
      return typeof schema._def.defaultValue === 'function'
        ? schema._def.defaultValue()
        : schema._def.defaultValue;
    }

    return this.getZodDefaultValue(schema._def.innerType);
  }

  private getZodEnumValues(schema: any): unknown[] | undefined {
    if (!schema?._def) {
      return undefined;
    }

    if (schema._def.values !== undefined) {
      return schema._def.values;
    }

    return this.getZodEnumValues(schema._def.innerType);
  }

  /**
   * Get JSON Schema type from Zod type
   */
  private getZodType(zodType: any): string {
    const typeName = zodType._def?.typeName;

    switch (typeName) {
      case 'ZodString':
        return 'string';
      case 'ZodNumber':
        return 'number';
      case 'ZodBoolean':
        return 'boolean';
      case 'ZodArray':
        return 'array';
      case 'ZodObject':
      case 'ZodRecord':
        return 'object';
      case 'ZodEnum':
        return 'string';
      case 'ZodOptional':
      case 'ZodDefault':
      case 'ZodNullable':
        return this.getZodType(zodType._def?.innerType);
      default:
        return 'string';
    }
  }

  /**
   * Graceful shutdown
   */
  private async shutdown(): Promise<void> {
    logger.info('Shutting down MCP server...');

    // Cleanup resources
    sshKeyManager.revokeAllKeys();
    approvalManager.clearAllApprovals();
    modeManager.endSession();

    auditLogger.logSessionEvent('ENDED', { reason: 'shutdown' });

    logger.info('MCP server shutdown complete');
    process.exit(0);
  }

  /**
   * Start the server
   */
  async start(): Promise<void> {
    // Initialize session
    modeManager.initializeSession();

    // Create transport
    const transport = new StdioServerTransport();

    // Connect server to transport
    await this.server.connect(transport);

    if (!process.env.DEVOPS_MCP_ELEVATION_TOKEN) {
      logger.warn(
        'DEVOPS_MCP_ELEVATION_TOKEN is not set. set_mode / approve_action ' +
        'will accept the AI\'s own boolean as consent. Set this env var in ' +
        'your MCP client config to require a user-held token.'
      );
    }

    logger.info('DevOps MCP Server started', {
      name: SERVER_NAME,
      version: SERVER_VERSION,
      mode: modeManager.getCurrentMode(),
      consentTokenConfigured: !!process.env.DEVOPS_MCP_ELEVATION_TOKEN,
    });

    auditLogger.logSessionEvent('STARTED', {
      serverName: SERVER_NAME,
      serverVersion: SERVER_VERSION,
    });
  }
}

/**
 * Global crash handlers — without these, an uncaught error (e.g. a stray
 * 'error' event on an SSH/Docker socket after the remote drops) kills the
 * process with NOTHING written to error.log, surfacing only as Claude's
 * "Server disconnected / process exiting early". Capture the full stack so
 * the next crash is diagnosable. Winston's File transport flushes async, so
 * we delay the exit briefly to let the record reach disk before dying.
 */
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception — server will exit', {
    error: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
  });
  setTimeout(() => process.exit(1), 250);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled promise rejection', {
    error: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
  });
});

/**
 * Main entry point
 */
async function main(): Promise<void> {
  try {
    const server = new DevOpsMCPServer();
    await server.start();
  } catch (error) {
    logger.error('Failed to start MCP server', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    process.exit(1);
  }
}

// Run
main();

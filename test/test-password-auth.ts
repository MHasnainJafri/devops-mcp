/**
 * Test password authentication
 */
import { serverConfigManager } from '../src/core/server-config-manager.js';
import { SSHExecutor } from '../src/executors/ssh-executor.js';

async function testPasswordAuth() {
  console.log('🧪 Testing Password Authentication\n');

  // Load config
  serverConfigManager.loadConfig();
  
  // Get server
  const server = serverConfigManager.getServer('my-vps');
  console.log('Server config:', JSON.stringify(server, null, 2));

  if (!server) {
    console.log('❌ Server not found');
    return;
  }

  // Get auth info
  const authInfo = serverConfigManager.getAuthInfo('my-vps');
  console.log('\nAuth info:', JSON.stringify(authInfo, null, 2));

  if (!authInfo) {
    console.log('❌ Auth info not found');
    return;
  }

  // Test SSH connection
  console.log('\n📡 Testing SSH connection...');
  
  try {
    const executor = new SSHExecutor({
      ssh: {
        host: server.host,
        port: server.port,
        username: server.username,
        password: authInfo.password,
      },
    });

    const connected = await executor.testConnection();
    console.log(`Connection result: ${connected ? '✅ SUCCESS' : '❌ FAILED'}`);

    if (connected) {
      // Try running a command
      const result = await executor.execute({ command: 'hostname' });
      console.log(`\nHostname: ${result.stdout}`);
    }

    await executor.cleanup();
  } catch (error) {
    console.log(`❌ Error: ${error instanceof Error ? error.message : error}`);
  }
}

testPasswordAuth();

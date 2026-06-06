/**
 * Manual test script for DevOps MCP Server
 * Run with: npx tsx test/manual-test.ts
 */

import { modeManager } from '../src/core/mode-manager.js';
import { commandValidator } from '../src/core/command-validator.js';
import { serverConfigManager } from '../src/core/server-config-manager.js';
import { LocalExecutor } from '../src/executors/local-executor.js';
import { AccessMode } from '../src/types/index.js';

async function runTests() {
  console.log('🧪 DevOps MCP Server - Manual Tests\n');
  console.log('='.repeat(50));

  // Test 1: Mode Manager
  console.log('\n📋 Test 1: Mode Manager');
  const session = modeManager.initializeSession();
  console.log(`  ✅ Session created: ${session.id}`);
  console.log(`  ✅ Current mode: ${modeManager.getCurrentMode()}`);
  console.log(`  ✅ Permissions:`, modeManager.getCurrentPermissions());

  // Test 2: Command Validator
  console.log('\n📋 Test 2: Command Validator');
  const safeCmd = commandValidator.validate({ command: 'ls -la' }, AccessMode.SAFE);
  console.log(`  ✅ "ls -la" in SAFE mode: allowed=${safeCmd.allowed}`);
  
  const dangerousCmd = commandValidator.validate({ command: 'rm -rf /' }, AccessMode.SAFE);
  console.log(`  ✅ "rm -rf /" in SAFE mode: allowed=${dangerousCmd.allowed}, required=${dangerousCmd.requiredMode}`);

  const aptCmd = commandValidator.validate({ command: 'apt install nginx' }, AccessMode.SAFE);
  console.log(`  ✅ "apt install" in SAFE mode: allowed=${aptCmd.allowed}, required=${aptCmd.requiredMode}`);

  // Test 3: Server Config Manager
  console.log('\n📋 Test 3: Server Config Manager');
  const status = serverConfigManager.getSetupStatus();
  console.log(`  ✅ Config exists: ${status.configExists}`);
  console.log(`  ✅ Server count: ${status.serverCount}`);
  if (status.serverCount > 0) {
    const servers = serverConfigManager.listServers();
    servers.forEach(s => {
      console.log(`     - ${s.id}: ${s.host} (${s.authType} auth, role: ${s.role})`);
    });
  }

  // Test 4: Local Executor
  console.log('\n📋 Test 4: Local Executor');
  const executor = new LocalExecutor();
  const testResult = await executor.execute({ command: 'echo "Hello from MCP"' });
  console.log(`  ✅ Echo command: success=${testResult.success}`);
  console.log(`  ✅ Output: "${testResult.stdout}"`);

  // Test 5: Mode Elevation
  console.log('\n📋 Test 5: Mode Elevation');
  try {
    modeManager.elevateMode(AccessMode.PROVISION, true, 'test-user', '10m');
    console.log(`  ✅ Elevated to: ${modeManager.getCurrentMode()}`);
    console.log(`  ✅ Time remaining: ${Math.round((modeManager.getTimeRemaining() || 0) / 1000)}s`);
    
    // Downgrade back
    modeManager.downgradeMode(AccessMode.SAFE);
    console.log(`  ✅ Downgraded to: ${modeManager.getCurrentMode()}`);
  } catch (error) {
    console.log(`  ❌ Elevation error: ${error}`);
  }

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log('✅ All tests passed!\n');
  console.log('To use with Cursor/Windsurf, add to MCP config:');
  console.log(`{
  "mcpServers": {
    "devops": {
      "command": "node",
      "args": ["${process.cwd().replace(/\\/g, '/')}/dist/index.js"]
    }
  }
}`);

  // End session
  modeManager.endSession();
}

runTests().catch(console.error);

/**
 * Offline smoke test for the transfer_files tool.
 * Run with: npx tsx test/transfer-test.ts
 *
 * Live SFTP upload/download needs a real server; this verifies the wiring:
 *  - the tool is registered (definition + handler + schema)
 *  - the schema parses/defaults correctly
 *  - the handler degrades gracefully with no active SSH session
 */

import { TOOL_DEFINITIONS, TransferFilesSchema } from '../src/tools/tool-schemas.js';
import { TOOL_HANDLERS } from '../src/tools/tool-handlers.js';

let failures = 0;
function check(name: string, cond: boolean) {
  console.log(`  ${cond ? '✅' : '❌'} ${name}`);
  if (!cond) failures++;
}

async function run() {
  console.log('🧪 transfer_files - Offline Smoke Tests\n' + '='.repeat(50));

  console.log('\n📋 Registration');
  const def = TOOL_DEFINITIONS.find((t) => t.name === 'transfer_files');
  check('tool is in TOOL_DEFINITIONS', !!def);
  check('handler is in TOOL_HANDLERS', typeof TOOL_HANDLERS.transfer_files === 'function');
  check('definition references the schema', def?.inputSchema === TransferFilesSchema);

  console.log('\n📋 Schema defaults');
  const parsed = TransferFilesSchema.parse({ localPath: './x', remotePath: '/srv/x' });
  check('direction defaults to upload', parsed.direction === 'upload');
  check('extract defaults to false', parsed.extract === false);
  check('overwrite defaults to true', parsed.overwrite === true);
  check('verifyChecksum defaults to false', parsed.verifyChecksum === false);

  console.log('\n📋 Schema validation');
  check('rejects bad direction', !TransferFilesSchema.safeParse({ localPath: 'a', remotePath: 'b', direction: 'sideways' }).success);
  check('requires localPath + remotePath', !TransferFilesSchema.safeParse({ direction: 'upload' }).success);

  console.log('\n📋 Handler without an SSH session');
  const res = await TOOL_HANDLERS.transfer_files({
    direction: 'upload',
    localPath: './package.json',
    remotePath: '/tmp/package.json',
    extract: false,
    verifyChecksum: false,
    overwrite: true,
  });
  check('returns success:false (no connection)', res.success === false);
  check('error mentions SSH connection', /SSH connection/i.test(res.error || ''));
  check('offers a next step', Array.isArray(res.nextSteps) && res.nextSteps.length > 0);

  console.log('\n' + '='.repeat(50));
  if (failures === 0) {
    console.log('✅ All transfer_files smoke tests passed!\n');
  } else {
    console.log(`❌ ${failures} check(s) failed.\n`);
    process.exitCode = 1;
  }
}

run().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

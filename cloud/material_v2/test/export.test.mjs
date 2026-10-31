import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  chmod, cp, mkdtemp, mkdir, open, readFile, readdir, rename, rm, stat, symlink, writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

import {
  aggregate, encodeRegistrationCanonical, frame, MATERIAL_CODEC_PROFILE,
} from '../../../tools/cloud-material/export.mjs';

const repo = path.resolve(import.meta.dirname, '../../..');
const project = process.env.XOLLVM_PROJECT_ROOT || '/data/user/0/com.termux/files/home/xollvm-android';
const cppTest = process.env.XOVM_MATERIAL_TEST || path.join(project, 'build-sensitive/tools/Obfuscator/VMRequirementsTests');
const builtFsHelper = process.env.XOVM_MATERIAL_FS_HELPER ||
  path.join(project, 'build-sensitive/bin/xollvm-cloud-material-fs-helper');
const cli = path.join(repo, 'tools/cloud-material/export.mjs');
const helperRoot = await mkdtemp(path.join(os.tmpdir(), 'xovm-trusted-helper-'));
await chmod(helperRoot, 0o700);
const fsHelper = path.join(helperRoot, 'xollvm-cloud-material-fs-helper');
await cp(builtFsHelper, fsHelper);
await chmod(fsHelper, 0o700);
process.env.XOVM_MATERIAL_FS_HELPER = fsHelper;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {encoding: 'utf8', ...options});
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return result;
}

async function genuineInput() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'xovm-export-test-'));
  const input = path.join(root, 'private');
  await mkdir(input, {mode: 0o700});
  run(cppTest, ['--gtest_filter=VMMaterial.ExportFixtureForAggregator'],
      {env: {...process.env, XOVM_TEST_EXPORT_ROOT: input}});
  return {root, input};
}

async function regionFile(input, wanted = 'auth/payment') {
  for (const bundleName of await readdir(input)) {
    const bundle = path.join(input, bundleName);
    if (!(await stat(bundle)).isDirectory()) continue;
    for (const name of await readdir(bundle)) {
      if (!name.endsWith('.region.json')) continue;
      const filename = path.join(bundle, name);
      const region = JSON.parse(await readFile(filename, 'ascii'));
      if (region.region_name === wanted) return {bundle, filename, name, region};
    }
  }
  assert.fail(`missing region ${wanted}`);
}

function rehashRegion(region) {
  const core = {...region};
  delete core.region_content_hash;
  delete core.region_id;
  region.region_content_hash = createHash('sha256').update(frame(
      'XOVM2/region-content', encodeRegistrationCanonical(
          core, MATERIAL_CODEC_PROFILE.canonicalRegion))).digest('hex');
  const identity = {
    format_version: 1,
    region_name: region.region_name,
    region_content_hash: region.region_content_hash,
    engine_abi_hash: region.engine_abi_hash,
    call_abi_hash: region.call_abi_hash,
    layout_hash: region.layout_hash,
    mode: region.mode,
    target_triple: region.target_triple,
  };
  region.region_id = createHash('sha256').update(frame(
      'XOVM2/region-id', encodeRegistrationCanonical(
          identity, MATERIAL_CODEC_PROFILE.canonicalRegion))).digest('hex');
}

async function replaceRegionFile(entry) {
  const priorId = entry.region.region_id;
  rehashRegion(entry.region);
  const bytes = encodeRegistrationCanonical(
      entry.region, MATERIAL_CODEC_PROFILE.canonicalRegion);
  const nameHash = createHash('sha256').update(entry.region.region_name, 'ascii').digest('hex');
  const replacement = path.join(entry.bundle,
      `${nameHash}.${entry.region.region_id}.${entry.region.region_content_hash}.region.json`);
  await writeFile(entry.filename, bytes);
  if (replacement !== entry.filename) await rename(entry.filename, replacement);
  const priorDescriptor = path.join(entry.bundle, `${priorId}.verifier`);
  const nextDescriptor = path.join(entry.bundle, `${entry.region.region_id}.verifier`);
  if (priorDescriptor !== nextDescriptor) await rename(priorDescriptor, nextDescriptor);
  entry.filename = replacement;
}

test('aggregates genuine compiler exports with exact identities and permissions', async () => {
  const {root, input} = await genuineInput();
  const output = path.join(root, 'release');
  const result = run(process.execPath, [cli, '--input-dir', input, '--output-dir', output]);
  assert.equal(result.stdout, '');
  const publicBytes = await readFile(path.join(output, 'public-manifest.json'));
  const privateBytes = await readFile(path.join(output, 'registration.private.json'));
  const manifest = JSON.parse(publicBytes);
  const registration = JSON.parse(privateBytes);
  assert.equal(manifest.software_id, 'test.app');
  assert.equal(manifest.regions.length, 2);
  assert.deepEqual(manifest.regions.map(region => region.region_id),
                   [...manifest.regions.map(region => region.region_id)].sort());
  assert.deepEqual(registration.regions.map(r => r.region_id),
                   manifest.regions.map(r => r.region_id));
  assert.equal(registration.build_id, manifest.build_id);
  for (const forbidden of ['canonical_bc', 'instruction_offsets', 'logical_opcodes',
                            'static_decode_descriptor', 'register_counts']) {
    assert.equal(Object.hasOwn(manifest.regions[0], forbidden), false);
  }
  const core = {...manifest};
  delete core.build_id;
  const expected = createHash('sha256').update(
      frame('XOVM2/build-id', encodeRegistrationCanonical(
          core, MATERIAL_CODEC_PROFILE.publicManifest))).digest('hex');
  assert.equal(manifest.build_id, expected);
  assert.deepEqual(publicBytes, encodeRegistrationCanonical(
      manifest, MATERIAL_CODEC_PROFILE.publicManifest));
  assert.deepEqual(privateBytes, Buffer.from(JSON.stringify(registration), 'ascii'));
  assert.equal((await stat(output)).mode & 0o777, 0o700);
  assert.equal((await stat(path.join(output, 'public-manifest.json'))).mode & 0o777, 0o600);
  assert.equal((await stat(path.join(output, 'registration.private.json'))).mode & 0o777, 0o600);
});

test('is deterministic and requires new absolute non-symlink output', async () => {
  const {root, input} = await genuineInput();
  const first = path.join(root, 'first');
  const second = path.join(root, 'second');
  run(process.execPath, [cli, '--input-dir', input, '--output-dir', first]);
  run(process.execPath, [cli, '--input-dir', input, '--output-dir', second]);
  assert.deepEqual(await readFile(path.join(first, 'public-manifest.json')),
                   await readFile(path.join(second, 'public-manifest.json')));
  assert.deepEqual(await readFile(path.join(first, 'registration.private.json')),
                   await readFile(path.join(second, 'registration.private.json')));

  const existing = path.join(root, 'existing');
  await mkdir(existing);
  let failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', existing], {encoding: 'utf8'});
  assert.notEqual(failed.status, 0);
  assert.doesNotMatch(failed.stderr, /canonical_bc|decode_salt/);

  const linked = path.join(root, 'linked');
  await symlink(input, linked);
  failed = spawnSync(process.execPath,
      [cli, '--input-dir', linked, '--output-dir', path.join(root, 'bad')], {encoding: 'utf8'});
  assert.notEqual(failed.status, 0);
});

test('rejects malformed and oversized private inputs without partial output', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'xovm-export-bad-'));
  const input = path.join(root, 'private');
  const bundle = path.join(input, `${'0'.repeat(64)}.materials`);
  await mkdir(bundle, {recursive: true, mode: 0o700});
  const secret = 'SECRET_BYTECODE_MUST_NOT_BE_LOGGED';
  await import('node:fs/promises').then(fs => fs.writeFile(
      path.join(bundle, `${'1'.repeat(64)}.${'2'.repeat(64)}.region.json`),
      `{"canonical_bc":"${secret}"}`, {mode: 0o600}));
  await import('node:fs/promises').then(fs => fs.writeFile(
      path.join(bundle, 'software-id'), 'test.app', {mode: 0o600}));
  const output = path.join(root, 'output');
  let failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', output], {encoding: 'utf8'});
  assert.notEqual(failed.status, 0);
  assert.doesNotMatch(failed.stderr, new RegExp(secret));
  await assert.rejects(stat(output));
});

test('rejects non-private input modes', async () => {
  const {root, input} = await genuineInput();
  let bundle;
  for (const name of await readdir(input)) {
    const candidate = path.join(input, name);
    if ((await stat(candidate)).isDirectory()) { bundle = candidate; break; }
  }
  assert.ok(bundle);
  const region = (await readdir(bundle)).find(name => name.endsWith('.region.json'));
  await chmod(path.join(bundle, region), 0o644);
  const output = path.join(root, 'output');
  let failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', output], {encoding: 'utf8'});
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /private_mode/);
  await assert.rejects(stat(output));

  await chmod(path.join(bundle, region), 0o400);
  failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', output], {encoding: 'utf8'});
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /private_mode/);
  await assert.rejects(stat(output));
});

test('enforces 192 MiB region and 512 MiB registration limits before reading', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'xovm-export-size-'));
  const input = path.join(root, 'private');
  const bundle = path.join(input, `${'0'.repeat(64)}.materials`);
  await mkdir(bundle, {recursive: true, mode: 0o700});
  const names = [0, 1, 2].map(index =>
    `${String(index).repeat(64)}.${'1'.repeat(64)}.${'2'.repeat(64)}.region.json`);
  for (const name of names) {
    const handle = await open(path.join(bundle, name), 'wx', 0o600);
    await handle.truncate(180 * 1024 * 1024);
    await handle.close();
  }
  await import('node:fs/promises').then(fs => fs.writeFile(
      path.join(bundle, 'software-id'), 'test.app', {mode: 0o600}));
  let failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', path.join(root, 'too-large')], {encoding: 'utf8'});
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /registration_size_limit/);

  await import('node:fs/promises').then(fs => fs.rm(path.join(bundle, names[2])));
  const handle = await open(path.join(bundle, names[0]), 'r+');
  await handle.truncate(193 * 1024 * 1024);
  await handle.close();
  failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', path.join(root, 'region-too-large')], {encoding: 'utf8'});
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /region_size_limit/);
});

test('failure before promotion cleans staging and publishes no output', async () => {
  const {root, input} = await genuineInput();
  const output = path.join(root, 'release');
  await assert.rejects(
      aggregate(['--input-dir', input, '--output-dir', output], {fault: 'before_rename'}),
      /test_before_rename/);
  await assert.rejects(stat(output));
  assert.equal((await readdir(root)).some(name => name.startsWith('.xovm-export-')), false);
});

test('atomic promotion never replaces an output created by a racing writer', async () => {
  const {root, input} = await genuineInput();
  const output = path.join(root, 'release');
  const sentinel = path.join(output, 'racer-owned');
  await assert.rejects(aggregate(
      ['--input-dir', input, '--output-dir', output],
      {beforePromote: async () => {
        await mkdir(output, {mode: 0o700});
        await writeFile(sentinel, 'untouched', {mode: 0o600});
      }}), /output_exists/);
  assert.equal(await readFile(sentinel, 'ascii'), 'untouched');
  assert.deepEqual(await readdir(output), ['racer-owned']);
  assert.equal((await readdir(root)).some(name => name.startsWith('.xovm-export-')), false);
});

test('same-UID lock replacement fails closed before publication', async () => {
  const {root, input} = await genuineInput();
  const output = path.join(root, 'release');
  await assert.rejects(aggregate(
      ['--input-dir', input, '--output-dir', output],
      {afterLock: async lockPaths => {
        for (const lockPath of lockPaths) {
          await rm(lockPath);
          await writeFile(lockPath, 'replacement', {mode: 0o600});
        }
      }}), /lock_replaced/);
  await assert.rejects(stat(output));
});

test('parent sync failure reports committed durability unknown without rollback', async () => {
  const {root, input} = await genuineInput();
  const output = path.join(root, 'release');
  const result = await aggregate(
      ['--input-dir', input, '--output-dir', output], {fault: 'after_commit'});
  assert.deepEqual(result, {committed: true, durability: 'unknown'});
  assert.equal((await stat(output)).isDirectory(), true);
  assert.deepEqual((await readdir(output)).sort(),
                   ['public-manifest.json', 'registration.private.json']);
  assert.equal((await readdir(root)).some(name => name.startsWith('.xovm-export-')), false);
  assert.deepEqual(await aggregate(['--input-dir', input, '--output-dir', output]),
                   {committed: true, durability: 'durable'});
});

test('helper exit after rename is reconciled as committed', async () => {
  const {root, input} = await genuineInput();
  const output = path.join(root, 'release');
  const probes = [];
  const result = await aggregate(
      ['--input-dir', input, '--output-dir', output], {
        fault: 'exit_after_commit', probe: event => probes.push(event),
      });
  assert.deepEqual(result, {committed: true, durability: 'durable'});
  assert.equal(probes.filter(event => event.kind === 'commit_reconciled').length, 1);
  assert.deepEqual((await readdir(output)).sort(),
                   ['public-manifest.json', 'registration.private.json']);
});

test('destination swap during ambiguous reconciliation is not accepted', async () => {
  const {root, input} = await genuineInput();
  const output = path.join(root, 'release');
  await assert.rejects(aggregate(
      ['--input-dir', input, '--output-dir', output], {
        fault: 'swap_during_reconcile',
      }), /commit_outcome_unknown/);
});

test('member content replacement during ambiguous reconciliation is not accepted', async () => {
  const {root, input} = await genuineInput();
  await assert.rejects(aggregate(
      ['--input-dir', input, '--output-dir', path.join(root, 'release')], {
        fault: 'member_content_during_reconcile',
      }), /commit_outcome_unknown/);
});

test('member pathname swap during ambiguous reconciliation is not accepted', async () => {
  const {root, input} = await genuineInput();
  await assert.rejects(aggregate(
      ['--input-dir', input, '--output-dir', path.join(root, 'release')], {
        fault: 'member_swap_during_reconcile',
      }), /commit_outcome_unknown/);
});

test('helper close failure after commit returns committed unknown', async () => {
  const {root, input} = await genuineInput();
  const output = path.join(root, 'release');
  const result = await aggregate(
      ['--input-dir', input, '--output-dir', output], {fault: 'close_after_commit'});
  assert.deepEqual(result, {committed: true, durability: 'unknown'});
  assert.equal((await stat(output)).isDirectory(), true);
});

test('helper discovery supports sibling installed layout and trusted PATH', async t => {
  for (const source of ['sibling', 'path']) await t.test(source, async () => {
    const {root, input} = await genuineInput();
    const bin = path.join(root, `${source}-bin`);
    await mkdir(bin, {mode: 0o700});
    const helper = path.join(bin, 'xollvm-cloud-material-fs-helper');
    await cp(fsHelper, helper);
    await chmod(helper, 0o700);
    const script = source === 'sibling' ? path.join(bin, 'xollvm-cloud-material-export') : cli;
    if (source === 'sibling') {
      await cp(cli, script);
      await chmod(script, 0o700);
    }
    const env = {...process.env, PATH: source === 'path' ? bin : ''};
    delete env.XOVM_MATERIAL_FS_HELPER;
    env.XOLLVM_PROJECT_ROOT = path.join(root, 'must-not-be-used');
    const output = path.join(root, `${source}-release`);
    const result = spawnSync(process.execPath,
        [script, '--input-dir', input, '--output-dir', output], {encoding: 'utf8', env});
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal((await stat(output)).isDirectory(), true);
  });
});

test('helper discovery rejects attacker-writable override and reports fixed absence', async () => {
  const {root, input} = await genuineInput();
  const writable = path.join(root, 'writable-helper');
  await cp(fsHelper, writable);
  await chmod(writable, 0o777);
  let failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', path.join(root, 'writable-output')], {
        encoding: 'utf8',
        env: {...process.env, XOVM_MATERIAL_FS_HELPER: writable},
      });
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /helper_untrusted/);
  assert.doesNotMatch(failed.stderr, /canonical_bc|decode_salt/);

  const env = {...process.env, PATH: '', XOLLVM_PROJECT_ROOT: path.join(root, 'unused')};
  delete env.XOVM_MATERIAL_FS_HELPER;
  failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', path.join(root, 'missing-output')], {
        encoding: 'utf8', env,
      });
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /helper_not_found/);
});

test('helper execution remains bound to opened inode after pathname replacement', async () => {
  const {root, input} = await genuineInput();
  const bin = path.join(root, 'race-bin');
  await mkdir(bin, {mode: 0o700});
  const helper = path.join(bin, 'xollvm-cloud-material-fs-helper');
  await cp(fsHelper, helper);
  await chmod(helper, 0o700);
  const prior = process.env.XOVM_MATERIAL_FS_HELPER;
  process.env.XOVM_MATERIAL_FS_HELPER = helper;
  let opened = false;
  try {
    const result = await aggregate(
        ['--input-dir', input, '--output-dir', path.join(root, 'release')], {
          afterHelperOpen: async candidate => {
            opened = true;
            await rename(candidate, `${candidate}.trusted`);
            await writeFile(candidate, '#!/system/bin/sh\nexit 97\n', {mode: 0o700});
          },
        });
    assert.deepEqual(result, {committed: true, durability: 'durable'});
    assert.equal(opened, true);
  } finally {
    process.env.XOVM_MATERIAL_FS_HELPER = prior;
  }
});

test('helper discovery rejects writable PATH parent and symlink candidate', async () => {
  const {root, input} = await genuineInput();
  const writable = path.join(root, 'writable-path');
  await mkdir(writable, {mode: 0o777});
  await chmod(writable, 0o777);
  const helper = path.join(writable, 'xollvm-cloud-material-fs-helper');
  await cp(fsHelper, helper);
  await chmod(helper, 0o700);
  let env = {...process.env, PATH: writable};
  delete env.XOVM_MATERIAL_FS_HELPER;
  let failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', path.join(root, 'path-output')], {
        encoding: 'utf8', env,
      });
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /helper_untrusted/);

  const linked = path.join(root, 'linked-helper');
  await symlink(fsHelper, linked);
  env = {...process.env, XOVM_MATERIAL_FS_HELPER: linked};
  failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', path.join(root, 'link-output')], {
        encoding: 'utf8', env,
      });
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /helper_untrusted/);
});

test('CLI help documents helper resolution order', () => {
  const result = spawnSync(process.execPath, [cli, '--help'], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /XOVM_MATERIAL_FS_HELPER/);
  assert.match(result.stdout, /sibling/);
  assert.match(result.stdout, /PATH/);
});

test('independent verifier rejects sparse records malformed variable tails and tail branches', async t => {
  const cases = [
    ['missing offset zero', entry => {
      entry.region.instruction_offsets.shift();
      entry.region.logical_opcodes.shift();
    }],
    ['missing middle record', entry => {
      const middle = Math.floor(entry.region.instruction_offsets.length / 2);
      entry.region.instruction_offsets.splice(middle, 1);
      entry.region.logical_opcodes.splice(middle, 1);
    }],
    ['record in operand tail', entry => {
      entry.region.instruction_offsets[1] = entry.region.instruction_offsets[0] + 1;
    }],
    ['truncated CALL tail', entry => {
      const index = entry.region.logical_opcodes.indexOf(0x10);
      assert.notEqual(index, -1);
      const bytecode = Buffer.from(entry.region.canonical_bc, 'base64');
      bytecode[entry.region.instruction_offsets[index] + 3] = 0x7f;
      entry.region.canonical_bc = bytecode.toString('base64');
    }],
    ['truncated SWITCH tail', entry => {
      const index = entry.region.logical_opcodes.indexOf(0x18);
      assert.notEqual(index, -1);
      const bytecode = Buffer.from(entry.region.canonical_bc, 'base64');
      const offset = entry.region.instruction_offsets[index];
      bytecode[offset + 2] = 0xff;
      bytecode[offset + 3] = 0xff;
      entry.region.canonical_bc = bytecode.toString('base64');
    }],
    ['branch into operand tail', entry => {
      const index = entry.region.logical_opcodes.indexOf(0x18);
      assert.notEqual(index, -1);
      const bytecode = Buffer.from(entry.region.canonical_bc, 'base64');
      const offset = entry.region.instruction_offsets[index];
      bytecode.writeUInt32LE(offset + 1, offset + 4);
      entry.region.canonical_bc = bytecode.toString('base64');
    }],
  ];
  for (const [name, mutate] of cases) await t.test(name, async () => {
    const {root, input} = await genuineInput();
    const entry = await regionFile(input);
    mutate(entry);
    await replaceRegionFile(entry);
    const output = path.join(root, 'release');
    const failed = spawnSync(process.execPath,
        [cli, '--input-dir', input, '--output-dir', output], {encoding: 'utf8'});
    assert.notEqual(failed.status, 0);
    assert.match(failed.stderr, /invalid_bytecode/);
    await assert.rejects(stat(output));
  });
});

test('registration path spools regions and writes bounded chunks', async () => {
  const {root, input} = await genuineInput();
  const output = path.join(root, 'release');
  const probes = [];
  await aggregate(['--input-dir', input, '--output-dir', output], {
    probe: event => probes.push(event),
  });
  assert.equal(probes.filter(event => event.kind === 'region_spooled').length, 2);
  assert.ok(probes.some(event => event.kind === 'registration_chunk'));
  assert.ok(Math.max(...probes.filter(event => event.kind === 'registration_chunk')
      .map(event => event.bytes)) <= 64 * 1024);
  assert.ok(probes.filter(event => event.kind === 'verification_workspace')
      .every(event => event.boundaryBytes <= Math.ceil(event.bytecodeBytes / 8)));
  assert.equal(probes.some(event => event.kind === 'region_dom'), false);
});

test('representative large registration stays allocation-bounded', async () => {
  const {root, input} = await genuineInput();
  const original = await regionFile(input);
  const descriptor = await readFile(path.join(original.bundle,
      `${original.region.region_id}.verifier`));
  for (let index = 0; index < 126; ++index) {
    const region = structuredClone(original.region);
    region.region_name = `bulk/${String(index).padStart(3, '0')}`;
    rehashRegion(region);
    const bytes = encodeRegistrationCanonical(region, MATERIAL_CODEC_PROFILE.canonicalRegion);
    const nameHash = createHash('sha256').update(region.region_name, 'ascii').digest('hex');
    await writeFile(path.join(original.bundle,
        `${nameHash}.${region.region_id}.${region.region_content_hash}.region.json`),
        bytes, {mode: 0o600});
    await writeFile(path.join(original.bundle, `${region.region_id}.verifier`),
        descriptor, {mode: 0o600});
  }
  const probes = [];
  const output = path.join(root, 'bulk-release');
  await aggregate(['--input-dir', input, '--output-dir', output], {
    probe: event => probes.push(event),
  });
  assert.equal(probes.filter(event => event.kind === 'region_spooled').length, 128);
  assert.ok(probes.filter(event => event.kind === 'verification_workspace')
      .every(event => event.boundaryBytes <= Math.ceil(event.bytecodeBytes / 8)));
  assert.ok(Math.max(...probes.filter(event => event.kind === 'registration_chunk')
      .map(event => event.bytes)) <= 64 * 1024);
  assert.equal(JSON.parse(await readFile(path.join(output, 'public-manifest.json')))
      .regions.length, 128);
});

test('same-name conflict diagnostic contains only sanitized public identities', async () => {
  const {root, input} = await genuineInput();
  const first = await regionFile(input, 'auth/payment');
  const second = await regionFile(input, 'zeta');
  second.region.region_name = first.region.region_name;
  await replaceRegionFile(second);
  const output = path.join(root, 'conflict-output');
  const failed = spawnSync(process.execPath,
      [cli, '--input-dir', input, '--output-dir', output], {
        encoding: 'utf8',
        env: {...process.env, XOVM_MATERIAL_FS_HELPER:
          process.env.XOVM_MATERIAL_FS_HELPER ||
            path.join(project, 'build-sensitive/bin/xollvm-cloud-material-fs-helper')},
      });
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, new RegExp(`name=${first.region.region_name}`));
  for (const value of [first.region.region_id, first.region.region_content_hash,
                       second.region.region_id, second.region.region_content_hash])
    assert.match(failed.stderr, new RegExp(value));
  assert.doesNotMatch(failed.stderr, /canonical_bc|decode_salt|XOVMVR1/);
});

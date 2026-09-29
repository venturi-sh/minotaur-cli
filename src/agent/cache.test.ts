import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { isReusable } from './cache.js';
import { Workspace } from './workspace.js';

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'minotaur-cache-'));
  await writeFile(join(root, 'app.py'), 'import yaml\nyaml.safe_load(data)\n');
});
afterEach(() => rm(root, { recursive: true, force: true }));

async function assessedInputs() {
  const ws = await Workspace.open(root);
  await ws.readFile('app.py');
  return ws.inputs();
}

const current = { promptVersion: 'triage-v1', modelId: 'anthropic:m' };

describe('isReusable', () => {
  it('reuses a succeeded assessment from the same prompt and model while its inputs hold', async () => {
    const previous = { status: 'succeeded', promptVersion: 'triage-v1', model: 'anthropic:m', inputs: await assessedInputs() };
    expect(await isReusable(previous, current, await Workspace.open(root))).toBe(true);
  });

  it('re-triages when a file the agent read has changed', async () => {
    const previous = { status: 'succeeded', promptVersion: 'triage-v1', model: 'anthropic:m', inputs: await assessedInputs() };
    await writeFile(join(root, 'app.py'), 'import yaml\nyaml.load(data)\n');
    expect(await isReusable(previous, current, await Workspace.open(root))).toBe(false);
  });

  it('re-triages under a new prompt version or model, or after a failure', async () => {
    const inputs = await assessedInputs();
    const ws = await Workspace.open(root);
    expect(await isReusable({ status: 'succeeded', promptVersion: 'triage-v0', model: 'anthropic:m', inputs }, current, ws)).toBe(false);
    expect(await isReusable({ status: 'succeeded', promptVersion: 'triage-v1', model: 'anthropic:other', inputs }, current, ws)).toBe(false);
    expect(await isReusable({ status: 'failed', promptVersion: 'triage-v1', model: 'anthropic:m', inputs }, current, ws)).toBe(false);
    expect(await isReusable(undefined, current, ws)).toBe(false);
  });
});

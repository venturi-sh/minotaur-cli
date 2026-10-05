import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { CheckTools, permit, serveTools, sessionOptions, triageWithClaudeCode } from './acp.js';
import { FINAL_TURN } from './agent.js';
import type { TriageSubject } from './prompt.js';
import { triageTools } from './tools.js';
import { Workspace } from './workspace.js';

const subject: TriageSubject = {
  id: 'f1',
  fingerprint: 'fp1',
  kind: 'sast',
  severity: 'high',
  title: 'Command injection',
  description: null,
  ruleId: 'js.exec',
  vulnerabilityIds: [],
  location: { path: 'app.js', startLine: 1, endLine: 1 },
  packageRef: null,
  toolName: 'opengrep',
  epss: null,
  kev: false,
};

const verdict = { exploitability: 'not_exploitable', confidence: 0.5, rationale: 'no input reaches it' };
const noEvents = { onStep: () => undefined, onSubmit: () => undefined, onExhausted: () => undefined };

let dir: string;
let workspace: Workspace;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'minotaur-acp-'));
  await writeFile(join(dir, 'app.js'), "exec('ping ' + req.query.host);\n");
  await writeFile(join(dir, '.env'), 'TOKEN=secret\n');
  workspace = await Workspace.open(dir);
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('permit', () => {
  const options = [
    { optionId: 'yes', name: 'Allow', kind: 'allow_once' as const },
    { optionId: 'no', name: 'Reject', kind: 'reject_once' as const },
  ];
  const request = (toolName: string) => ({ sessionId: 's', options, toolCall: { toolCallId: 't', _meta: { claudeCode: { toolName } } } });

  it("allows Minotaur's tools and refuses Claude Code's own", () => {
    expect(permit(request('mcp__minotaur__read_file'))).toEqual({ outcome: { outcome: 'selected', optionId: 'yes' } });
    expect(permit(request('Bash'))).toEqual({ outcome: { outcome: 'selected', optionId: 'no' } });
    expect(permit(request('mcp__other__read_file'))).toEqual({ outcome: { outcome: 'selected', optionId: 'no' } });
  });
});

describe('sessionOptions', () => {
  it('gives Claude Code no tools of its own and none of the settings', () => {
    expect(sessionOptions({ modelId: 'claude-sonnet-5', effort: 'high' }, ['read_file', 'submit_verdict'])).toEqual({
      model: 'claude-sonnet-5',
      effort: 'high',
      tools: [],
      allowedTools: ['mcp__minotaur__read_file', 'mcp__minotaur__submit_verdict'],
      settingSources: [],
      strictMcpConfig: true,
      persistSession: false,
    });
  });
});

describe('CheckTools', () => {
  it('reads through the workspace, so secret files stay out', async () => {
    const tools = new CheckTools(triageTools(workspace, 'exploit'), 5, noEvents);
    const read = await tools.call('read_file', { path: 'app.js' });
    expect(JSON.stringify(read.content)).toContain('req.query.host');
    const secret = await tools.call('read_file', { path: '.env' });
    expect(JSON.stringify(secret.content)).not.toContain('TOKEN=secret');
    expect(workspace.inputs().map((input) => input.path)).toContain('app.js');
  });

  it('refuses reads after the step limit and asks for the answer instead', async () => {
    let exhausted = 0;
    const tools = new CheckTools(triageTools(workspace, 'exploit'), 1, { ...noEvents, onExhausted: () => (exhausted += 1) });
    await tools.call('list_dir', { path: '.' });
    const refused = await tools.call('read_file', { path: 'app.js' });
    expect(refused.isError).toBe(true);
    expect(JSON.stringify(refused.content)).toContain(JSON.stringify(FINAL_TURN).slice(1, 40));
    expect(tools.steps).toBe(1);
    await tools.call('read_file', { path: 'app.js' });
    await tools.call('read_file', { path: 'app.js' });
    expect(exhausted).toBe(1);
  });

  it('keeps the first valid answer and returns invalid input to the model', async () => {
    const tools = new CheckTools(triageTools(workspace, 'exploit'), 5, noEvents);
    expect((await tools.call('submit_verdict', { exploitability: 'maybe' })).isError).toBe(true);
    expect(tools.submitted).toBeUndefined();
    await tools.call('submit_verdict', verdict);
    await tools.call('submit_verdict', { ...verdict, rationale: 'changed my mind' });
    expect(tools.submitted).toMatchObject({ rationale: 'no input reaches it' });
  });

  it('describes each tool with a JSON schema', () => {
    const tools = new CheckTools(triageTools(workspace, 'exploit'), 5, noEvents);
    const listed = tools.list();
    expect(listed.map((tool) => tool.name)).toEqual(['read_file', 'grep', 'list_dir', 'submit_verdict']);
    expect(listed[0]!.inputSchema).toMatchObject({ type: 'object', required: ['path'] });
  });
});

describe('serveTools', () => {
  it('refuses requests without the token', async () => {
    const server = await serveTools(new CheckTools(triageTools(workspace, 'exploit'), 5, noEvents));
    try {
      const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
      const headers = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
      expect((await fetch(server.url, { method: 'POST', body, headers })).status).toBe(401);
      expect((await fetch(server.url, { method: 'POST', body, headers: { ...headers, Authorization: 'Bearer wrong' } })).status).toBe(401);
    } finally {
      await server.close();
    }
  });
});

describe('triageWithClaudeCode', () => {
  const fakeAgent = resolve(import.meta.dirname, 'acp-fake-agent.ts');
  const tsx = resolve(import.meta.dirname, '../../node_modules/.bin/tsx');

  async function agentCommand(): Promise<string> {
    const command = join(dir, 'fake-acp');
    await writeFile(command, `#!/bin/sh\nexec "${tsx}" "${fakeAgent}"\n`);
    await chmod(command, 0o755);
    return command;
  }

  it('runs the check in Claude Code with only Minotaur tools, and no API key', async () => {
    const log = join(dir, 'session.json');
    const env = { ...process.env, MINOTAUR_ACP_COMMAND: await agentCommand(), FAKE_ACP_LOG: log, ANTHROPIC_API_KEY: 'sk-not-for-claude-code' };
    const result = await triageWithClaudeCode(subject, workspace, { modelId: 'claude-sonnet-5', maxSteps: 5, mode: 'exploit', env });

    expect(result.error).toBeUndefined();
    expect(result.status).toBe('succeeded');
    expect(result.exploit).toMatchObject({ exploitability: 'exploitable', rationale: 'The host parameter reaches exec (prompt 1).' });
    expect(result.rejected).toEqual([]);
    expect(result.steps).toBe(1);
    expect(result.inputTokens).toBe(1200);
    expect(result.costUsd).toBe(0);
    expect(result.inputs.map((input) => input.path)).toEqual(['app.js']);

    const seen = JSON.parse(await readFile(log, 'utf8')) as { params: Record<string, any>; env: Record<string, string> };
    expect(seen.env['ANTHROPIC_API_KEY']).toBeUndefined();
    expect(seen.params['cwd']).toBe(workspace.root);
    expect(seen.params['mcpServers'][0]).toMatchObject({ type: 'http', name: 'minotaur' });
    expect(seen.params['mcpServers'][0].url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
    expect(seen.params['_meta'].claudeCode.options).toMatchObject({ model: 'claude-sonnet-5', tools: [], settingSources: [] });
    expect(seen.params['_meta'].systemPrompt).toContain('mcp__minotaur__submit_verdict');
  });

  it('fails when the model never submits an answer', async () => {
    const env = { ...process.env, MINOTAUR_ACP_COMMAND: await agentCommand(), FAKE_ACP_BEHAVIOUR: 'prose' };
    const result = await triageWithClaudeCode(subject, workspace, { modelId: 'claude-sonnet-5', maxSteps: 5, mode: 'exploit', env });
    expect(result.status).toBe('failed');
    expect(result.error).toMatch(/did not submit a verdict/);
  });

  it('says how to sign in when Claude Code is not signed in', async () => {
    const env = { ...process.env, MINOTAUR_ACP_COMMAND: await agentCommand(), FAKE_ACP_BEHAVIOUR: 'unauthenticated' };
    const result = await triageWithClaudeCode(subject, workspace, { modelId: 'claude-sonnet-5', maxSteps: 5, mode: 'exploit', env });
    expect(result.status).toBe('failed');
    expect(result.error).toMatch(/Claude Code is not signed in/);
  });

  it('says how to install the adapter when it is missing', async () => {
    const env = { ...process.env, MINOTAUR_ACP_COMMAND: join(dir, 'no-such-adapter') };
    const result = await triageWithClaudeCode(subject, workspace, { modelId: 'claude-sonnet-5', maxSteps: 5, mode: 'exploit', env });
    expect(result.status).toBe('failed');
    expect(result.error).toMatch(/npm install -g @agentclientprotocol\/claude-agent-acp/);
  });
});

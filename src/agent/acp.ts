/**
 * A check run by Claude Code, through the Agent Client Protocol (ACP).
 *
 * Minotaur starts `claude-agent-acp`, the ACP adapter for Claude Code, and
 * talks to it over stdio. Claude Code signs in on its own, so a check uses the
 * Claude subscription that Claude Code is signed in with. Minotaur sends no
 * API key, and removes the API key variables from the adapter's environment.
 *
 * Claude Code gets none of its own tools. Its only tools are Minotaur's
 * (`read_file`, `grep`, `list_dir` and `submit_verdict`), served over MCP on a
 * loopback port that needs a random token. So every read still goes through
 * the confined workspace, files with secrets stay out, and every input is
 * recorded for the cache. Claude Code loads no settings, neither the user's
 * nor the repository's, because a repository could otherwise add hooks or
 * MCP servers to the check.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Readable, Writable } from 'node:stream';

import * as acp from '@agentclientprotocol/sdk';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { ToolSet } from 'ai';
import { z } from 'zod';

import type { AssessmentMode } from '../core/index.js';

import { FINAL_TURN, REMINDER, settleVerdict, type AgentResult, type StepProgress } from './agent.js';
import type { Effort } from './model.js';
import { EXPLOIT_SYSTEM_PROMPT, renderFinding, SYSTEM_PROMPT, type EarlierCheck, type TriageSubject } from './prompt.js';
import { triageTools } from './tools.js';
import type { Workspace } from './workspace.js';

/** The adapter started when `MINOTAUR_ACP_COMMAND` is not set. */
export const DEFAULT_ACP_COMMAND = 'claude-agent-acp';
/** The npm package of the adapter. */
export const ACP_PACKAGE = '@agentclientprotocol/claude-agent-acp';

/** The MCP server name. Claude Code shows its tools as `mcp__minotaur__<tool>`. */
const SERVER_NAME = 'minotaur';
const FINAL_TOOL = 'submit_verdict';

/** Removed from the adapter's environment, so Claude Code uses its subscription login. */
const API_KEY_VARIABLES = ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'MINOTAUR_API_KEY'];

/** How many times a model that stopped without an answer is told to submit one. */
const MAX_REMINDERS = 2;
/** Tool calls refused after the step limit before the turn is cancelled. */
const MAX_REFUSED_CALLS = 3;
const MAX_REQUEST_BYTES = 1_000_000;

/** ACP's error code for a session that needs a login. */
const AUTH_REQUIRED = -32000;

const TOOL_NOTE = `Your tools are named mcp__${SERVER_NAME}__read_file, mcp__${SERVER_NAME}__grep, mcp__${SERVER_NAME}__list_dir and mcp__${SERVER_NAME}__submit_verdict. Paths are relative to the repository root.`;

export interface ClaudeCodeOptions {
  /** The Claude model, such as `claude-sonnet-5`. */
  modelId: string;
  maxSteps: number;
  effort?: Effort | undefined;
  mode?: AssessmentMode | undefined;
  earlier?: EarlierCheck | undefined;
  abortSignal?: AbortSignal | undefined;
  onStep?: ((progress: StepProgress) => void) | undefined;
  /** The environment the adapter starts with, and where `MINOTAUR_ACP_COMMAND` is read. Defaults to `process.env`. */
  env?: Readonly<Record<string, string | undefined>> | undefined;
}

export async function triageWithClaudeCode(
  subject: TriageSubject,
  workspace: Workspace,
  options: ClaudeCodeOptions,
): Promise<AgentResult> {
  const mode = options.mode ?? 'triage';
  const env = options.env ?? process.env;
  let usage = { inputTokens: 0, outputTokens: 0 };
  const result = (outcome: Pick<AgentResult, 'status' | 'error'>, tools: CheckTools): AgentResult => ({
    rejected: [],
    downgraded: false,
    inputs: workspace.inputs(),
    ...usage,
    costUsd: 0,
    steps: tools.steps,
    ...outcome,
  });

  let cancel = (): void => undefined;
  const tools = new CheckTools(triageTools(workspace, mode), options.maxSteps, {
    onStep: (steps) =>
      options.onStep?.({ steps, ...usage, costUsd: 0, inputs: workspace.inputs() }),
    // The answer is in, so the rest of the turn is not needed.
    onSubmit: () => cancel(),
    onExhausted: () => cancel(),
  });
  const server = await serveTools(tools);
  let agent: AgentProcess | undefined;
  try {
    agent = await startAgent(env['MINOTAUR_ACP_COMMAND'] || DEFAULT_ACP_COMMAND, workspace.root, env);
    const stream = acp.ndJsonStream(
      Writable.toWeb(agent.child.stdin) as WritableStream<Uint8Array>,
      Readable.toWeb(agent.child.stdout) as ReadableStream<Uint8Array>,
    );
    const stopReason = await acp
      .client({ name: 'minotaur' })
      .onRequest(acp.methods.client.session.requestPermission, ({ params }) => permit(params))
      .onNotification(acp.methods.client.session.update, () => undefined)
      .connectWith(stream, async (ctx) => {
        await ctx.request(acp.methods.agent.initialize, { protocolVersion: acp.PROTOCOL_VERSION, clientCapabilities: {} });
        const { sessionId } = await ctx
          .request(acp.methods.agent.session.new, {
            cwd: workspace.root,
            mcpServers: [
              { type: 'http', name: SERVER_NAME, url: server.url, headers: [{ name: 'Authorization', value: `Bearer ${server.token}` }] },
            ],
            _meta: {
              systemPrompt: `${mode === 'exploit' ? EXPLOIT_SYSTEM_PROMPT : SYSTEM_PROMPT}\n\n${TOOL_NOTE}`,
              claudeCode: { options: sessionOptions(options, Object.keys(tools.names)) },
            },
          })
          .catch((error: unknown) => {
            throw explainSessionError(error);
          });

        cancel = () => void ctx.notify(acp.methods.agent.session.cancel, { sessionId }).catch(() => undefined);
        options.abortSignal?.addEventListener('abort', cancel, { once: true });

        let text = renderFinding(subject, mode, options.earlier);
        for (let reminders = 0; ; reminders += 1) {
          const response = await ctx.request(acp.methods.agent.session.prompt, { sessionId, prompt: [{ type: 'text', text }] });
          if (response.usage) usage = { inputTokens: response.usage.inputTokens, outputTokens: response.usage.outputTokens };
          const done = tools.submitted !== undefined || response.stopReason === 'cancelled' || response.stopReason === 'refusal';
          if (done || reminders >= MAX_REMINDERS) return response.stopReason;
          text = tools.exhausted ? FINAL_TURN : REMINDER;
        }
      });

    if (tools.submitted === undefined) {
      if (options.abortSignal?.aborted) return result({ status: 'failed', error: 'the check was cancelled' }, tools);
      const error =
        stopReason === 'refusal'
          ? `Claude refused to continue after ${plural(tools.steps, 'step')}`
          : `the model did not submit a verdict (stopped with "${stopReason}" after ${plural(tools.steps, 'step')})`;
      return result({ status: 'failed', error }, tools);
    }
    return { ...result({ status: 'succeeded' }, tools), ...(await settleVerdict(mode, tools.submitted, workspace)) };
  } catch (error) {
    const detail = agent?.stderr().trim();
    const message = (error as Error).message;
    return result({ status: 'failed', error: detail && !message.includes(detail) ? `${message}\n${detail}` : message }, tools);
  } finally {
    agent?.child.kill();
    await server.close();
  }
}

/** What Claude Code is started with. Anything not listed here keeps Claude Code's default. */
export function sessionOptions(options: Pick<ClaudeCodeOptions, 'modelId' | 'effort'>, toolNames: readonly string[]): Record<string, unknown> {
  return {
    model: options.modelId,
    ...(options.effort ? { effort: options.effort } : {}),
    // None of Claude Code's own tools: reads go through the workspace, and nothing runs commands.
    tools: [],
    allowedTools: toolNames.map((name) => `mcp__${SERVER_NAME}__${name}`),
    // Neither the user's nor the repository's settings, hooks or MCP servers.
    settingSources: [],
    strictMcpConfig: true,
    persistSession: false,
  };
}

/** Allows Minotaur's own tools and refuses everything else. */
export function permit(params: acp.RequestPermissionRequest): acp.RequestPermissionResponse {
  const toolName = toolNameOf(params.toolCall);
  const ours = toolName?.startsWith(`mcp__${SERVER_NAME}__`) ?? false;
  const option = params.options.find((choice) => choice.kind === (ours ? 'allow_once' : 'reject_once'));
  if (!option) return { outcome: { outcome: 'cancelled' } };
  return { outcome: { outcome: 'selected', optionId: option.optionId } };
}

function toolNameOf(toolCall: acp.ToolCallUpdate): string | undefined {
  const claudeCode = toolCall._meta?.['claudeCode'];
  if (typeof claudeCode !== 'object' || claudeCode === null) return undefined;
  const name = (claudeCode as Record<string, unknown>)['toolName'];
  return typeof name === 'string' ? name : undefined;
}

function explainSessionError(error: unknown): Error {
  if (typeof error === 'object' && error !== null && (error as { code?: unknown }).code === AUTH_REQUIRED) {
    return new Error('Claude Code is not signed in. Run claude, sign in with /login, then try again.');
  }
  return error instanceof Error ? error : new Error(String(error));
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

interface ToolEvents {
  onStep: (steps: number) => void;
  onSubmit: () => void;
  onExhausted: () => void;
}

interface CheckTool {
  description: string;
  schema: z.ZodType;
  execute: (input: unknown) => Promise<unknown>;
}

/**
 * The check's tools, with the step limit. Once the reads are used up, a read
 * returns the final-turn instruction instead, so the model submits its answer.
 */
export class CheckTools {
  steps = 0;
  submitted: unknown;
  exhausted = false;
  readonly names: Record<string, CheckTool>;
  private refused = 0;

  constructor(
    tools: ToolSet,
    private readonly maxSteps: number,
    private readonly events: ToolEvents,
  ) {
    this.names = Object.fromEntries(
      Object.entries(tools).map(([name, tool]) => [
        name,
        {
          description: typeof tool.description === 'string' ? tool.description : '',
          schema: tool.inputSchema as z.ZodType,
          execute: (input: unknown) => (tool.execute as (input: unknown, options: unknown) => Promise<unknown>)(input, {}),
        },
      ]),
    );
  }

  list(): { name: string; description: string; inputSchema: { type: 'object'; [key: string]: unknown } }[] {
    return Object.entries(this.names).map(([name, tool]) => ({
      name,
      description: tool.description,
      inputSchema: z.toJSONSchema(tool.schema, { io: 'input' }) as { type: 'object'; [key: string]: unknown },
    }));
  }

  async call(name: string, args: unknown): Promise<CallToolResult> {
    const tool = this.names[name];
    if (!tool) return failure(`unknown tool ${name}`);
    const parsed = tool.schema.safeParse(args);
    if (!parsed.success) return failure(`invalid input: ${parsed.error.message}`);
    if (name === FINAL_TOOL) {
      // The first answer counts. A second call cannot replace it.
      if (this.submitted === undefined) {
        this.submitted = parsed.data;
        this.events.onSubmit();
      }
      return text(JSON.stringify({ received: true }));
    }
    if (this.steps >= this.maxSteps) {
      this.exhausted = true;
      this.refused += 1;
      if (this.refused >= MAX_REFUSED_CALLS) this.events.onExhausted();
      return failure(FINAL_TURN);
    }
    this.steps += 1;
    const output = await tool.execute(parsed.data);
    this.events.onStep(this.steps);
    return text(JSON.stringify(output));
  }
}

function text(value: string): CallToolResult {
  return { content: [{ type: 'text', text: value }] };
}

function failure(message: string): CallToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

interface ToolServer {
  url: string;
  token: string;
  close: () => Promise<void>;
}

/** Serves the tools over MCP on a loopback port. Each request needs the bearer token. */
export async function serveTools(tools: CheckTools): Promise<ToolServer> {
  const token = randomBytes(32).toString('hex');
  const expected = Buffer.from(`Bearer ${token}`);
  const http = createServer((req, res) => {
    const given = Buffer.from(req.headers.authorization ?? '');
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
      res.writeHead(401).end();
      return;
    }
    // Stateless: a POST carries every request, and there is no stream to open or session to end.
    if (req.method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' }).end();
      return;
    }
    void (async () => {
      const body = await readJson(req);
      const mcp = new Server({ name: SERVER_NAME, version: '1' }, { capabilities: { tools: {} } });
      mcp.setRequestHandler(ListToolsRequestSchema, () => ({ tools: tools.list() }));
      mcp.setRequestHandler(CallToolRequestSchema, (request) => tools.call(request.params.name, request.params.arguments ?? {}));
      const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });
      res.on('close', () => {
        void transport.close();
        void mcp.close();
      });
      // The SDK's own types disagree under exactOptionalPropertyTypes.
      await mcp.connect(transport as Parameters<typeof mcp.connect>[0]);
      await transport.handleRequest(req, res, body);
    })().catch(() => {
      if (!res.headersSent) res.writeHead(400).end();
      else res.end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    http.once('error', reject);
    http.listen(0, '127.0.0.1', () => resolve());
  });
  const { port } = http.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    token,
    close: () =>
      new Promise((resolve) => {
        http.closeAllConnections();
        http.close(() => resolve());
      }),
  };
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_REQUEST_BYTES) throw new Error('request too large');
    chunks.push(chunk as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}

interface AgentProcess {
  child: ChildProcessWithoutNullStreams;
  /** The end of what the adapter wrote to stderr, for errors. */
  stderr: () => string;
}

async function startAgent(command: string, cwd: string, env: Readonly<Record<string, string | undefined>>): Promise<AgentProcess> {
  const childEnv: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined && !API_KEY_VARIABLES.includes(key)) childEnv[key] = value;
  }
  const child = spawn(command, [], { cwd, env: childEnv, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    stderr = (stderr + chunk).slice(-2_000);
  });
  await new Promise<void>((resolve, reject) => {
    child.once('spawn', resolve);
    child.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') {
        reject(new Error(`${command} is not installed. Install the Claude Code ACP adapter with: npm install -g ${ACP_PACKAGE}`));
      } else reject(error);
    });
  });
  return { child, stderr: () => stderr };
}

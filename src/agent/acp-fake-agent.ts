/**
 * A stand-in for claude-agent-acp, for `acp.test.ts`. It speaks ACP on stdio,
 * reads `app.js` with Minotaur's MCP tools and submits a verdict that quotes it.
 *
 * `FAKE_ACP_LOG` names a file that gets the session/new params and the
 * environment, so the test can check what Claude Code would have been given.
 * `FAKE_ACP_BEHAVIOUR` is `submit` (the default), `prose` (ends the turn
 * without an answer) or `unauthenticated` (session/new needs a login).
 */

import { writeFileSync } from 'node:fs';
import { Readable, Writable } from 'node:stream';

import * as acp from '@agentclientprotocol/sdk';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const behaviour = process.env['FAKE_ACP_BEHAVIOUR'] ?? 'submit';
let server: { url: string; headers: Record<string, string> } | undefined;
let prompts = 0;

const app = acp
  .agent({ name: 'fake-claude' })
  .onRequest(acp.methods.agent.initialize, () => ({ protocolVersion: acp.PROTOCOL_VERSION, agentCapabilities: {} }))
  .onRequest(acp.methods.agent.session.new, ({ params }) => {
    if (behaviour === 'unauthenticated') throw acp.RequestError.authRequired();
    const log = process.env['FAKE_ACP_LOG'];
    if (log) writeFileSync(log, JSON.stringify({ params, env: process.env }));
    const http = params.mcpServers.find((entry) => 'type' in entry && entry.type === 'http');
    if (http && 'url' in http) {
      server = { url: http.url, headers: Object.fromEntries(http.headers.map((header) => [header.name, header.value])) };
    }
    return { sessionId: 'session-1' };
  })
  .onRequest(acp.methods.agent.session.prompt, async () => {
    prompts += 1;
    if (behaviour === 'prose' || !server) return { stopReason: 'end_turn' as const };
    const mcp = new Client({ name: 'fake-claude', version: '1' });
    const transport = new StreamableHTTPClientTransport(new URL(server.url), { requestInit: { headers: server.headers } });
    await mcp.connect(transport as Parameters<typeof mcp.connect>[0]);
    await mcp.callTool({ name: 'read_file', arguments: { path: 'app.js' } });
    await mcp.callTool({
      name: 'submit_verdict',
      arguments: {
        exploitability: 'exploitable',
        confidence: 0.9,
        rationale: `The host parameter reaches exec (prompt ${prompts}).`,
        evidence: [{ path: 'app.js', startLine: 1, endLine: 1, quote: "exec('ping ' + req.query.host);" }],
      },
    });
    await mcp.close();
    return { stopReason: 'end_turn' as const, usage: { inputTokens: 1200, outputTokens: 80, totalTokens: 1280 } };
  })
  .onNotification(acp.methods.agent.session.cancel, () => undefined);

const connection = app.connect(
  acp.ndJsonStream(Writable.toWeb(process.stdout) as WritableStream<Uint8Array>, Readable.toWeb(process.stdin) as ReadableStream<Uint8Array>),
);
await connection.closed;

/**
 * The whole CLI against a fake OpenAI-compatible server on localhost, the way
 * it runs against Ollama or a company gateway.
 */

import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { main } from './main.js';

const SECRET = 'ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234';
const QUERY_LINE = "  const sql = `SELECT * FROM Users WHERE email = '${req.body.email}'`;";

type ToolCall = { name: string; args: Record<string, unknown> };

let server: Server;
let baseUrl: string;
let script: ToolCall[][] = [];
let requests: Array<Record<string, unknown>> = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      requests.push(JSON.parse(body) as Record<string, unknown>);
      const calls = script.shift() ?? [];
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          id: `chatcmpl-${requests.length}`,
          object: 'chat.completion',
          created: 0,
          model: 'fake-coder',
          choices: [
            {
              index: 0,
              message: {
                role: 'assistant',
                content: null,
                tool_calls: calls.map((call, index) => ({
                  id: `call_${requests.length}_${index}`,
                  type: 'function',
                  function: { name: call.name, arguments: JSON.stringify(call.args) },
                })),
              },
              finish_reason: 'tool_calls',
            },
          ],
          usage: { prompt_tokens: 1_000, completion_tokens: 100, total_tokens: 1_100 },
        }),
      );
    });
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1`;
});
afterAll(() => new Promise<void>((done) => server.close(() => done())));

let root: string;
let cache: string;
let stdout: string;
let stderr: string;

/** Commits everything in the fixture repository, creating it first, and returns the short hash. */
function commitAll(message: string): string {
  const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });
  git('init', '-q');
  git('add', '.');
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', message);
  return git('log', '-1', '--format=%h').trim();
}

beforeEach(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-e2e-')));
  await mkdir(join(root, 'routes'));
  await mkdir(join(root, 'config'));
  await writeFile(
    join(root, 'routes', 'login.js'),
    ['module.exports = function login(req, res) {', QUERY_LINE, '  return db.query(sql);', '};', ''].join('\n'),
  );
  await writeFile(join(root, 'config', 'deploy.py'), `TOKEN = "${SECRET}"\n`);
  await writeFile(
    join(root, 'semgrep.json'),
    JSON.stringify({
      version: '1.172.0',
      results: [
        {
          check_id: 'javascript.express.security.sql-injection',
          path: join(root, 'routes', 'login.js'),
          start: { line: 2, col: 3 },
          end: { line: 2, col: 70 },
          extra: { message: 'SQL built from request data', severity: 'ERROR', lines: 'requires login', metadata: {} },
        },
      ],
      errors: [],
      paths: { scanned: ['routes/login.js'] },
    }),
  );
  await writeFile(
    join(root, 'gitleaks.sarif'),
    JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'gitleaks', rules: [{ id: 'github-pat' }] } },
          results: [
            {
              ruleId: 'github-pat',
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'config/deploy.py' },
                    region: { startLine: 1, snippet: { text: SECRET } },
                  },
                },
              ],
            },
          ],
        },
      ],
    }),
  );

  cache = await mkdtemp(join(tmpdir(), 'minotaur-e2e-cache-'));
  vi.stubEnv('MINOTAUR_CACHE_DIR', cache);
  script = [];
  requests = [];
  stdout = '';
  stderr = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => ((stdout += String(chunk)), true));
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => ((stderr += String(chunk)), true));
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await rm(root, { recursive: true, force: true });
  await rm(cache, { recursive: true, force: true });
});

const sources = () => ['--source', join(root, 'semgrep.json'), '--source', join(root, 'gitleaks.sarif')];
const model = () => ['--model', 'openai-compatible:fake-coder', '--base-url', baseUrl];

async function scanJson(): Promise<{ findings: Array<{ id: string; kind: string; location?: { path: string } }> }> {
  expect(await main(['scan', root, ...sources(), '--json'])).toBe(0);
  const parsed = JSON.parse(stdout);
  stdout = '';
  return parsed;
}

const verdict = {
  exploitability: 'exploitable',
  confidence: 0.9,
  rationale: 'The request body is interpolated straight into the SQL string.',
  entryPoint: 'POST /login body.email',
  preconditions: [],
  evidence: [{ path: 'routes/login.js', startLine: 2, endLine: 2, quote: QUERY_LINE.trim() }],
  openQuestions: [],
};

describe('minotaur scan', () => {
  it('lists findings from report files with repository paths', async () => {
    expect(await main(['scan', root, ...sources()])).toBe(0);
    expect(stdout).toContain('routes/login.js:2');
    expect(stdout).toContain('config/deploy.py:1');
    expect(stdout).not.toContain(SECRET);
    expect(stderr).toContain('semgrep.json');
  });

  it('keeps the file with a secret protected when the filter hides the secret finding', async () => {
    expect(await main(['scan', root, ...sources(), '--json', '--min-severity', 'critical'])).toBe(0);
    const file = JSON.parse(stdout);
    expect(file.findings.some((finding: { kind: string }) => finding.kind === 'secret')).toBe(false);
    expect(file.protectedPaths).toEqual(['config/deploy.py']);
  });

  it('reuses the last scan of a commit, and says which commit it is', async () => {
    const first = commitAll('first');
    const run = async (...extra: string[]) => {
      stderr = '';
      expect(await main(['scan', root, ...sources(), ...extra])).toBe(0);
      return stderr;
    };
    expect(await run()).toContain(`at commit ${first} (first)`);
    expect(stderr).toContain('Scanning');
    expect(await run()).toContain('Using the scan');
    expect(await run('--rescan')).toContain('Scanning');
    expect(stdout).toContain(`On commit ${first} (first).`);

    // An uncommitted edit is left out, so the scan is of a clean copy of the commit.
    await writeFile(join(root, 'routes', 'login.js'), 'changed\n');
    expect(await run()).toContain('Uncommitted changes are left out');
    expect(stderr).toContain('Scanning');
    expect(await run()).toContain('Using the scan');
    expect(stdout).toContain('routes/login.js:2');
  });

  it('scans an earlier commit given by hash, and refuses one that does not exist', async () => {
    const first = commitAll('first');
    await writeFile(join(root, 'routes', 'later.js'), 'x\n');
    commitAll('second');
    stderr = '';
    expect(await main(['scan', root, ...sources(), '--commit', first])).toBe(0);
    expect(stderr).toContain(`at commit ${first} (first)`);
    expect(stderr).toContain('not your working tree');
    await expect(main(['scan', root, ...sources(), '--commit', 'nope'])).rejects.toThrow(/"nope" is not a commit/);
  });

  it('hides findings rated as noise unless asked, and keeps them in JSON', async () => {
    const style = join(root, 'style.json');
    await writeFile(
      style,
      JSON.stringify({
        version: '1.172.0',
        results: [
          {
            check_id: 'javascript.lang.correctness.no-replaceall',
            path: join(root, 'routes', 'login.js'),
            start: { line: 3, col: 3 },
            end: { line: 3, col: 20 },
            extra: { message: 'replaceAll is not portable', severity: 'WARNING', lines: 'x', metadata: {} },
          },
        ],
        errors: [],
        paths: { scanned: ['routes/login.js'] },
      }),
    );
    const scan = async (...extra: string[]) => {
      stdout = '';
      expect(await main(['scan', root, ...sources(), '--source', style, ...extra])).toBe(0);
      return stdout;
    };

    const plain = await scan();
    expect(plain).not.toContain('routes/login.js:3');
    expect(plain).toContain('1 hidden as likely noise (--all shows them)');
    expect(plain).toContain('likely an issue');

    expect(await scan('--all')).toContain('routes/login.js:3');

    const json = JSON.parse(await scan('--json'));
    const noise = json.findings.find((finding: { ruleId: string }) => finding.ruleId === 'javascript.lang.correctness.no-replaceall');
    expect(noise).toMatchObject({ focus: 'noise' });
    expect(noise.focusReasons.length).toBeGreaterThan(0);
    expect(json.findings.at(-1).focus).toBe('noise');

    const likely = JSON.parse(await scan('--json', '--focus', 'likely'));
    expect(likely.findings.map((finding: { focus: string }) => finding.focus)).toEqual(['likely', 'likely']);

    await expect(main(['scan', root, ...sources(), '--focus', 'high'])).rejects.toThrow(/--focus must be one of/);
  });

  it('marks a finding by hand, hides it, lifts a false secret, and undoes it', async () => {
    const first = commitAll('first');
    const { findings } = await scanJson();
    const secret = findings.find((finding) => finding.kind === 'secret')!;

    expect(await main(['mark', secret.id, 'false-positive', root, ...sources(), '--reason', 'Fake token in a fixture'])).toBe(0);
    expect(stdout).toContain(`Marked ${secret.id} (github-pat) as false positive in .minotaur/decisions.yml.`);
    expect(stdout).toContain('Checks may now read config/deploy.py');
    const file = await readFile(join(root, '.minotaur', 'decisions.yml'), 'utf8');
    expect(file).toContain('reason: Fake token in a fixture');
    expect(file).not.toContain(SECRET);

    // The decisions file alone does not make the working tree count as changed.
    stdout = '';
    stderr = '';
    expect(await main(['scan', root, ...sources()])).toBe(0);
    expect(stderr).not.toContain('Uncommitted changes');
    expect(stderr).toContain(`at commit ${first}`);
    expect(stdout).not.toContain('config/deploy.py:1');
    expect(stdout).toContain('1 marked false positive, accepted risk or fixed (--all shows them)');

    stdout = '';
    const json = await scanJson();
    expect(json.findings.find((finding) => finding.id === secret.id)).toMatchObject({ decision: { state: 'false_positive' } });
    expect((json as unknown as { protectedPaths: string[] }).protectedPaths).toEqual([]);

    expect(await main(['mark', secret.id.slice(0, 5), 'open', root])).toBe(0);
    expect(stdout).toContain(`${secret.id} is open again`);
    stdout = '';
    expect((await scanJson()).findings.find((finding) => finding.id === secret.id)).not.toHaveProperty('decision');

    await expect(main(['mark', secret.id, 'maybe', root])).rejects.toThrow(/is not a decision/);
  });

  it('writes JSON without the secret in it', async () => {
    const { findings } = await scanJson();
    expect(findings.map((finding) => finding.kind).sort()).toEqual(['sast', 'secret']);
    expect(JSON.stringify(findings)).not.toContain(SECRET);
  });
});

describe('minotaur triage', () => {
  it('investigates with a self-hosted model and never sends the secret', async () => {
    const { findings } = await scanJson();
    const code = findings.find((finding) => finding.kind === 'sast')!;
    script = [
      [{ name: 'read_file', args: { path: 'config/deploy.py' } }],
      [{ name: 'read_file', args: { path: 'routes/login.js' } }],
      [{ name: 'submit_verdict', args: verdict }],
    ];

    expect(await main(['triage', code.id, root, ...sources(), ...model(), '--json'])).toBe(0);
    const result = JSON.parse(stdout);
    expect(result).toMatchObject({
      status: 'succeeded',
      exploitability: 'exploitable',
      entryPoint: 'POST /login body.email',
      downgraded: false,
      filesRead: ['routes/login.js'],
      model: 'openai-compatible:fake-coder',
      costUsd: 0,
    });
    expect(result.evidence).toHaveLength(1);

    expect(requests).toHaveLength(3);
    for (const request of requests) {
      const body = JSON.stringify(request);
      expect(body).not.toContain(SECRET);
      expect(body).not.toContain('cache_control');
      expect(request['tool_choice'] === undefined || request['tool_choice'] === 'auto').toBe(true);
    }
    expect(stderr).toContain(`Code is sent to ${baseUrl}`);
    expect(stderr).toContain('looked at routes/login.js');
    expect(stderr).not.toContain('$');
  });

  it('digs deeper from an earlier result, using the findings from scan --json', async () => {
    const scan = await scanJson();
    const code = scan.findings.find((finding) => finding.kind === 'sast')!;
    const findingsFile = join(root, 'findings.json');
    await writeFile(findingsFile, JSON.stringify(scan));

    script = [
      [
        {
          name: 'submit_verdict',
          args: { exploitability: 'undetermined', confidence: 0.3, rationale: 'Could not find where login is mounted.', openQuestions: ['Which router mounts login?'] },
        },
      ],
    ];
    expect(await main(['triage', code.id, root, '--findings', findingsFile, ...model(), '--json'])).toBe(0);
    const earlierFile = join(root, 'earlier.json');
    await writeFile(earlierFile, stdout);
    stdout = '';

    script = [[{ name: 'read_file', args: { path: 'routes/login.js' } }], [{ name: 'submit_verdict', args: verdict }]];
    requests = [];
    expect(
      await main(['triage', code.id, root, '--findings', findingsFile, ...model(), '--continue-from', earlierFile, '--json']),
    ).toBe(0);
    const result = JSON.parse(stdout);
    expect(result).toMatchObject({ exploitability: 'exploitable', continuedFrom: earlierFile });
    expect(JSON.stringify(requests[0])).toContain('Which router mounts login?');
  });

  it('reuses a check while the model and the files it read stay the same', async () => {
    const { findings } = await scanJson();
    const code = findings.find((finding) => finding.kind === 'sast')!;
    const answer = () => [[{ name: 'read_file', args: { path: 'routes/login.js' } }], [{ name: 'submit_verdict', args: verdict }]];
    const run = async (...extra: string[]) => {
      stdout = '';
      stderr = '';
      requests = [];
      script = answer();
      expect(await main(['triage', code.id, root, ...sources(), ...model(), '--json', ...extra])).toBe(0);
      return JSON.parse(stdout);
    };

    const first = await run();
    expect(requests).toHaveLength(2);

    expect(await run()).toEqual(first);
    expect(requests).toHaveLength(0);
    expect(stderr).toContain('Reusing the check');

    await run('--recheck');
    expect(requests).toHaveLength(2);

    await run('--model', 'openai-compatible:other-coder');
    expect(requests).toHaveLength(2);

    await writeFile(join(root, 'routes', 'login.js'), `${await readFile(join(root, 'routes', 'login.js'), 'utf8')}// changed\n`);
    await run();
    expect(requests).toHaveLength(2);
    await run();
    expect(requests).toHaveLength(0);
  });

  it('reuses a check on the commit it was made on, even with uncommitted edits', async () => {
    commitAll('first');
    const { findings } = await scanJson();
    const code = findings.find((finding) => finding.kind === 'sast')!;
    const run = async () => {
      stdout = '';
      stderr = '';
      requests = [];
      script = [[{ name: 'read_file', args: { path: 'routes/login.js' } }], [{ name: 'submit_verdict', args: verdict }]];
      expect(await main(['triage', code.id, root, ...sources(), ...model(), '--json'])).toBe(0);
    };
    await run();
    expect(requests).toHaveLength(2);

    await writeFile(join(root, 'routes', 'login.js'), `${await readFile(join(root, 'routes', 'login.js'), 'utf8')}// changed\n`);
    await run();
    expect(requests).toHaveLength(0);
    expect(stderr).toContain('It was made on this commit');
  });

  it('refuses to triage a secret before anything is sent', async () => {
    const { findings } = await scanJson();
    const secret = findings.find((finding) => finding.kind === 'secret')!;
    await expect(main(['triage', secret.id, root, ...sources(), ...model()])).rejects.toThrow(/never triaged/);
    expect(requests).toHaveLength(0);
  });

  it('stops at the token cap', async () => {
    const { findings } = await scanJson();
    const code = findings.find((finding) => finding.kind === 'sast')!;
    script = Array.from({ length: 30 }, () => [{ name: 'list_dir', args: { path: '.' } }]);

    const exit = await main(['triage', code.id, root, ...sources(), ...model(), '--max-tokens', '30000', '--json']);
    const result = JSON.parse(stdout);
    expect(exit).toBe(1);
    expect(result.status).toBe('skipped_budget');
    expect(result.steps).toBeGreaterThan(1);
    expect(result.steps).toBeLessThan(30);
    expect(requests).toHaveLength(result.steps);
    expect(result.inputTokens + result.outputTokens).toBeLessThanOrEqual(30_000);
  });

  it('sends nothing when the token cap cannot cover a single step', async () => {
    const { findings } = await scanJson();
    const code = findings.find((finding) => finding.kind === 'sast')!;

    const exit = await main(['triage', code.id, root, ...sources(), ...model(), '--max-tokens', '3000', '--json']);
    expect(exit).toBe(1);
    expect(JSON.parse(stdout)).toMatchObject({ status: 'skipped_budget', steps: 0 });
    expect(requests).toHaveLength(0);
  });

  it('keeps the result file readable for later runs', async () => {
    const { findings } = await scanJson();
    const code = findings.find((finding) => finding.kind === 'sast')!;
    script = [[{ name: 'submit_verdict', args: verdict }]];
    expect(await main(['triage', code.id, root, ...sources(), ...model()])).toBe(0);
    expect(stdout).toContain('EXPLOITABLE');
    expect(await readFile(join(root, 'routes', 'login.js'), 'utf8')).toContain(QUERY_LINE);
  });
});

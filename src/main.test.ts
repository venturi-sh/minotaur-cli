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

const browse = vi.hoisted(() => vi.fn(async () => []));
vi.mock('./interactive/app.js', () => ({ browse }));

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
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', message);
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

  // Every run looks at a commit.
  commitAll('fixture');
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

describe('minotaur', () => {
  function terminal(on: boolean): () => void {
    const stdin = process.stdin.isTTY;
    const stdout = process.stdout.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: on });
    Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value: on });
    return () => {
      Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: stdin });
      Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value: stdout });
    };
  }

  it('browses the directory it is given, and . means the current one', async () => {
    const restore = terminal(true);
    const cwd = process.cwd();
    try {
      expect(await main([root])).toBe(0);
      expect(browse).toHaveBeenCalledWith(expect.objectContaining({ root }));

      browse.mockClear();
      process.chdir(root);
      // pnpm records where the test was started, and `.` follows that rather than the directory just entered.
      const typedIn = process.env['INIT_CWD'];
      delete process.env['INIT_CWD'];
      try {
        expect(await main(['.'])).toBe(0);
        expect(browse).toHaveBeenCalledWith(expect.objectContaining({ root }));
      } finally {
        if (typedIn === undefined) delete process.env['INIT_CWD'];
        else process.env['INIT_CWD'] = typedIn;
      }
    } finally {
      process.chdir(cwd);
      restore();
    }
  });

  it('rejects a word that is neither a command nor a directory', async () => {
    await expect(main(['nope'])).rejects.toThrow(/unknown command "nope"/);
    await expect(main([root, 'again'])).rejects.toThrow(/at most one path/);
  });
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
  it('refuses a folder without git, or without a commit, and says how to make one', async () => {
    const plain = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-plain-')));
    try {
      await expect(main(['scan', plain, ...sources()])).rejects.toThrow(/not in a git repository[\s\S]*git init && git add -A && git commit/);
      execFileSync('git', ['init', '-q'], { cwd: plain });
      await expect(main(['scan', plain, ...sources()])).rejects.toThrow(/has no commits yet[\s\S]*git add -A && git commit/);
    } finally {
      await rm(plain, { recursive: true, force: true });
    }
  });

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

describe('agent verdicts', () => {
  it('briefs a finding, checks the answer, and then hides it', async () => {
    const first = commitAll('first');
    const scanned = await scanJson();
    const code = scanned.findings.find((finding) => finding.kind === 'sast')!;
    const secret = scanned.findings.find((finding) => finding.kind === 'secret')!;

    expect(await main(['brief', code.id, root, ...sources(), '--json'])).toBe(0);
    const brief = JSON.parse(stdout);
    expect(brief.tree).toBe(root);
    expect(brief.commit.short).toBe(first);
    expect(brief.instructions).toContain('exploitable');
    expect(brief.instructions).toContain('untrusted data');
    expect(brief.submit).toContain(`verdict ${code.id}`);
    expect(brief.verdict.properties.exploitability).toBeTruthy();

    const file = join(root, 'verdict.json');
    await writeFile(file, JSON.stringify(verdict));
    stdout = '';
    expect(await main(['verdict', code.id, root, ...sources(), '--file', file, '--json', '--agent', 'cursor'])).toBe(0);
    expect(JSON.parse(stdout)).toMatchObject({ exploitability: 'exploitable', downgraded: false, model: 'agent:cursor', rejectedEvidence: [] });

    stdout = '';
    expect(await main(['scan', root, ...sources(), '--json', '--unchecked'])).toBe(0);
    expect(JSON.parse(stdout).findings.some((finding: { id: string }) => finding.id === code.id)).toBe(false);

    stdout = '';
    const again = await scanJson();
    expect(again.findings.find((finding) => finding.id === code.id)).toMatchObject({
      triageable: true,
      check: { exploitability: 'exploitable', by: 'agent:cursor' },
    });

    await writeFile(file, JSON.stringify({ ...verdict, evidence: [{ path: 'routes/login.js', startLine: 2, endLine: 2, quote: 'not the line' }] }));
    stdout = '';
    expect(await main(['verdict', code.id, root, ...sources(), '--file', file, '--json'])).toBe(0);
    expect(JSON.parse(stdout)).toMatchObject({ exploitability: 'undetermined', downgraded: true });

    await writeFile(file, '{');
    stdout = '';
    expect(await main(['verdict', code.id, root, ...sources(), '--file', file])).toBe(1);
    expect(JSON.parse(stdout).problems[0]).toMatch(/not JSON/);

    await writeFile(file, JSON.stringify({ exploitability: 'nope' }));
    stdout = '';
    expect(await main(['verdict', code.id, root, ...sources(), '--file', file])).toBe(1);
    expect(JSON.parse(stdout).problems.join('\n')).toMatch(/exploitability/);

    await writeFile(file, JSON.stringify(verdict));
    stdout = '';
    expect(await main(['verdict', secret.id, root, ...sources(), '--file', file])).toBe(1);
    expect(JSON.parse(stdout).problems[0]).toMatch(/secret/);
  });

  it('points at the clean copy when the working tree has changes', async () => {
    commitAll('first');
    const { findings } = await scanJson();
    const code = findings.find((finding) => finding.kind === 'sast')!;
    await writeFile(join(root, 'notes.txt'), 'changed\n');
    stdout = '';
    expect(await main(['brief', code.id, root, ...sources(), '--json'])).toBe(0);
    const brief = JSON.parse(stdout);
    expect(brief.tree).not.toBe(root);
    expect(brief.tree).toContain(brief.commit.sha);
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

describe('minotaur fix', () => {
  const SAFE_LINE = "  const sql = 'SELECT * FROM Users WHERE email = ?';";
  const fixCalls = (): ToolCall[][] => [
    [{ name: 'read_file', args: { path: 'routes/login.js' } }],
    [{ name: 'replace_in_file', args: { path: 'routes/login.js', oldText: QUERY_LINE, newText: SAFE_LINE } }],
    [{ name: 'submit_fix', args: { outcome: 'fixed', summary: 'Used a placeholder for the email.', notes: [] } }],
  ];
  const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });

  beforeEach(() => {
    for (const name of ['AUTHOR', 'COMMITTER']) {
      vi.stubEnv(`GIT_${name}_NAME`, 't');
      vi.stubEnv(`GIT_${name}_EMAIL`, 't@t');
    }
  });

  it('does not commit a fix that no scanner can check, and keeps no branch', async () => {
    const sql = (await scanJson()).findings.find((finding) => finding.kind === 'sast')!;
    script = fixCalls();
    expect(await main(['fix', sql.id, root, ...sources(), ...model()])).toBe(1);
    expect(stdout).toContain('Not committed, no scanner could verify it');
    expect(stdout).toContain('No branch was kept');
    expect(git('branch', '--list', 'minotaur/*')).toBe('');
  });

  it('commits on a new branch with --allow-unverified, and leaves the working tree alone', async () => {
    const sql = (await scanJson()).findings.find((finding) => finding.kind === 'sast')!;
    script = fixCalls();
    expect(await main(['fix', sql.id, root, ...sources(), ...model(), '--allow-unverified', '--json'])).toBe(0);
    const run = JSON.parse(stdout);
    expect(run.branch).toBe('minotaur/fixes');
    expect(run.results[0]).toMatchObject({ status: 'committed_unverified', changedFiles: ['routes/login.js'] });
    expect(git('show', `${run.branch}:routes/login.js`)).toContain(SAFE_LINE);
    expect(await readFile(join(root, 'routes', 'login.js'), 'utf8')).toContain(QUERY_LINE);
    expect(stderr).toContain('on branch minotaur/fixes');
  });

  it('skips a secret without calling the model, and takes several ids', async () => {
    const found = (await scanJson()).findings;
    const secret = found.find((finding) => finding.kind === 'secret')!;
    const sql = found.find((finding) => finding.kind === 'sast')!;
    script = fixCalls();
    expect(await main(['fix', secret.id, sql.id, root, ...sources(), ...model(), '--allow-unverified', '--json'])).toBe(1);
    const run = JSON.parse(stdout);
    expect(run.branch).toBe('minotaur/fixes');
    expect(run.results.map((result: { status: string }) => result.status)).toEqual(['skipped', 'committed_unverified']);
    expect(JSON.stringify(requests)).not.toContain(SECRET);
  });

  it('commits on another branch with --branch', async () => {
    const sql = (await scanJson()).findings.find((finding) => finding.kind === 'sast')!;
    script = fixCalls();
    expect(await main(['fix', sql.id, root, ...sources(), ...model(), '--allow-unverified', '--branch', 'security/fixes', '--json'])).toBe(0);
    expect(JSON.parse(stdout).branch).toBe('security/fixes');
    expect(git('branch', '--list', 'minotaur/*')).toBe('');
  });

  it("does not start while an agent's edits wait in the worktree", async () => {
    const sql = (await scanJson()).findings.find((finding) => finding.kind === 'sast')!;
    expect(await main(['brief', sql.id, root, ...sources(), '--fix', '--json'])).toBe(0);
    const tree = JSON.parse(stdout).tree as string;
    stdout = '';
    await writeFile(join(tree, 'routes', 'login.js'), 'in progress\n');
    await expect(main(['fix', sql.id, root, ...sources(), ...model()])).rejects.toThrow(`uncommitted edits for finding ${sql.id}`);
    expect(await readFile(join(tree, 'routes', 'login.js'), 'utf8')).toBe('in progress\n');
  });
});

describe('minotaur fix --all', () => {
  const SAFE_LINE = "  const sql = 'SELECT * FROM Users WHERE email = ?';";
  const fixCalls = (): ToolCall[][] => [
    [{ name: 'replace_in_file', args: { path: 'routes/login.js', oldText: QUERY_LINE, newText: SAFE_LINE } }],
    [{ name: 'submit_fix', args: { outcome: 'fixed', summary: 'Used a placeholder for the email.', notes: [] } }],
  ];

  beforeEach(() => {
    for (const name of ['AUTHOR', 'COMMITTER']) {
      vi.stubEnv(`GIT_${name}_NAME`, 't');
      vi.stubEnv(`GIT_${name}_EMAIL`, 't@t');
    }
  });

  it('fixes every open finding on the batch branch, and a secret it cannot fix is not a failure', async () => {
    script = fixCalls();
    expect(await main(['fix', '--all', root, ...sources(), ...model(), '--allow-unverified', '--focus', 'noise', '--json'])).toBe(0);
    const run = JSON.parse(stdout);
    expect(run.branch).toBe('minotaur/fixes');
    expect(run.results.map((result: { finding: { kind: string }; status: string }) => `${result.finding.kind}:${result.status}`).sort()).toEqual([
      'sast:committed_unverified',
      'secret:skipped',
    ]);
    expect(run.continue).toBeNull();
  });

  it('leaves out findings a person closed', async () => {
    const sql = (await scanJson()).findings.find((finding) => finding.kind === 'sast')!;
    expect(await main(['mark', sql.id, 'false-positive', root, ...sources(), '--reason', 'test'])).toBe(0);
    stdout = '';
    expect(await main(['fix', '--all', root, ...sources(), ...model(), '--focus', 'noise', '--json'])).toBe(0);
    const run = JSON.parse(stdout);
    expect(run.results.map((result: { finding: { kind: string } }) => result.finding.kind)).toEqual(['secret']);
    expect(requests).toHaveLength(0);
  });

  it('stops at the cap with exit code 3 when there is no terminal to ask, and says how to continue', async () => {
    vi.stubEnv('MINOTAUR_PRICE_INPUT_PER_MTOK', '3');
    vi.stubEnv('MINOTAUR_PRICE_OUTPUT_PER_MTOK', '15');
    script = fixCalls();
    expect(await main(['fix', '--all', root, ...sources(), ...model(), '--focus', 'noise', '--max-total-usd', '0.01', '--json'])).toBe(3);
    const run = JSON.parse(stdout);
    expect(run.stoppedAtCap).toBe(true);
    expect(run.results.map((result: { status: string }) => result.status)).toContain('stopped_at_cap');
    expect(run.continue).toMatch(/^minotaur fix --all .* --commit [0-9a-f]{40}$/);
    expect(requests).toHaveLength(0);
  });

  it('rejects flags that contradict each other', async () => {
    await expect(main(['fix', '--all', 'abcd1234', root])).rejects.toThrow('no finding ids');
    await expect(main(['fix', 'abcd1234', '--verify', '--discard'])).rejects.toThrow('use one');
    await expect(main(['fix'])).rejects.toThrow('or --all');
  });
});

describe('agent fix loop', () => {
  const SAFE_LINE = "  const sql = 'SELECT * FROM Users WHERE email = ?';";
  const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });

  beforeEach(() => {
    for (const name of ['AUTHOR', 'COMMITTER']) {
      vi.stubEnv(`GIT_${name}_NAME`, 't');
      vi.stubEnv(`GIT_${name}_EMAIL`, 't@t');
    }
  });

  async function briefFix(id: string): Promise<{ tree: string; branch: string; verify: string; finding: string; notes: string[]; instructions: string }> {
    stdout = '';
    expect(await main(['brief', id, root, ...sources(), '--fix', '--json'])).toBe(0);
    const parsed = JSON.parse(stdout);
    stdout = '';
    return parsed;
  }

  it('gives a worktree, keeps the edits across briefs, and commits what passes', async () => {
    const sql = (await scanJson()).findings.find((finding) => finding.kind === 'sast')!;
    const first = await briefFix(sql.id);
    expect(first.branch).toBe('minotaur/fixes');
    expect(first.instructions).toContain('Do not commit');
    expect(first.verify).toContain('--verify');
    const file = join(first.tree, 'routes', 'login.js');
    await writeFile(file, (await readFile(file, 'utf8')).replace(QUERY_LINE, SAFE_LINE));
    expect((await briefFix(sql.id)).tree).toBe(first.tree);
    expect(await readFile(file, 'utf8')).toContain(SAFE_LINE);

    // Report files cannot run again, so the fix is only committed when that is allowed.
    expect(await main(['fix', sql.id, root, ...sources(), '--verify', '--json'])).toBe(1);
    expect(JSON.parse(stdout)).toMatchObject({ status: 'unverified', tree: first.tree });
    stdout = '';
    expect(await main(['fix', sql.id, root, ...sources(), '--verify', '--allow-unverified', '--agent', 'test', '--message', 'Placeholder for the email.', '--json'])).toBe(0);
    expect(JSON.parse(stdout)).toMatchObject({ status: 'committed_unverified', model: 'agent:test', changedFiles: ['routes/login.js'], tree: null });
    const message = git('log', '-1', '--format=%B', first.branch);
    expect(message).toContain('Placeholder for the email.');
    expect(message).toContain('Minotaur-Fixed-By: agent:test');
    expect(git('worktree', 'list')).not.toContain('worktrees');
    expect(await readFile(join(root, 'routes', 'login.js'), 'utf8')).toContain(QUERY_LINE);
  });

  it('keeps a secret out of the brief and says to rotate it', async () => {
    const secret = (await scanJson()).findings.find((finding) => finding.kind === 'secret')!;
    const brief = await briefFix(secret.id);
    expect(JSON.stringify(brief)).not.toContain(SECRET);
    expect(brief.finding).toContain('Do not print, copy, log or repeat');
    expect(brief.notes.join(' ')).toContain('rotate it');
  });

  it('discards the worktree and the empty branch', async () => {
    const sql = (await scanJson()).findings.find((finding) => finding.kind === 'sast')!;
    await briefFix(sql.id);
    expect(await main(['fix', sql.id, root, ...sources(), '--discard'])).toBe(0);
    expect(stdout).toContain(`Removed the edits for ${sql.id} and the empty branch minotaur/fixes`);
    expect(git('branch', '--list', 'minotaur/*')).toBe('');
  });

  it('asks for a brief before verifying', async () => {
    const sql = (await scanJson()).findings.find((finding) => finding.kind === 'sast')!;
    await expect(main(['fix', sql.id, root, ...sources(), '--verify'])).rejects.toThrow('--fix --json" first');
  });
});

describe('fixes on branches', () => {
  const SAFE_LINE = "  const sql = 'SELECT * FROM Users WHERE email = ?';";
  const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });

  beforeEach(() => {
    for (const name of ['AUTHOR', 'COMMITTER']) {
      vi.stubEnv(`GIT_${name}_NAME`, 't');
      vi.stubEnv(`GIT_${name}_EMAIL`, 't@t');
    }
  });

  it('shows a fix waiting on a branch in a later scan, until it is merged', async () => {
    const sql = (await scanJson()).findings.find((finding) => finding.kind === 'sast')!;
    script = [
      [{ name: 'replace_in_file', args: { path: 'routes/login.js', oldText: QUERY_LINE, newText: SAFE_LINE } }],
      [{ name: 'submit_fix', args: { outcome: 'fixed', summary: 'Placeholder.', notes: [] } }],
    ];
    expect(await main(['fix', sql.id, root, ...sources(), ...model(), '--allow-unverified'])).toBe(0);
    stdout = '';

    const after = (await scanJson()).findings as unknown as Array<{ id: string; fix: { branch: string; verified: boolean } | null }>;
    expect(after.find((finding) => finding.id === sql.id)!.fix).toMatchObject({ branch: 'minotaur/fixes', verified: false });
    expect(after.filter((finding) => finding.id !== sql.id).every((finding) => finding.fix === null)).toBe(true);

    expect(await main(['scan', root, ...sources()])).toBe(0);
    expect(stdout).toContain('⎇');
    expect(stdout).toContain('1 finding has a fix on branch minotaur/fixes, not merged yet');
    expect(stdout).toContain('git merge minotaur/fixes');

    git('merge', '-q', 'minotaur/fixes');
    stdout = '';
    // The report file is unchanged, so the finding is still listed; the fix is merged, so it is no longer pending.
    expect((await scanJson()).findings.every((finding) => (finding as { fix?: unknown }).fix === null)).toBe(true);
  });
});

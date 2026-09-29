# minotaur

`minotaur` lists what your security scanners found, sorts out the noise, and asks a model
whether a finding is exploitable. It runs on your machine with nothing else: no database, no
Docker, and no server. The model can be one you run yourself, or any provider your company
already approved, as long as it speaks the OpenAI chat API or is Anthropic.

It started as the command line of the Minotaur platform, and uses the same findings model,
fingerprints and exploitability agent, so a finding has the same id in both.

```bash
pnpm install
pnpm minotaur scan ~/code/shop                      # list findings
pnpm minotaur triage 3f9a1c2e ~/code/shop           # is this one exploitable?
pnpm minotaur mark 3f9a1c2e false-positive --reason "Test fixture"
```

Run `pnpm minotaur` on its own in a terminal to browse the findings in the current
repository. Use the arrow keys (or `j` and `k`) to move, Enter to open a finding, `t` to
check whether it is exploitable, `d` to dig deeper from an answer, `m` to mark it yourself,
`s` to change the lowest severity shown, `a` to show or hide the findings rated as noise or
marked closed, `r` to scan again, and `q` to quit.

A check runs in the background, so you can keep browsing. Pressing `t` on other findings
while one runs queues them, and they run one after the other; `t` on a queued finding takes
it out again. Ctrl+C stops the running check and clears the queue. A new scan with `r` skips
the cache and looks up the commit again, so on `HEAD` it picks up new commits and edits. It
keeps the filters, the selected finding and the checks from the session. When you quit, the
answers from the session are printed.

`pnpm build` produces a single file, `dist/minotaur.js`, that runs with plain `node`
anywhere.

## Requirements

Node 22 or newer, and pnpm 10 to build it. Git is used when the folder is a repository.

## Where findings come from

With nothing configured, `scan` runs Trivy for dependencies, secrets and configuration, and
Opengrep for code. When either is missing, it is downloaded the first time, into
`~/Library/Caches/minotaur` on macOS or `~/.cache/minotaur` on Linux (`MINOTAUR_CACHE_DIR`
changes that). Each download is pinned to a version and a SHA-256 checksum, and is not
unpacked or run if the checksum doesn't match. That is about 100 MB, and Trivy then fetches
its vulnerability database into its own cache, about 1.4 GB on disk. Any other supported
scanner on your `PATH` (Semgrep, Grype, OSV-Scanner, TruffleHog, Checkov) runs as well, and
an installed Trivy or Semgrep is used instead of a download.

Opengrep's rules are its fork of the Semgrep community rules, frozen in January 2025 and
licensed LGPL 2.1 with the Commons Clause, which forbids selling a product whose value
comes substantially from them.

Findings in files git ignores, such as dependencies, build output and caches, are left out
of the list, and `--include-ignored` shows them. Those files are still scanned, so a secret
found in one still keeps that file away from the model.

`scan` can also read reports you already have, which is how it fits into a CI pipeline:

```bash
pnpm minotaur scan . --source semgrep --source reports/trivy.json --source results.sarif
```

A report can be SARIF from any tool, or the native JSON of one of the scanners above, and
the format is detected. Each finding gets a short id, the first eight characters of its
fingerprint, which stays the same between runs and between a report and a live scan.
`--json` writes the list in a form `triage --findings` reads back, so a finding doesn't
have to be scanned twice. Otherwise `triage` re-runs the same sources to find it.

In a git repository, every command looks at one commit, `HEAD` unless `--commit` names
another (a hash, branch or tag), and says which one at the start. On `HEAD` with no
uncommitted changes, that is your working tree. Otherwise it is a clean copy of the commit,
kept in the cache folder, so uncommitted changes are left out, and so are installed
dependencies such as `node_modules`, which checks then cannot read. Minotaur says so when
that happens. `scan --json` records the commit, and `triage --findings` uses it.

The last scan of a commit is kept in the cache folder and reused for up to 24 hours while
the sources and scanners stay the same, and on the working tree the files git ignores too.
`--rescan` forces a fresh scan. The 24 hours exist because new vulnerabilities are published
even when the code stays the same. The cached scan is readable only by your user and never
stores the text of a secret. Outside git, every run scans.

A finished check is kept too, per commit, and reused on that commit as it is, with the same
model and effort. On a later commit it is reused on the same rule as the Minotaur platform, if every
file the agent read and every search it ran would come out the same, and from then on it
belongs to that commit too. A reused check costs nothing and says how old it is.
`--recheck` asks the model again. In the interactive view, checks that still apply show in
the list straight away, and `t` runs a fresh one.

Scanners run directly, **without the container sandbox the Minotaur platform uses**, with your
permissions and your network. An installed Semgrep uses the `p/default` rules, downloaded
from the Semgrep registry each run.

## Focus

Every finding is rated `likely` (likely an issue), `maybe` (worth a look) or `noise`
(likely noise), with the reasons, and the list is ordered likely first, then by risk. `scan`
and the interactive view hide the noise and say how much they hid. `--all` or `a` shows it,
and `--focus likely` shows only the likely ones. `--json` keeps every finding, with its
`focus`, `focusReasons` and `riskScore`, unless `--focus` is given.

Code findings from style, correctness, performance and portability rules are noise. Security
rules that only flag a pattern to review (the `audit` rules) are worth a look, and other
security rules are likely. Code in tests, fixtures, examples and docs goes one level down.
A dependency is likely when CISA lists it as exploited or its risk score says to act, and
otherwise worth a look. It is never noise. Secrets are always likely, except in test code.

The exploited list (CISA KEV) and the chance of exploitation (EPSS, from FIRST) are fetched
for the CVEs in the scan and kept in the cache folder for 24 hours. Only the CVE ids are sent.
Offline, the older copy is used, and without one, dependencies are rated on severity and CVSS
alone. Either way `scan` says so.

A team can correct the rating in `.minotaur.yml`, with globs on rule ids and paths. `keep`
wins over `noise`:

```yaml
focus:
  noise:
    rules: ["javascript.lang.security.audit.detect-non-literal-regexp"]
    paths: ["scripts/**"]
  keep:
    paths: ["src/payments/**"]
```

## Marking findings yourself

When you already know the answer, record it instead of asking a model. In the interactive
view, press `m` on a finding, pick false positive, accepted risk, fixed or confirmed, and type
why. From the command line:

```bash
pnpm minotaur mark 209cf080 false-positive --reason "Fake key in a scanner test fixture"
pnpm minotaur mark 209cf080 open      # undo
```

Decisions go to `.minotaur/decisions.yml`, keyed by the finding's fingerprint, with the title,
path, reason, who and when, so they read well in a pull request. Commit the file to share them.
Writing it does not count as an uncommitted change, so the run stays on your working tree.

False positives, accepted risks and fixed findings are hidden like noise: `--all` or `a` shows
them. A confirmed finding is rated likely and listed first. A secret marked a false positive no
longer keeps its file away from checks, as on the Minotaur platform, unless another secret is found in
it. Anyone who can change the file can lift that protection, so review it like code.

## Choosing the model

With Ollama, or any other server that speaks the OpenAI chat API:

```bash
ollama pull qwen3-coder
pnpm minotaur triage 3f9a1c2e . --model openai-compatible:qwen3-coder --base-url http://localhost:11434/v1
```

The same works for a company gateway in front of Bedrock or Azure OpenAI; put its key in
`MINOTAUR_API_KEY`. With Anthropic, `export ANTHROPIC_API_KEY=...` is enough, and the
default is `claude-opus-5-5` at medium effort.

Before anything is sent, `triage` prints where the code is going. Secret findings are never
triaged, and the agent cannot read `.env` files, key files, or any file a secret finding in
the same scan points at. Each check is capped at 30 model calls and $3. A model you run
yourself has no price, so give it a token cap with `--max-tokens` instead. `--json` writes
the answer to a file, and `--continue-from FILE` starts a new check from its open questions.

## `.minotaur.yml`

Settings a team shares go in `.minotaur.yml` at the repository root, and flags override
them. API keys are refused here, because the file is meant to be committed.

```yaml
sources:
  - scanner: semgrep
    args: ["--config", "p/owasp-top-ten"]
  - report: reports/trivy.json
model: openai-compatible:qwen3-coder
baseUrl: http://localhost:11434/v1
triage:
  maxSteps: 30
  maxTokens: 500000
```

| Variable | Meaning |
| --- | --- |
| `ANTHROPIC_API_KEY` | Key for `anthropic:` models. Never sent anywhere else. |
| `MINOTAUR_API_KEY` | Key for an `openai-compatible:` server, if it needs one. |
| `MINOTAUR_MODEL`, `MINOTAUR_BASE_URL` | Defaults when neither a flag nor `.minotaur.yml` sets them. |
| `MINOTAUR_PRICE_INPUT_PER_MTOK`, `MINOTAUR_PRICE_OUTPUT_PER_MTOK` | Price of a paid model Minotaur doesn't know, so the dollar cap works. |
| `MINOTAUR_CACHE_DIR` | Where downloaded scanners, rules, the last scans, finished checks and copies of commits are kept. |

## Layout

| Folder | What it holds |
| --- | --- |
| `src/` | The command itself: arguments, caches, commits, decisions, focus and output |
| `src/interactive/` | The terminal view, built with Ink |
| `src/core/` | The findings model, fingerprints, risk score and focus rating |
| `src/scanners/` | Scanner adapters, SARIF parsing and running scanners locally |
| `src/agent/` | The exploitability agent: tools, file access rules, prompts, budget and models |
| `src/feeds/` | The CISA KEV and FIRST EPSS feeds |

## Development

```bash
pnpm typecheck
pnpm test             # Vitest; no test calls a model provider or the network
pnpm test:coverage
pnpm build            # dist/minotaur.js
pnpm minotaur --help  # run from source
```

The end-to-end tests use a fake OpenAI-compatible server on localhost. The agent is tested
with the AI SDK's mock model, including path confinement, refused credential files, citation
checking and the spend cap.

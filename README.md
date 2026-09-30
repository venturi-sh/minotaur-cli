# minotaur

Run your security scanners, hide the noise, and ask a model whether a finding is exploitable.
Everything runs on your machine.

## Install

Needs Node 22, pnpm 10 and git. Minotaur only scans a git repository with at least one
commit. For a folder without git, make a snapshot first:

```bash
git init && git add -A && git commit -m snapshot
```

```bash
pnpm install
pnpm build            # dist/minotaur.js, runs with plain node
```

## Use

```bash
pnpm minotaur                                   # browse the findings in this repository
pnpm minotaur scan ~/code/shop                  # list findings
pnpm minotaur triage 3f9a1c2e ~/code/shop       # is this one exploitable?
pnpm minotaur mark 3f9a1c2e false-positive --reason "Test fixture"
```

In the browser, press `t` to check a finding, `m` to mark it, `a` to show hidden findings, `r`
to scan again and `q` to quit. The footer lists the other keys.

`minotaur --help` lists every option. It is also what an agent should read. The loop is
`scan --json --unchecked`, then `brief ID --json`, then `verdict ID --json`. No model key is
needed: the agent reads the code and submits the answer itself.

## How it works

**Scanning.** By default it runs Trivy and Opengrep, and downloads them the first time. It
also runs any other supported scanner you have installed, or reads reports you pass with
`--source`. It scans `HEAD`, or the commit you give with `--commit`, and caches the scan for
24 hours.

**Focus.** Findings are rated likely, maybe or noise. Style rules, test code and similar noise
are hidden. Dependencies are ranked with CISA's exploited list and EPSS scores.

**Checks.** A model reads the code around a finding and answers exploitable, not exploitable
or undetermined, and cites the code it used. Each check is capped at 30 steps and $3.

**Decisions.** `mark` records your own answer in `.minotaur/decisions.yml`. Commit that file
to share your decisions with your team.

## Model

Use Anthropic:

```bash
export ANTHROPIC_API_KEY=...
```

Or any server that speaks the OpenAI chat API, such as Ollama:

```bash
pnpm minotaur triage 3f9a1c2e --model openai-compatible:qwen3-coder --base-url http://localhost:11434/v1
```

Shared settings go in `.minotaur.yml` at the repository root. API keys go only in environment
variables.

## Safety

- Secrets are never sent to the model, and neither are files that contain a secret, `.env`
  files or key files.
- Scanners run directly on your machine, with your permissions. There is no sandbox.
- A secret marked a false positive can be read by checks, so review changes to the decisions
  file like code.

## Develop

```bash
pnpm typecheck
pnpm test
```

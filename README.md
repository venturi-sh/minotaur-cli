# minotaur

Run your security scanners, hide the noise, ask a model whether a finding is exploitable, and
fix it on a branch. Everything runs on your machine.

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
pnpm minotaur fix 3f9a1c2e                      # fix it on the branch minotaur/fix-3f9a1c2e
pnpm minotaur fix --all                         # fix everything scan lists, one commit each
```

In the browser, press `t` to check a finding, `f` to fix it, `F` to fix all findings shown (the footer shows how many), `m`
to mark it, `a` to show hidden findings, `r` to scan again and `q` to quit. The footer lists the
other keys.

`minotaur --help` lists every option. It is also what an agent should read. The loop is
`scan --json --unchecked`, then `brief ID --json`, then `verdict ID --json`. No model key is
needed: the agent reads the code and submits the answer itself. To fix a finding, the loop is
`brief ID --fix --json`, the agent edits the worktree it names, then `fix ID --verify`.

## How it works

**Scanning.** By default it runs Trivy and Opengrep, and downloads them the first time. It
also runs any other supported scanner you have installed, or reads reports you pass with
`--source`. It scans `HEAD`, or the commit you give with `--commit`, and caches the scan for
24 hours.

**Focus.** Findings are rated likely, maybe or noise. Style rules, test code and similar noise
are hidden. Dependencies are ranked with CISA's exploited list and EPSS scores.

**Checks.** A model reads the code around a finding and answers exploitable, not exploitable
or undetermined, and cites the code it used. Each check is capped at 30 steps and $3.

**Fixes.** `fix` never changes your working tree. It makes a git worktree from the scanned commit
in the cache, and commits each fix on the branch `minotaur/fix-ID`, or `minotaur/fixes-COMMIT`
for several findings. You review the branch and merge it.

- Code and configuration findings are fixed by the model. It can read and edit files, but not
  credential files, git files, scanner ignore files, lockfiles or Minotaur's own settings.
- A dependency with a known fixed version is upgraded by npm, pnpm, go or cargo, or in a pinned
  `requirements*.txt`, without a model. A dependency that the project does not declare gets an
  override. If the package manager cannot do it, the model changes the manifest and the package
  manager updates the lockfile. Other lockfiles, such as `yarn.lock` or `poetry.lock`, are not
  supported yet.
- Secrets are never fixed by the model. An agent can remove one with `brief ID --fix`, but you
  must rotate the credential, because git history still has it.

A fix is committed only when the scanners that reported the finding run again and all of these
are true: the finding is gone, the changed files have no new finding as severe, and the change
does not silence the scanner (for example with `nosemgrep`). A fix that fails gets one more
attempt, with the scanner's result. A finding from a report file cannot be rescanned, so its fix
is not committed unless you add `--allow-unverified`.

Each finding has the same limits as a check. A run of several fixes also has a cap for the
whole run, $10 by default (`--max-total-usd`). At the cap, Minotaur asks whether to spend as
much again. Without a terminal, it stops with exit code 3 and prints the `--resume` command.

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
- `brief ID --fix` for a secret gives your agent a worktree that contains the credential. The
  brief itself does not contain it. Use this only with an agent you trust with the credential.
- `fix` runs package managers with their scripts turned off. They connect to their registries.
- The model writes code that you merge. Review each fix branch like any other change.
- A secret marked a false positive can be read by checks, so review changes to the decisions
  file like code.

## Develop

```bash
pnpm typecheck
pnpm test
```

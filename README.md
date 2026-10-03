<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo-light.png">
  <img alt="Minotaur" src="assets/logo-dark.png" width="440">
</picture>

</div>

# minotaur-cli

Minotaur is a CLI tool designed to be easily used by either a human or an agent to surface exploitable security issues.

It relies on existing security scanners like trivy or opengrep (configurable) and hands over exploitabililty checks to a LLM (also configurable).

The simplest way to use it is to hand it over to an LLM directly, allowing you to rely on subscription usage.

e.g.

```
Use the minotaur cli to find critical potential security vulnerabilities and determine their exploitability.
```

you can then browse the results using the TUI by simply running the `minotaur` command.

Alternatively, you can plug into an LLM API by either setting an API_KEY or using oauth for Anthropic with `minotaur auth login`.

## Install

```bash
npm install -g minotaur-cli     # installs the `minotaur` command
```

## Requirements

- node
- git

Minotaur only scans a git repository with at least one commit. If the folder is not one, it
offers to make a repository and commit a snapshot. You can also do that yourself:

```bash
git init && git add -A && git commit -m snapshot
```

## Use

```bash
minotaur                                   # browse the findings in this repository
minotaur config                            # choose scanners and a model, write .minotaur.yml
minotaur ~/code/shop                       # the same, in that repository
minotaur scan ~/code/shop                  # list findings
minotaur triage 3f9a1c2e ~/code/shop       # is this one exploitable?
minotaur mark 3f9a1c2e false-positive --reason "Test fixture"
```

In the browser, press `t` to check a finding, `m` to mark it, `a` to show hidden findings,
`r` to scan again and `q` to quit. The footer lists the other keys.

`minotaur --help` lists every option. It is also what an agent should read. The loop is
`scan --json --unchecked`, then `brief ID --json`, then `verdict ID --json`. No model key is
needed: the agent reads the code and submits the answer itself.

## How it works

**Scanning.** By default it runs Trivy and Opengrep, and downloads them the first time. It
also runs any other supported scanner you have installed, or reads reports you pass with
`--source`. It scans `HEAD`, or the commit you give with `--commit`, never the working
tree, and caches the scan for 24 hours.

**Focus.** Findings are rated likely, maybe or noise. Style rules, test code and similar noise
are hidden. Dependencies are ranked with CISA's exploited list and EPSS scores.

**Checks.** A model reads the code around a finding and answers exploitable, not exploitable
or undetermined, and cites the code it used. Each check is capped at 30 steps and $3.

**Decisions.** `mark` records your own answer in `.minotaur/decisions.yml`. Commit that file
to share your decisions with your team.

## Model

Use Anthropic with an API key:

```bash
export ANTHROPIC_API_KEY=...
```

Or sign in. `minotaur auth login` shows a list of providers. Anthropic uses the Claude Console
through `ant`, and offers to install `ant` when it is missing. OpenAI asks for an API key and
stores it outside the repository. An environment key always wins.

```bash
minotaur auth login anthropic
minotaur auth login openai
```

Or call OpenAI by name:

```bash
minotaur triage 3f9a1c2e --model openai:gpt-5.4
```

Or any server that speaks the OpenAI chat API, such as Ollama:

```bash
minotaur triage 3f9a1c2e --model openai-compatible:qwen3-coder --base-url http://localhost:11434/v1
```

`minotaur config` asks which scanners to run and which model to use, and writes them to
`.minotaur.yml` at the repository root. If Trivy or Opengrep is missing, it offers to download
them. On macOS, if Homebrew is installed, it offers to install the other scanners with it. API
keys go only in environment variables. A Console login is stored by the `ant` command, and an
OpenAI key by `minotaur auth login openai`, not in the repository.

## Safety

- Secrets are never sent to the model, and neither are files that contain a secret, `.env`
  files or key files.
- Scanners run directly on your machine, with your permissions. There is no sandbox.
- A secret marked a false positive can be read by checks, so review changes to the decisions
  file like code.

## Develop

Needs pnpm 10.

```bash
pnpm install
pnpm minotaur --help  # runs from source
pnpm typecheck
pnpm test
pnpm build            # dist/minotaur.js, one file that runs with plain node
```

## License

MIT. See [LICENSE](LICENSE).

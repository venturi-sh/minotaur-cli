/**
 * `minotaur config`: pick scanners and a model, then write `.minotaur.yml`.
 *
 * Ink draws the questions. The choices themselves are applied in `configure.ts`,
 * so a test can record a file without a terminal.
 */

import { MultiSelect, Select, TextInput } from '@inkjs/ui';
import { Box, Text, render, useApp } from 'ink';
import { useEffect, useRef, useState } from 'react';

import type { Env } from './auth.js';
import { loadConfig, type Config } from './config.js';
import {
  anthropicModels,
  anthropicReady,
  applyChoices,
  configuredModel,
  initialScanners,
  installMissing,
  installWithBrew,
  missingScanners,
  nameList,
  renderConfig,
  requireBaseUrl,
  requireModelId,
  saveConfig,
  scannerChoices,
  type ConfigChoices,
} from './configure.js';
import { installedScanners, isInstalled } from './scanners/index.js';
import { defaultSources } from './sources.js';

export interface WizardOutcome {
  choices: ConfigChoices;
  /** True when the person asked to start the Claude Console login after the file is written. */
  signIn: boolean;
  /** Managed scanners to download, when they asked. */
  install: readonly string[];
  /** Scanners to install with Homebrew, when they asked. */
  brew: readonly string[];
  /** Chosen scanners that are not on PATH and that this machine cannot install. */
  separate: readonly string[];
}

export interface AskConfigOptions {
  config: Config;
  installed: ReadonlySet<string>;
  /** Pre-checked when the file lists no scanners. The same set a scan would run. */
  fallbackScanners: readonly string[];
  anthropicReady: boolean;
  /** True on a Mac where `brew` is on PATH. Missing scanners can then be installed with Homebrew. */
  canBrew?: boolean;
  input?: NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?: (raw: boolean) => unknown };
  output?: NodeJS.WritableStream & { columns?: number; rows?: number };
}

type Step = 'sources' | 'install' | 'brew' | 'provider' | 'anthropic' | 'local-model' | 'local-url' | 'confirm' | 'login';

export function askConfig(options: AskConfigOptions): Promise<WizardOutcome | null> {
  let outcome: WizardOutcome | null = null;
  let finished = false;
  const instance = render(<Wizard options={options} onFinish={(value) => ((outcome = value), (finished = true))} />, {
    exitOnCtrlC: true,
    patchConsole: false,
    interactive: true,
    ...(options.input ? { stdin: options.input as NodeJS.ReadStream } : {}),
    ...(options.output ? { stdout: options.output as NodeJS.WriteStream } : {}),
  });
  return instance.waitUntilExit().then(() => (finished ? outcome : null));
}

export async function configureRepository(options: {
  root: string;
  env?: Env;
  login?: () => Promise<number>;
  answers?: ConfigChoices;
  signIn?: boolean;
  /** Managed scanners to download when `answers` is set. The wizard decides this itself. */
  install?: readonly string[];
  installScanners?: (names: readonly string[]) => Promise<void>;
  /** Scanners to install with Homebrew when `answers` is set. */
  brew?: readonly string[];
  brewInstall?: (formulas: readonly string[]) => Promise<number>;
  /** When set, used instead of looking for Homebrew on a Mac. */
  canBrew?: boolean;
  anthropicReady?: boolean;
  input?: AskConfigOptions['input'];
  output?: AskConfigOptions['output'];
}): Promise<number> {
  const env = options.env ?? process.env;
  const { config } = await loadConfig(options.root);
  const ready = options.anthropicReady ?? (await anthropicReady(env));
  const canBrew = options.canBrew ?? (process.platform === 'darwin' && (await isInstalled('brew')));
  const outcome = options.answers
    ? { choices: options.answers, signIn: options.signIn ?? false, install: options.install ?? [], brew: options.brew ?? [], separate: [] as readonly string[] }
    : await askConfig({
        config,
        installed: new Set((await installedScanners()).map((scanner) => scanner.name)),
        fallbackScanners: (config.sources ?? []).some((source) => 'scanner' in source)
          ? []
          : (await defaultSources(options.root)).flatMap((source) => ('scanner' in source ? [source.scanner] : [])),
        anthropicReady: ready,
        canBrew,
        ...(options.input ? { input: options.input } : {}),
        ...(options.output ? { output: options.output } : {}),
      });
  if (!outcome) {
    process.stderr.write('Left .minotaur.yml unchanged.\n');
    return 0;
  }

  const path = await saveConfig(options.root, applyChoices(config, outcome.choices));
  process.stdout.write(`Wrote ${path}\n`);
  const toInstall = outcome.install;
  if (toInstall.length > 0) {
    try {
      await (options.installScanners ?? ((names: readonly string[]) => installMissing(names)))(toInstall);
      for (const name of toInstall) process.stderr.write(`Installed ${name}.\n`);
    } catch (error) {
      process.stderr.write(`${(error as Error).message}\n`);
      return 1;
    }
  }
  if (outcome.brew.length > 0) {
    try {
      await installWithBrew(outcome.brew, options.brewInstall);
      process.stderr.write(`Installed ${nameList(outcome.brew)} with Homebrew.\n`);
    } catch (error) {
      process.stderr.write(`${(error as Error).message}\n`);
      return 1;
    }
  }
  const separate = outcome.separate;
  if (separate.length > 0) {
    const pronoun = separate.length === 1 ? 'it' : 'them';
    process.stderr.write(`${nameList(separate)} ${separate.length === 1 ? 'is' : 'are'} not installed. Minotaur cannot download ${pronoun}.\n`);
  }
  if (outcome.choices.provider === 'anthropic' && !ready) {
    if (outcome.signIn) return (options.login ?? (async () => 0))();
    process.stderr.write('Set ANTHROPIC_API_KEY, or run minotaur auth login, before a check or a fix.\n');
  }
  if (outcome.choices.provider === 'openai-compatible' && !env['MINOTAUR_API_KEY']) {
    process.stderr.write('If that server needs a key, set MINOTAUR_API_KEY. It is not written to the file.\n');
  }
  return 0;
}

function Wizard({ options, onFinish }: { options: AskConfigOptions; onFinish: (outcome: WizardOutcome | null) => void }) {
  const { exit } = useApp();
  const [step, setStep] = useState<Step>('sources');
  const [error, setError] = useState<string | null>(null);
  const [scanners, setScanners] = useState<string[]>([]);
  const [modelId, setModelId] = useState<string | undefined>();
  const [choices, setChoices] = useState<ConfigChoices | null>(null);
  const [pending, setPending] = useState<string[]>([]);
  const [pendingBrew, setPendingBrew] = useState<string[]>([]);
  const [install, setInstall] = useState<string[]>([]);
  const [brew, setBrew] = useState<string[]>([]);
  const [separate, setSeparate] = useState<string[]>([]);
  const held = useRef(false);

  useEffect(() => {
    held.current = false;
  }, [step]);

  function finish(outcome: WizardOutcome | null): void {
    if (held.current) return;
    held.current = true;
    onFinish(outcome);
    exit();
  }

  function advance(next: Step, run: () => void): void {
    if (held.current) return;
    held.current = true;
    setError(null);
    run();
    setStep(next);
  }

  const reports = (options.config.sources ?? []).flatMap((source) => ('report' in source ? [source.report] : []));
  const current = configuredModel(options.config);
  const preferred = anthropicModels()[0] ?? 'claude-sonnet-5';

  return (
    <Box flexDirection="column">
      {step === 'sources' && (
        <Box flexDirection="column">
          <Text>Which scanners should Minotaur run?</Text>
          <Text dimColor>Space selects, enter continues.</Text>
          {reports.length > 0 && <Text>Report files already in .minotaur.yml stay: {reports.join(', ')}</Text>}
          {error && <Text color="red">{error}</Text>}
          <MultiSelect
            visibleOptionCount={scannerChoices(options.installed, options.canBrew ?? false).length}
            options={scannerChoices(options.installed, options.canBrew ?? false).map((choice) => ({ label: choice.label, value: choice.name }))}
            defaultValue={initialScanners(options.config, options.fallbackScanners)}
            onSubmit={(values) => {
              if (values.length === 0) {
                setError('Pick at least one scanner.');
                return;
              }
              const missing = missingScanners(values, options.installed, options.canBrew ?? false);
              const next = missing.download.length > 0 ? 'install' : missing.brew.length > 0 ? 'brew' : 'provider';
              advance(next, () => {
                setScanners(values);
                setPending(missing.download);
                setPendingBrew(missing.brew);
                setSeparate(missing.separate);
                if (missing.download.length === 0) setInstall([]);
                if (missing.brew.length === 0) setBrew([]);
              });
            }}
          />
        </Box>
      )}
      {step === 'install' && (
        <Box flexDirection="column">
          <Text>
            {nameList(pending)} {pending.length === 1 ? 'is' : 'are'} not installed. Download {pending.length === 1 ? 'it' : 'them'} now?
          </Text>
          {separate.length > 0 && (
            <Text>
              {nameList(separate)} must be installed separately. Minotaur cannot download {separate.length === 1 ? 'it' : 'them'}.
            </Text>
          )}
          <Text dimColor>Enter chooses the highlighted one.</Text>
          <Select
            visibleOptionCount={2}
            options={[
              { label: `Download ${nameList(pending)}`, value: 'yes' },
              { label: 'Not now', value: 'no' },
            ]}
            onChange={(value) => {
              const chosen = value === 'yes' ? pending : [];
              const next = pendingBrew.length > 0 ? 'brew' : 'provider';
              advance(next, () => setInstall(chosen));
            }}
          />
        </Box>
      )}
      {step === 'brew' && (
        <Box flexDirection="column">
          <Text>
            {nameList(pendingBrew)} {pendingBrew.length === 1 ? 'is' : 'are'} not installed. Install {pendingBrew.length === 1 ? 'it' : 'them'} with Homebrew?
          </Text>
          <Text dimColor>Enter chooses the highlighted one.</Text>
          <Select
            visibleOptionCount={2}
            options={[
              { label: `Install ${nameList(pendingBrew)} with Homebrew`, value: 'yes' },
              { label: 'Not now', value: 'no' },
            ]}
            onChange={(value) => advance('provider', () => setBrew(value === 'yes' ? pendingBrew : []))}
          />
        </Box>
      )}
      {step === 'provider' && (
        <Box flexDirection="column">
          <Text>
            {current
              ? `Model in .minotaur.yml now: ${current.provider}:${current.modelId}${options.config.baseUrl ? ` at ${options.config.baseUrl}` : ''}`
              : 'No model is set in .minotaur.yml yet.'}
          </Text>
          <Text>Which model should checks and fixes use?</Text>
          <Text dimColor>Enter chooses the highlighted one.</Text>
          <Select
            visibleOptionCount={3}
            options={[
              { label: 'Anthropic', value: 'anthropic' },
              { label: 'A server you run (OpenAI-compatible API)', value: 'openai-compatible' },
              { label: 'Don\'t record a model (MINOTAUR_MODEL still applies)', value: 'unset' },
            ]}
            onChange={(value) => {
              if (value === 'anthropic') advance('anthropic', () => undefined);
              else if (value === 'openai-compatible') advance('local-model', () => undefined);
              else advance('confirm', () => setChoices({ scanners, provider: 'unset' }));
            }}
          />
        </Box>
      )}
      {step === 'anthropic' && (
        <Box flexDirection="column">
          <Text>Which Anthropic model?</Text>
          <Text dimColor>Enter chooses the highlighted one.</Text>
          <Select
            visibleOptionCount={anthropicModels().length}
            options={modelOptions(current?.provider === 'anthropic' ? current.modelId : null, preferred)}
            onChange={(value) => advance('confirm', () => setChoices({ scanners, provider: 'anthropic', modelId: value }))}
          />
        </Box>
      )}
      {step === 'local-model' && (
        <Box flexDirection="column">
          <Text>Model name on that server</Text>
          {error && <Text color="red">{error}</Text>}
          <TextInput
            defaultValue={current?.provider === 'openai-compatible' ? current.modelId : 'qwen3-coder'}
            onSubmit={(value) => {
              try {
                const id = requireModelId('openai-compatible', value);
                advance('local-url', () => setModelId(id));
              } catch (caught) {
                setError((caught as Error).message);
              }
            }}
          />
        </Box>
      )}
      {step === 'local-url' && (
        <Box flexDirection="column">
          <Text>Address of the server. Ollama is http://localhost:11434/v1</Text>
          {error && <Text color="red">{error}</Text>}
          <TextInput
            defaultValue={options.config.baseUrl ?? 'http://localhost:11434/v1'}
            onSubmit={(value) => {
              try {
                const url = requireBaseUrl(value);
                advance('confirm', () =>
                  setChoices({ scanners, provider: 'openai-compatible', ...(modelId ? { modelId } : {}), baseUrl: url }),
                );
              } catch (caught) {
                setError((caught as Error).message);
              }
            }}
          />
        </Box>
      )}
      {(step === 'confirm' || step === 'login') && choices && (
        <Box flexDirection="column">
          <Text>Write this to .minotaur.yml?</Text>
          {previewLines(options.config, choices).map((line, index) => (
            <Text key={index} dimColor>
              {line.length > 0 ? line : ' '}
            </Text>
          ))}
          {separate.length > 0 && (
            <Text>
              {nameList(separate)} {separate.length === 1 ? 'is' : 'are'} not installed, and Minotaur cannot download {separate.length === 1 ? 'it' : 'them'}.
            </Text>
          )}
          {step === 'confirm' && (
            <Select
              visibleOptionCount={2}
              options={[
                { label: 'Write .minotaur.yml', value: 'write' },
                { label: 'Cancel', value: 'cancel' },
              ]}
              onChange={(value) => {
                if (value === 'cancel') finish(null);
                else if (choices.provider === 'anthropic' && !options.anthropicReady) advance('login', () => undefined);
                else finish({ choices, signIn: false, install, brew, separate });
              }}
            />
          )}
          {step === 'login' && (
            <Box flexDirection="column">
              <Text>Anthropic needs an API key or a Console login. Sign in now?</Text>
              <Select
                visibleOptionCount={2}
                options={[
                  { label: 'Not now', value: 'no' },
                  { label: 'Sign in to the Claude Console', value: 'yes' },
                ]}
                onChange={(value) => finish({ choices, signIn: value === 'yes', install, brew, separate })}
              />
            </Box>
          )}
        </Box>
      )}
    </Box>
  );
}

function modelOptions(current: string | null, preferred: string): { label: string; value: string }[] {
  const models = anthropicModels();
  const ordered = current && models.includes(current) ? [current, ...models.filter((id) => id !== current)] : models;
  return ordered.map((id) => ({ value: id, label: id === preferred ? `${id}  (default)` : id }));
}

function previewLines(config: Config, choices: ConfigChoices): string[] {
  try {
    return renderConfig(applyChoices(config, choices)).split('\n');
  } catch (error) {
    return [(error as Error).message];
  }
}

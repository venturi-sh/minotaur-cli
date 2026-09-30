/**
 * The tools the agents work with, all going through the confined workspace.
 * The triage agent only reads; the fix agent can also edit.
 */

import { tool, type ToolSet } from 'ai';
import { z } from 'zod';

import { exploitVerdictSchema, triageVerdictSchema, type AssessmentMode } from '../core/index.js';

import { fixSubmissionSchema } from './fix-schema.js';
import { WorkspaceAccessError, type Workspace } from './workspace.js';

/** Tool failures go back to the model as data, so a bad path costs a step rather than the run. */
async function guarded<T>(run: () => Promise<T>): Promise<T | { error: string }> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof WorkspaceAccessError) return { error: error.message };
    return { error: `failed: ${(error as Error).message}` };
  }
}

function readTools(workspace: Workspace): ToolSet {
  return {
    read_file: tool({
      description:
        'Read a file from the repository, with line numbers. Paths are relative to the repository root. Read a line range for large files.',
      inputSchema: z.object({
        path: z.string().describe('Relative path, such as src/app.ts'),
        startLine: z.number().int().positive().optional(),
        endLine: z.number().int().positive().optional(),
      }),
      execute: ({ path, startLine, endLine }) => guarded(() => workspace.readFile(path, { startLine, endLine })),
    }),
    grep: tool({
      description:
        'Search file contents with a JavaScript regular expression, one line at a time. Installed dependencies and build output are skipped unless pathContains names one of their directories, such as .venv/, site-packages/ or node_modules/lodash/. Returns matching lines with their paths and line numbers.',
      inputSchema: z.object({
        pattern: z.string().min(1),
        pathContains: z
          .string()
          .optional()
          .describe('Only search paths containing this text, such as src/, .py, or site-packages/aiohttp/ to search inside a dependency'),
        ignoreCase: z.boolean().optional(),
      }),
      execute: ({ pattern, pathContains, ignoreCase }) =>
        guarded(() => workspace.grep(pattern, { pathContains, ignoreCase })),
    }),
    list_dir: tool({
      description: 'List a directory in the repository. Use "." for the root.',
      inputSchema: z.object({ path: z.string() }),
      execute: ({ path }) => guarded(() => workspace.listDir(path)),
    }),
  };
}

export function triageTools(workspace: Workspace, mode: AssessmentMode = 'triage'): ToolSet {
  return {
    ...readTools(workspace),
    submit_verdict:
      mode === 'exploit'
        ? tool({
            description: 'Submit the exploitability answer. Call this exactly once, when you are done investigating.',
            inputSchema: exploitVerdictSchema,
            execute: async () => ({ received: true }),
          })
        : tool({
            description: 'Submit the final verdict. Call this exactly once, when you are done investigating.',
            inputSchema: triageVerdictSchema,
            execute: async () => ({ received: true }),
          }),
  };
}

export function fixTools(workspace: Workspace): ToolSet {
  return {
    ...readTools(workspace),
    replace_in_file: tool({
      description:
        'Replace one exact piece of text in a file. oldText must occur exactly once: copy it from read_file output without the line-number prefixes, with enough surrounding lines to make it unique.',
      inputSchema: z.object({
        path: z.string().describe('Relative path, such as src/app.ts'),
        oldText: z.string().min(1),
        newText: z.string(),
      }),
      execute: ({ path, oldText, newText }) => guarded(() => workspace.replaceInFile(path, oldText, newText)),
    }),
    write_file: tool({
      description: 'Write a whole file, creating it if missing. Use for a new file; edit an existing file with replace_in_file.',
      inputSchema: z.object({ path: z.string(), content: z.string() }),
      execute: ({ path, content }) => guarded(() => workspace.writeFile(path, content)),
    }),
    submit_fix: tool({
      description: 'Submit the result. Call this exactly once, when the fix is complete or you decide it cannot be done safely.',
      inputSchema: fixSubmissionSchema,
      execute: async () => ({ received: true }),
    }),
  };
}

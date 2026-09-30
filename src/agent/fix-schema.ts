import { z } from 'zod';

/** What the fix agent submits. The change itself is in the files it edited. */
export const fixSubmissionSchema = z.object({
  outcome: z.enum(['fixed', 'gave_up']),
  /** What changed and why it removes the vulnerability, or why no safe fix was possible. */
  summary: z.string().min(1),
  /** What a reviewer should check, such as a behaviour change or a new dependency. */
  notes: z.array(z.string().min(1)).default([]),
});
export type FixSubmission = z.infer<typeof fixSubmissionSchema>;

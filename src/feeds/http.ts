/**
 * Fetching the published CISA and FIRST feeds. No third-party code runs, and
 * every response is parsed through a Zod schema before it is used.
 */

const USER_AGENT = 'minotaur-cli/0.1';

export interface FetchOptions {
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 120_000;

export async function fetchOk(url: string, options: FetchOptions = {}): Promise<Response> {
  const response = await fetch(url, {
    headers: { 'user-agent': USER_AGENT, accept: '*/*' },
    redirect: 'follow',
    signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new Error(`GET ${url} returned ${response.status} ${response.statusText}`);
  }
  if (response.body === null) {
    throw new Error(`GET ${url} returned no body`);
  }

  return response;
}

// Entry point for the forge service.
//
// The harness that embeds this service passes its control address in
// MAKEFUN_ENV_URL. The lifecycle here is deliberately small: build the
// app, bind an ephemeral port, announce that port to the harness, wait
// until the harness reports the run is done, then shut down cleanly.

import { createApp } from './app.ts';

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

// POST our port to $MAKEFUN_ENV_URL/register. A 200 or 409 means the
// harness knows us; 400/405 are fatal; anything else (including a refused
// connection while the harness is still starting) is retried with
// backoff for up to thirty seconds.
async function registerWithHarness(envUrl: string, port: number): Promise<void> {
  const deadline = Date.now() + 30_000;
  let delay = 250;
  for (;;) {
    let refused = false;
    try {
      const response = await fetch(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
      });
      await response.text().catch(() => '');
      if (response.status === 200 || response.status === 409) return;
      if (response.status === 400 || response.status === 405) refused = true;
    } catch {
      // Harness not reachable yet — fall through to the retry delay.
    }
    if (refused) throw new Error('harness refused the registration request');
    if (Date.now() >= deadline) throw new Error('timed out registering with the harness');
    await sleep(delay);
    delay = Math.min(delay * 2, 2_000);
  }
}

// Poll $MAKEFUN_ENV_URL/done until the harness says the run is over.
async function waitForHarnessDone(envUrl: string): Promise<void> {
  for (;;) {
    try {
      const response = await fetch(`${envUrl}/done`);
      if (response.ok) {
        const payload = (await response.json()) as { done?: unknown };
        if (payload.done === true) return;
      }
    } catch {
      // Transient failure — keep polling.
    }
    await sleep(250);
  }
}

async function main(): Promise<void> {
  const envUrl = process.env.MAKEFUN_ENV_URL;
  if (!envUrl) {
    console.error('MAKEFUN_ENV_URL is not set; nowhere to register');
    process.exit(1);
  }

  const server = createApp();

  // If the harness stops us mid-run, close the listener and exit instead
  // of dying with client sockets half-open.
  const shutdown = (): void => {
    server.closeAllConnections?.();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1_000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    console.error('server did not bind a TCP port');
    process.exit(1);
  }

  await registerWithHarness(envUrl, address.port);
  await waitForHarnessDone(envUrl);
  // Drain any keep-alive sockets the harness is still holding so close()
  // resolves promptly instead of waiting for them to time out.
  server.closeAllConnections?.();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

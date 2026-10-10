/**
 * A throwaway HTTP server, so the network side is tested against something
 * real rather than against a mock of what I assume Node does.
 */

import { createServer } from 'node:http';

const running = [];

/**
 * @param {(req: import('node:http').IncomingMessage) => ({ status?: number, headers?: object, body?: string, hang?: boolean })} handler
 */
export async function start(handler) {
  const server = createServer((request, response) => {
    const answer = handler(request) ?? {};
    if (answer.hang) return; // never responds, for the timeout test

    response.writeHead(answer.status ?? 200, { 'content-type': 'text/html', ...(answer.headers ?? {}) });
    response.end(answer.body ?? 'ok');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  running.push(server);

  const { port } = server.address();
  return {
    port,
    origin: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** A port nothing is listening on. */
export async function closedPort() {
  const server = await start(() => ({}));
  const { port } = server;
  await server.close();
  return port;
}

export async function stopAll() {
  for (const server of running.splice(0)) {
    await new Promise((resolve) => server.close(resolve));
  }
}

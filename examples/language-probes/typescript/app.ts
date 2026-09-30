// SPDX-License-Identifier: Apache-2.0
// Real TypeScript is erased to JS, then embedded with SpiderMonkey. Not AssemblyScript.
type Request = { url: string; method: string; body?: Uint8Array };
export const incomingHandler = {
  handle(req: Request) {
    let status = 200;
    let body: Uint8Array = new TextEncoder().encode('ok');
    if (req.url.endsWith('/echo') && req.method === 'post') body = req.body ?? new Uint8Array();
    else if (req.url.endsWith('/unicode')) body = new TextEncoder().encode('Hello, 世界 👋');
    else if (!req.url.endsWith('/')) { status = 404; body = new TextEncoder().encode('not found'); }
    return { status, headers: [], body };
  }
};

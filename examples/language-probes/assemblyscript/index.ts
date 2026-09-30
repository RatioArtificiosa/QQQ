// SPDX-License-Identifier: Apache-2.0
// Narrow canonical ABI probe for qqq:http@1.0.0; not a general WIT generator.
// Stub allocation is bounded by the host's fresh Store per request.
export function handle(method: i32, url: usize, urlLength: i32, headers: usize,
  headerCount: i32, hasBody: i32, body: usize, bodyLength: i32): usize {
  const path = String.UTF8.decodeUnsafe(url, urlLength);
  let status: u16 = 200;
  let content = String.UTF8.encode("ok");
  if (path.endsWith("/echo") && method == 2) {
    content = new ArrayBuffer(hasBody == 0 ? 0 : bodyLength);
    if (hasBody != 0) memory.copy(changetype<usize>(content), body, bodyLength);
  } else if (path.endsWith("/unicode")) {
    content = String.UTF8.encode("Hello, 世界 👋");
  } else if (!path.endsWith("/")) {
    status = 404;
    content = String.UTF8.encode("not found");
  }
  const response = new ArrayBuffer(24);
  const ptr = changetype<usize>(response);
  store<u8>(ptr, 0);
  store<u16>(ptr + 4, status);
  store<u32>(ptr + 8, 0);
  store<u32>(ptr + 12, 0);
  store<usize>(ptr + 16, changetype<usize>(content));
  store<u32>(ptr + 20, content.byteLength);
  return ptr;
}
export function cabi_realloc(old: usize, oldSize: i32, align: i32, size: i32): usize {
  if (size == 0) return 0;
  const next = heap.alloc(size);
  if (old != 0) memory.copy(next, old, min(oldSize, size));
  return next;
}
export function abort(message: usize, file: usize, line: u32, column: u32): void {
  unreachable();
}

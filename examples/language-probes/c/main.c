// SPDX-License-Identifier: Apache-2.0
#include "app.h"
#include <stdlib.h>
#include <string.h>

static bool ends_with(app_string_t s, const char *suffix) {
  size_t n = strlen(suffix);
  return s.len >= n && memcmp(s.ptr + s.len - n, suffix, n) == 0;
}

bool exports_qqq_http_incoming_handler_handle(
    exports_qqq_http_incoming_handler_request_t *req,
    exports_qqq_http_incoming_handler_response_t *ret,
    exports_qqq_http_incoming_handler_http_error_t *err) {
  (void)err;
  const uint8_t *body = (const uint8_t *)"ok";
  size_t len = 2;
  ret->status = 200;
  ret->headers.ptr = NULL;
  ret->headers.len = 0;
  if (ends_with(req->url, "/echo") && req->method == QQQ_HTTP_HTTP_METHOD_POST) {
    len = req->body.is_some ? req->body.val.len : 0;
    body = req->body.is_some ? req->body.val.ptr : NULL;
  } else if (ends_with(req->url, "/unicode")) {
    body = (const uint8_t *)"Hello, 世界 👋";
    len = strlen((const char *)body);
  } else if (!ends_with(req->url, "/")) {
    ret->status = 404;
    body = (const uint8_t *)"not found";
    len = 9;
  }
  ret->body.ptr = (uint8_t *)malloc(len ? len : 1);
  if (!ret->body.ptr) abort();
  ret->body.len = len;
  if (len) memcpy(ret->body.ptr, body, len);
  return true;
}

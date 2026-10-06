;; SPDX-License-Identifier: Apache-2.0
;; A hostile HTTP guest: the same ABI as `live-http.wat`, but the response
;; record at address zero carries status 99 (`\63\00` where the live fixture
;; has `\c8\00` = 200) with empty headers. Status 99 has no wire meaning, so
;; the host boundary (`to_served`) must refuse it with `QQQ-3009`, the
;; caller must render 502, and the audit row must read `Failed` — a guest
;; that answers outside the protocol is exercising the authority and
;; failing, never succeeding quietly.
(component
  (core module $m
    (memory (export "memory") 1)
    (global $next (mut i32) (i32.const 1024))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      global.get $next
      global.get $next i32.const 4096 i32.add global.set $next)
    (data (i32.const 0) "\00\00\00\00\63\00\00\00\00\00\00\00\00\00\00\00\40\00\00\00\02\00\00\00")
    (data (i32.const 64) "v1")
    (func (export "handle") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      i32.const 0))
  (core instance $i (instantiate $m))
  (type $bytes (list u8))
  (type $method (enum "get" "head" "post" "put" "delete" "connect" "options" "trace" "patch"))
  (export $public-method "method" (type $method))
  (type $header (record (field "name" string) (field "value" $bytes)))
  (export $public-header "header" (type $header))
  (type $headers (list $public-header))
  (type $body (option $bytes))
  (type $request (record (field "method" $public-method) (field "url" string)
    (field "headers" $headers) (field "body" $body)))
  (export $public-request "request" (type $request))
  (type $response (record (field "status" u16) (field "headers" $headers) (field "body" $bytes)))
  (export $public-response "response" (type $response))
  (type $error (variant (case "host-not-allowed") (case "connection-failed")
    (case "request-too-large") (case "response-too-large") (case "invalid-url")
    (case "subrequest-limit-exceeded")))
  (export $public-error "http-error" (type $error))
  (type $result (result $public-response (error $public-error)))
  (func $handle (param "req" $public-request) (result $result)
    (canon lift (core func $i "handle") (memory (core memory $i "memory")) (realloc (core func $i "realloc"))))
  (instance $api (export "handle" (func $handle)))
  (export "qqq:http/incoming-handler@1.0.0" (instance $api)))

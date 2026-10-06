;; SPDX-License-Identifier: Apache-2.0
;; A trapping HTTP guest: the same ABI as `live-http.wat`, but the exported
;; handler executes `unreachable`, so the call traps. The host boundary must
;; convert the trap into an error, the slot must go through `Pool::discard()`
;; (never back to idle), and the audit row must read `Failed` — a trapped
;; instance is dropped, never reused (`F-01`, `F-11`).
(component
  (core module $m
    (memory (export "memory") 1)
    (global $next (mut i32) (i32.const 1024))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      global.get $next
      global.get $next i32.const 4096 i32.add global.set $next)
    (data (i32.const 0) "\00\00\00\00\c8\00\00\00\00\00\00\00\00\00\00\00\40\00\00\00\02\00\00\00")
    (data (i32.const 64) "v1")
    (func (export "handle") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      unreachable))
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

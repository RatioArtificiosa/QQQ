;; SPDX-License-Identifier: Apache-2.0
;; An empty event-stream guest: every request answers 200 with
;; `Content-Type: text/event-stream` and an empty body.
;;
;; Used to prove an SSE stream ends orderly (`Done`, recorded
;; `completed`) when the guest has nothing to say, rather than idling
;; forever or failing: a guest with nothing to say closes instead of
;; holding the stream open. Same ABI as sse-event.wat; only the body
;; length differs (0 in the response record at offset 16).
(component
  (core module $m
    (memory (export "memory") 1)
    (global $next (mut i32) (i32.const 1024))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      global.get $next
      global.get $next i32.const 4096 i32.add global.set $next)
    ;; Response record (24 bytes): ok discriminant, status 200,
    ;; headers at 64 (1 entry), body at 113 (0 bytes: done).
    (data (i32.const 0) "\00\00\00\00\c8\00\00\00\40\00\00\00\01\00\00\00\71\00\00\00\00\00\00\00")
    ;; One header record (16 bytes): name at 80 (12 bytes), value at 96 (17 bytes).
    (data (i32.const 64) "\50\00\00\00\0c\00\00\00\60\00\00\00\11\00\00\00")
    (data (i32.const 80) "content-type")
    (data (i32.const 96) "text/event-stream")
    (data (i32.const 113) "data: hello\n\n")
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

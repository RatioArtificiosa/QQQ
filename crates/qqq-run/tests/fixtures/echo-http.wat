;; SPDX-License-Identifier: Apache-2.0
;; An echo guest: the response body is byte-identical to the request body.
;; Same interface as live-http.wat (a QQQ application), but the core `handle`
;; copies the request body into a fresh response record instead of returning
;; a static one. Used for byte-identity and marshalling benchmarks: any
;; difference between the dynamic and typed paths shows up here.
;;
;; Lowered layout this relies on (canonical ABI, little-endian):
;; - request params (8xi32): method, url ptr/len, headers ptr/len,
;;   body-present, body ptr/len.
;; - the core function returns a pointer to 24 bytes: result discriminant
;;   (i32, 0 for ok), status (u16), headers ptr/len (empty), body ptr/len.
(component
  (core module $m
    (memory (export "memory") 96)
    (global $next (mut i32) (i32.const 1024))
    ;; Honest bump allocator: hands out `size` bytes and advances past them,
    ;; so the host's lowering and lifting never overlap guest data. (A dummy
    ;; that returns the break without reserving lets the host stack
    ;; allocations on top of each other — and on the guest's own areas.)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (call $bump (local.get 3)))
    (func $bump (param i32) (result i32)
      (local $t i32) (local $end i32) (local $have i32) (local $want i32)
      (local.set $t (global.get $next))
      ;; Round the new break up to 4 bytes so every record stays aligned.
      (local.set $end
        (i32.and
          (i32.add (i32.add (local.get $t) (local.get 0)) (i32.const 3))
          (i32.const -4)))
      ;; Grow the memory when the break would leave it: the host lowers
      ;; multi-megabyte bodies through `realloc`, and a bump allocator that
      ;; cannot grow hands back pointers past the end (the lift then fails
      ;; with "realloc return: beyond end of memory"). Growth itself goes
      ;; through the store limiter, so the ceiling still binds.
      (local.set $have (memory.size))
      (local.set $want
        (i32.div_u (i32.add (local.get $end) (i32.const 65535)) (i32.const 65536)))
      (if (i32.gt_u (local.get $want) (local.get $have))
        (then
          (if (i32.eq
                (memory.grow (i32.sub (local.get $want) (local.get $have)))
                (i32.const -1))
            (then unreachable))))
      (global.set $next (local.get $end))
      (local.get $t))
    (func (export "handle") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      (local $r i32) (local $q i32)
      (local.set $r (call $bump (i32.const 24)))
      (i32.store (local.get $r) (i32.const 0))
      (i32.store16 offset=4 (local.get $r) (i32.const 200))
      (i32.store offset=8 (local.get $r) (i32.const 0))
      (i32.store offset=12 (local.get $r) (i32.const 0))
      (if (i32.eqz (local.get 5))
        (then
          ;; Absent body echoes as an empty body: the response shape carries
          ;; a byte list, not an option, so there is no absent to preserve.
          (local.set $q (call $bump (i32.const 0)))
          (i32.store offset=16 (local.get $r) (local.get $q))
          (i32.store offset=20 (local.get $r) (i32.const 0)))
        (else
          (local.set $q (call $bump (local.get 7)))
          (memory.copy (local.get $q) (local.get 6) (local.get 7))
          (i32.store offset=16 (local.get $r) (local.get $q))
          (i32.store offset=20 (local.get $r) (local.get 7))))
      (local.get $r)))
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

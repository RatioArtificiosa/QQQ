(component
  ;; CON-019 fixture: the 0.3 guest the conformance suite executes against.
  ;;
  ;; The clock instance is what the host serves (sync shapes) and refuses by
  ;; name (async traps): inspect must require it as clock.monotonic, never
  ;; reinterpret it onto 0.2. The incoming-handler instance is unserved in
  ;; 0.3: inspect must report it as unmapped, never claim it and never drop
  ;; it silently. Assembled with the pinned `wat` crate; the byte-identical
  ;; artifact lives beside this source as wasi03-clock.component.wasm, and a
  ;; test pins the two to the same import set so neither can drift.
  (import "wasi:clocks/monotonic-clock@0.3.2" (instance $clock
    (export "now" (func (result u64)))
    (export "get-resolution" (func (result u64)))
    (export "wait-until" (func (param "when" u64)))
    (export "wait-for" (func (param "how-long" u64)))))
  (import "wasi:http/incoming-handler@0.3.2" (instance $incoming
    (export "handle" (func))))
  (core module $m)
  (core instance $i (instantiate $m)))

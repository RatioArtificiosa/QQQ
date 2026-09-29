# Profiling QQQ

**How to find out where the time goes**, which tools actually exist on each platform, and what this
project's own measurement discipline already decided.

This page is the workflow for `PERF-024`. Every number on it was measured, and every number carries the
command that re-derives it — a figure without one is a figure with no owner (`§O-277`).

---

## 1. Which tools exist, measured

The three tools the checklist names are **not interchangeable across platforms**, and two of the three
are absent from the workstation this was written on. Measured with `Get-Command` on Windows 11:

| tool | here | where it works | what it is for |
|---|---|---|---|
| `perf` | **absent** | Linux | sampling profiler, kernel-aware; the default on Linux |
| `samply` | **absent** | Linux, macOS | Firefox Profiler front-end over `perf`/DTrace |
| `vtune` | **absent** | Linux, Windows, macOS | Intel; the deepest micro-architectural view, and the heaviest to install |
| `wpr` | `C:\Windows\system32\wpr.exe` | Windows | Windows Performance Recorder — ETW capture |
| `xperf` | `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe` | Windows | the analyser for a `wpr` capture |

**So the honest instruction is: `perf` on Linux, `wpr` + `xperf` on Windows, and `samply`/VTune if you
install them.** A workflow that said "run `perf record`" would fail on the machine that needed it most.

Re-derive the table:

```powershell
foreach ($t in 'perf','samply','vtune','wpr','xperf') {
  $c = Get-Command $t -ErrorAction SilentlyContinue
  "{0,-8} {1}" -f $t, ($(if ($c) { $c.Source } else { 'NOT FOUND' }))
}
```

### Windows: `wpr` then `xperf`

```powershell
wpr -start CPU -filemode                    # begin capture
# ... run the thing you are profiling ...
wpr -stop capture.etl                       # stop; the file is the recording
xperf -i capture.etl -o capture.csv -a dumper
```

`wpr` records the whole system by default. For a single process, add `-profiledProcesses qqqai.exe` to
`-start`, or filter afterwards in WER — capturing everything and filtering later is usually faster than
getting the filter right first.

**`wpr` needs administrator rights, and that was measured rather than assumed.** On the workstation this
page was written from, `wpr -start` fails:

```
Failed to enable the policy to profile system performance.
Profile Id: CPU.Verbose.File
```

and `wpr -stop` confirms nothing was left running (`There are no trace profiles running`). **So the
procedure above is written and attempted, and it has not been executed here.** An elevated shell, or a
Linux machine with `perf`, is what would execute it. `PERF-024` stays open for that reason — see §5.

### Linux: `perf`

```sh
perf record -g --call-graph dwarf -- ./target/release/qqqai serve ./app
perf report
```

`--call-graph dwarf` is worth the overhead here: the runtime builds with debug information even in
release, and frame-pointer unwinding loses the guest frames.

---

## 2. What this project already decided about benchmarking

**`criterion` was rejected twice, deliberately, and the reason is in the build file.** From
`crates/qqq-bench/Cargo.toml`:

> `criterion` was considered and rejected twice — once in `PERF-001` for measuring in-process calls with
> no concurrency concept, and again here because `§9.1` requires the concurrency level be *disclosed per
> result*, which is a concept Criterion does not have.

**So do not reach for `criterion`.** `crates/qqq-bench/` is this project's harness — it carries the
`§9.1` methodology as a type, percentile statistics, repetition and variance, and the `§9.2` budget
contract. A micro-benchmark that bypasses it produces a number that cannot be compared with any other
number in the repository.

Two consequences worth stating:

- **A profile is for finding where time goes; `qqq-bench` is for saying how much.** They answer
  different questions and neither replaces the other.
- **`§9.1` requires the concurrency level per result.** A measurement taken at an undisclosed
  concurrency is not comparable to one taken at a different level, so record it or do not publish the
  number.

---

## 3. The measurement in this page, and how it was taken

`DIST-011` sets a `--version` startup budget of **≤15 ms**. Measured on 2026-09-28, 30 consecutive runs
of a **debug** binary:

| | |
|---|---|
| binary | `target/debug/qqqai.exe`, **30,512,128 bytes** |
| runs | 30 |
| min | **6.94 ms** |
| median | **7.70 ms** |
| p90 | **8.69 ms** |
| max | **10.10 ms** |
| budget (`DIST-011`) | ≤15 ms — **met** |

Re-derive it:

```powershell
$bin = "target\debug\qqqai.exe"
$t = 1..30 | ForEach-Object {
  $sw = [System.Diagnostics.Stopwatch]::StartNew(); & $bin --version *> $null; $sw.Stop()
  $sw.Elapsed.TotalMilliseconds
}
$s = $t | Sort-Object
"min={0:N2} median={1:N2} p90={2:N2} max={3:N2}" -f $s[0], $s[15], $s[27], $s[-1]
```

**Three things about that table are deliberate.**

1. **It is a debug build**, and it says so. A debug binary is not the artifact a user runs, so this
   number is a *floor on the machine's noise*, not a release measurement. Saying which build produced a
   figure is the difference between a measurement and a claim.
2. **It reports min, median, p90 and max rather than a mean.** The mean of a startup measurement is
   dominated by scheduler noise, and a single number hides exactly the tail that matters.
3. **It was taken 30 times, not once.** One run of a 7 ms process is a measurement of the operating
   system's timer resolution.

---

## 4. The instrument that is built but not yet fed

`PERF-025` added a fuel-derived CPU cost per request to `qqq_host::Metrics`:

| method | meaning |
|---|---|
| `fuel()` | total fuel consumed |
| `executions_metered()` | executions whose fuel was **actually reported** |
| `cost_per_request()` | `fuel / executions_metered`, or `None` when nothing was metered |
| `metering_coverage_bps()` | what share of successful executions were measured |

**And measured on 2026-09-28, nothing calls `note_execution` outside its own tests.** So on the HTTP path
`fuel()` is **0** and `cost_per_request()` is **`None`**.

That is the correct answer, not a bug in the metric: `None` says *there is no measurement*, where `0`
would say *a request costs nothing*. But it means **a profile is currently the only way to see where
request time goes** — the fuel instrument cannot tell you until `ARCH-011` step 13 is finished.

`crates/qqq-serve/src/lifecycle.rs` tracks that gap, and names the two halves: *no handle peak reaches
telemetry on the HTTP path*, and *the two registries have no common key*.

Re-derive it:

```sh
rg -n 'note_execution' crates/ | grep -v 'metrics.rs'
```

---

## 5. What a profile here cannot tell you

- **Guest time versus host time.** A `wpr` or `perf` capture sees one address space. Wasm frames appear
  as interpreter or JIT frames; attributing them to the guest function that caused them needs the
  debug information `qqq-debug` extracts, and that is a separate step.
- **Capability denials.** A profile shows a call that happened, not a call that was *refused*. That is
  the audit stream's job.
- **Anything about a different machine.** `PERF-021` publishes the hardware reference specification
  precisely because a latency number without the hardware it was taken on is not comparable to
  another one (`PLAN-013`).
- **Whether a budget is met.** A profile is for finding the cause; `qqq-bench` is for deciding the
  result. **Never raise a budget to make a benchmark pass** — a budget that hides a shortfall is worse
  than one that shows it.

---

## 6. Why `PERF-024` is still open

The checklist's own note on this item says it stays open *"rather than being ticked with a procedure
nobody executed"*, and that standard applies to this page. Measured on 2026-09-28, every profiler the
checklist names is unavailable here:

| tool | present | why it cannot run |
|---|---|---|
| `perf` | no | Linux only |
| `samply` | no | not installed |
| VTune | no | not installed |
| `wpr` | **yes** | **needs elevation** — `wpr -start` fails with *Failed to enable the policy to profile system performance* |
| `xperf` | **yes** | analyses a capture that `wpr` could not produce |

So the workflow above is **written and attempted, not executed**. The measurement in §3 was taken with a
stopwatch, which is a real measurement but not a profile. **Ticking the item would claim an executed
procedure this machine cannot execute**, and the honest position is the one the item already takes.

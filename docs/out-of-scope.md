# What QQQ does not defend against

A security document that lists only protections is incomplete, and the incompleteness
is dangerous in one specific way: a reader assumes the absent cases are covered.
Every runtime has limits, and the only honest question is whether they are **stated**
or **discovered**.

This page is the stated list. It expands Proposal §7.2, which names four classes.

Read this before deciding QQQ is appropriate for a threat model. If your threat is on
this list, QQQ is not the control you need — and in most cases **nothing** is, which
is why saying so is more useful than implying otherwise.

---

## 1. A malicious host administrator

**Not defended. Cannot be.**

If an attacker controls the host process — the machine, the kernel, the `qqqai`
process, the container it runs in — they control everything the guest sees. They can
read the guest's memory, forge its syscalls, alter the capability manifest before the
engine reads it, and rewrite the audit log. A sandbox cannot defend against the entity
that *implements* the sandbox.

That is true of every runtime, and a project claiming otherwise is describing
something impossible.

**What this means in practice.** The capability model promises "a guest has no
authority the manifest did not grant it" — relative to *host code that behaves*. If
the host is compromised, the promise is void, and the honest framing is that QQQ
protects the host **from** guests, not guests from the host.

**Where the boundary sits.** The trust boundary is the host process. Above it, QQQ's
guarantees hold and are testable. Below it, nothing here applies. Deployments with an
adversarial-host threat model need hardware isolation (separate machines, confidential
computing), which is a different layer and out of QQQ's scope.

---

## 2. Side channels between tenants

**Not defended, and not claimed.**

QQQ does not currently claim **side-channel isolation between tenants**. Concretely,
this means:

* **Cache timing.** A tenant measuring memory-access timing may learn about another
  tenant's data or access patterns when they share a physical core or an L3 cache.
  QQQ does not pin tenants to isolated cache partitions.
* **Spectre-class speculation attacks.** A guest running on a core that speculatively
  executes past a bounds check may observe another context's memory through
  microarchitectural state. Wasmtime applies mitigations and the research continues;
  none of it is a guarantee.
* **Timing in general.** QQQ does not make wall-clock time constant across guests.
  Fuel accounting measures *executed work*, not elapsed time, and a guest can observe
  host load through its own scheduling.

**What is *not* implied by the above.** These are not "any two tenants can read each
other's secrets". Exploiting a side channel is a serious research effort, and the
practical bar is high. The claim being avoided is the strong one: QQQ does not
*guarantee* isolation at that layer, and will not say it does.

**If your threat model includes cross-tenant side channels**, the mitigations are at
other layers — dedicated cores per tenant, physical separation, or confidential
computing hardware. QQQ's capability model reduces the *reachable surface* for such an
attack (a guest without a grant cannot even attempt to address another tenant's memory)
but does not close the timing channel.

---

## 3. Physical access

**Not defended.**

An attacker with physical access to the machine can read memory through cold-boot
attacks, attach a debugger, tap the memory bus, or replace the binary. QQQ has no
mechanism that operates below the OS, so none of this is in scope.

Server deployments normally address this with datacentre controls, full-disk
encryption, and secure boot — all below QQQ's layer and none of them QQQ's concern to
implement.

---

## 4. Denial of service by sheer volume

**Not defended beyond configured limits.**

QQQ enforces *per-instance* limits: fuel, memory, epochs, and handle counts. A single
guest cannot run forever or allocate without bound, and a hostile guest that tries is
terminated deterministically.

What QQQ does **not** defend against is volume:

* **Bandwidth floods.** A network attacker sending more requests than the host can
  parse consumes the *host's* capacity before any guest runs. The per-guest limits
  never engage, because the work is rejected upstream.
* **Connection exhaustion.** QQQ bounds per-connection resources, but the number of
  connections is a host-level concern.
* **A sufficiently large number of legitimate-looking tenants.** If an attacker can
  create instances faster than the host can retire them, per-instance limits do not
  help.
* **Amplification.** A guest with an egress grant can be made to send traffic at a
  remote target; QQQ bounds the guest's own resources, not the collateral.

**Where this belongs.** Rate limiting, connection caps, CDN absorption and autoscaling
are the controls for volume attacks, and they sit in front of QQQ or beside it. QQQ
composes with them rather than replacing them.

**One thing QQQ *does* improve here, stated precisely.** Per-instance limits make a
*single* malicious guest cheap to contain: it burns fuel and is stopped, rather than
being killed by an operator noticing CPU saturation. That bounds the damage from one
bad actor without bounding a flood from many.

---

## 5. Bugs in Wasmtime

**Reported upstream, patched here on a deadline.**

QQQ's sandbox **is** Wasmtime's. A guest that escapes the sandbox is out of it
regardless of what its manifest granted, so a Wasmtime vulnerability is the one class
of issue no amount of QQQ-side correctness can mitigate.

Those bugs are Wasmtime's to fix and ours to track. We commit to a **72-hour** target
for shipping a patched engine after a patched upstream release exists; the detected-by,
clock, and verification details are in
[`wasmtime-advisory-process.md`](wasmtime-advisory-process.md).

This is listed separately from the four above because it is **defended** — just not
by code. It is a process commitment with measurable deadlines.

---

## 6. Anything requiring an unbounded capability

**Not offered.**

`qqq.toml` cannot express "this component may reach any host" or "may read any path".
A bare `*` is rejected at parse time, and a grant must name a resource.

This is a *protection*, listed here because the practical consequence surprises people:
some legitimate workloads cannot be expressed. A component that genuinely needs to
reach arbitrary hosts cannot be declared — deliberately, because an unbounded grant is
one where the capability model stops meaning anything, and a manifest that can say
"anything" is a manifest nobody can review.

If you need that, it is a signal the workload does not fit the model.

---

## How this list is maintained

Each entry states a limit **and** what a reader should do about it. An entry that
said only "not defended" would be accurate and useless.

When a class moves from out-of-scope to defended, it moves to
[`/SECURITY.md`](../SECURITY.md)'s in-scope table in the same change — and the two
documents are checked against each other by `tools/check_security_scope.py`, because
a threat model that disagrees with the security policy means one of them is wrong and
neither says which.

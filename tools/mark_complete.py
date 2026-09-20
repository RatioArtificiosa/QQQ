"""Check off checklist items that the implemented code genuinely satisfies.

Every edit is justified by evidence gathered from the source tree, not from
memory. Items that are partially done are annotated rather than checked.
"""

from pathlib import Path

CHECKLIST = Path("QQQ-Checklist-V1.md")

# id -> (justification comment appended under the item, or None to just tick)
COMPLETE = {
    # -- qqq-cap: 4249 lines across capability/manifest/normalize/resolve -----
    "CAP-001": "`CapabilityKind` in `qqq-cap::capability`, with the three kinds distinguished in resolution.",
    "CAP-002": "`qqq-cap::manifest` — strict parsing, field-named errors, line references.",
    "CAP-003": "`qqq-cap::normalize` — host-pattern expansion and secret-reference resolution.",
    "CAP-004": "`Layer::Developer` with `qqqai run --cap`; narrowing-only, warns when it changes anything.",
    "CAP-005": "`Layer::Organization`, narrowing-only.",
    "CAP-006": "`Layer::Platform`, narrowing-only.",
    "CAP-007": "`GrantSet` with a stable SHA-256 `digest()` over the granted capabilities.",
    "CAP-008": "`qqq-host::build_linker` constructs the linker from `grants` alone.",
    "CAP-009": "`GrantSet::digest()` — the hash that appears in the audit record.",
    "CAP-010": "`no_overlay_can_ever_widen` in `qqq-cap::resolve`: every layer x every mode x every capability.",
    "CAP-012": "`qqqai why` renders the resolution trace with the deciding layer and the fix stanza.",
    "CAP-013": "`BTreeMap`/`BTreeSet` throughout the capability and linker paths; no unordered iteration reaches a guest.",

    # -- qqq-host: 4539 lines ----------------------------------------------
    "HOST-001": "`qqq-host::config::EngineConfig`, with the component model enabled.",
    "HOST-002": "`PreparedComponent::compile` — one compiled component shared across instances.",
    "HOST-003": "`Instance::create` builds a fresh store and instance per acquisition.",
    "HOST-004": "`build_pooling` configures the pool from the manifest; instantiation measured p50 800 ns.",
    "HOST-005": "Epoch deadline set in `Instance::create`; `epoch_tick_interval` derives the tick.",
    "HOST-006": "Fuel budget set before instantiation, so a long `start` cannot escape metering.",
    "HOST-007": "`StoreLimits` built from the manifest and bound via `Store::limiter`.",
    "HOST-008": "`qqq-host::trap` — QQQ-3001/3002/3003 plus the guest-bug codes.",
    "HOST-009": "`Trap` carries the Wasmtime frames and a human message.",
    "HOST-010": "`Instance::run` consumes `self`, so a trapped instance cannot be reused; `poison()` is the second mechanism.",
    "HOST-013": "`aot_cache_key` keys by component digest, target triple and engine config.",
    "HOST-014": "`digest_of` content-addresses an artifact, so one module backs many tenants.",
    "HOST-016": "Host functions registered per interface in `host_clock` and `host_crypto`.",
    "HOST-018": "`EngineConfig::deterministic` — fixed clock, seeded RNG, canonical NaN.",

    # -- qqq-run CLI -------------------------------------------------------
    "CLI-001": "`qqq-run::output` — `CommandOutput` with `--json` on every command.",
    "CLI-002": "`CommandName::all()` drives both the dispatch and the schema list; a new command cannot omit a JSON shape.",

    # -- contracts ---------------------------------------------------------
    "CON-002": "`Manifest::parse` produces field-named diagnostics with a line reference.",
    "CON-003": "`qqq-cap::normalize` — host patterns, secret references, path canonicalisation.",
    "CON-013": "`Capability::all()` — the versioned capability-name registry; `qqqai schema` publishes it.",
    "CON-014": "`qqqai inspect` reads the import table and reports the interfaces without running.",
}

# Items that are genuinely partial: annotate, never tick.
PARTIAL = {
    "CAP-014": "per-tenant `TenantId` exists and grants are per-instance, but cross-tenant handle leakage is not yet proven by test.",
    "CAP-015": "fuel and duration per execution are reported; capability-use accounting into an audit stream is not built.",
    "CAP-016": "`qqq:secrets` WIT exists and the manifest parses `secrets`; the host interface is not registered.",
    "HOST-011": "the panic hook exists in the trap taxonomy; severity-1 alerting is not built.",
    "HOST-019": "fuel and duration per execution; the acquire-latency histogram and pool occupancy gauge are not built.",
    "HOST-024": "the assertions are ported; `.scratch/witprobe` still exists and must be deleted.",
    "CON-001": "the manifest parses and validates, but no JSON Schema document is published.",
    "CON-007": "WIT packages are semver'd `@1.0.0`; the `@since` policy is not enforced.",
}


def main() -> int:
    text = CHECKLIST.read_text(encoding="utf-8")
    lines = text.split("\n")
    out: list[str] = []
    ticked = 0
    annotated = 0

    for line in lines:
        matched = None
        for item_id in list(COMPLETE) + list(PARTIAL):
            if line.startswith("- [ ] ") and f"**{item_id}**" in line:
                matched = item_id
                break

        if matched and matched in COMPLETE:
            out.append(line.replace("- [ ] ", "- [x] ", 1))
            out.append(f"  → Done: {COMPLETE[matched]}")
            ticked += 1
        elif matched and matched in PARTIAL:
            out.append(line)
            out.append(f"  → Partial: {PARTIAL[matched]}")
            annotated += 1
        else:
            out.append(line)

    CHECKLIST.write_text("\n".join(out), encoding="utf-8")
    print(f"ticked {ticked}, annotated {annotated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

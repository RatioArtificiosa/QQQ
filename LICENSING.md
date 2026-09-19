# QQQ Licensing

**Short version:**

- **The runtime is free. Forever. For everyone. Including your company.**
- **You pay only for governance, evidence and liability** — never for the ability to execute code.

---

## 1. What is free

Everything in this repository is licensed under the **Apache License 2.0** (see [`LICENSE`](LICENSE)):

| Component | Licence |
|---|---|
| `qqqai` runtime and host | Apache-2.0 |
| `qqqai` CLI | Apache-2.0 |
| All first-party language SDKs | Apache-2.0 |
| Package manager and registry client | Apache-2.0 |
| Dev server, test runner, debugger | Apache-2.0 |
| Embeddable libraries (`qqq-cap`, `qqq-host`, `qqq-abi`) | Apache-2.0 |

**No seat limits. No revenue limits. No user-count limits. No telemetry phone-home. No licence key.** Use it commercially, modify it, redistribute it, embed it in your product. Nothing to ask your legal team before you run code.

This commitment is **irrevocable for the 1.x line**.

---

## 2. What is paid

**QQQ Fabric** is a separate product, in a separate repository, under a separate commercial licence. It is **additive** — nothing in the free runtime depends on it, and the runtime works identically without it.

Fabric exists for organizations that need to answer questions like:

- *Which of our 400 deployed components hold a network-egress capability, and who approved it?*
- *Prove to our auditor that no production workload ever had filesystem write access.*
- *Enforce a single capability policy across every cluster, and prove it was enforced.*
- *Run this in an air-gapped environment with a mirrored, verified package supply chain.*
- *Retain 7 years of capability-audit evidence in tamper-evident form.*

Those are governance, evidence, and liability problems. They are what enterprises actually pay for. **We do not charge for execution.**

---

## 3. Tiers

| Tier | Who qualifies | Fabric | Support | Price |
|---|---|---|---|---|
| **Free** | Individuals, solo developers, students, non-profits, OSS projects, and companies with **under $2M annual revenue** | ✅ Full | Community | **$0** |
| **Team** | Up to 25 engineers | ✅ Full | Email, 2 business days | ~$25 / engineer / month |
| **Business** | Up to 250 engineers | ✅ Full | 8×5 SLA | ~$60 / engineer / month |
| **Enterprise** | 250+ engineers | ✅ Full | 24×7, indemnification, air-gapped, TAM | Custom |
| **Platform / OEM** | Embedders redistributing QQQ | ✅ Full | Jointly-branded | Custom |

> Pricing is indicative and for planning only. It is not an offer.

---

## 4. Plain-language FAQ

**My company has 200 employees. Do we have to pay to use QQQ?**
No. The runtime is Apache-2.0 and always will be. You only pay if you want QQQ Fabric or commercial support.

**I'm a solo developer building a commercial product. What do I pay?**
Nothing. You get everything, including Fabric, for free.

**We're a startup with $1.5M revenue. Do we get Fabric free?**
Yes, under the free-entity grant. Above $2M, Fabric requires a subscription.

**Can I embed QQQ in my own product and sell it?**
Yes, under Apache-2.0. See the Platform/OEM tier if you want jointly-branded support.

**Does QQQ phone home?**
No. No telemetry, no analytics, no licence checks. The runtime has no network calls you did not configure.

**Is QQQ "open source"?**
The **runtime** is — genuinely, OSI-approved Apache-2.0. **Fabric is not**, and we will not describe it as such. Fabric is a commercial product under a source-available business licence.

**What happens if you get acquired or shut down?**
The Apache-2.0 grant on the runtime is irrevocable. Every release is published with source, provenance attestations and reproducible builds. You can always rebuild it.

**What if we outgrow the free tier and don't want to pay?**
The runtime keeps working. You lose Fabric's governance features. Nothing stops functioning.

---

## 5. Why this model

We chose an **open core with a governance boundary**, not a user-count boundary, for three reasons:

1. **Runtimes win through bottom-up adoption.** Node and Bun succeeded because an engineer could install them without a procurement review. A licence that gates *execution* kills that, and with it the product.
2. **Enterprises pay for accountability, not execution.** Organization-wide policy, audit evidence, SSO, air-gapped supply chains, and indemnification are things companies genuinely budget for. "May I run this binary" is not.
3. **Openness is a competitive weapon.** If the runtime is genuinely open, it can be embedded in platforms, forked by researchers, and audited by anyone. That is how a runtime becomes infrastructure.

---

## 6. Contributing

Contributions to the Apache-2.0 runtime are accepted under the Developer Certificate of Origin. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## 7. Notes

- This document is a plain-language summary, **not a licence**. The binding terms are in [`LICENSE`](LICENSE) (runtime) and in the Fabric repository (commercial product).
- Nothing here is legal advice. If your use case is unusual, talk to counsel.
- Trademark rights are not granted by the Apache-2.0 licence. "QQQ" and the QQQ marks are reserved.

---

<p align="center"><sub>Questions? <a href="https://qqq.codes/licensing">qqq.codes/licensing</a></sub></p>

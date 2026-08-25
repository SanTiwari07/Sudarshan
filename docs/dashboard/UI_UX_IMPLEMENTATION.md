# UI/UX research report — implementation record

Maps every recommendation in the research report to what was built, what
already existed, and what was deliberately done differently.

Status: **[DONE]** built this cycle · **[EXISTED]** already present ·
**[DIFFERENT]** implemented, but not the way the report suggested, with the
reason · **[GAP]** not done.

---

## §2A Persistent header

| item | status | where |
| --- | --- | --- |
| Condensed hero on all views | **[DONE]** | `investigation/PersistentCaseBar.tsx` |
| Quantitative score over a binary verdict | **[DONE]** | score rendered as `96.8 / 100` beside the band |
| Behavioural pills | **[DONE]** | `investigation/BehaviorTags.tsx` |

**[DIFFERENT]** The report says make the condensed hero stick to the top of
*all* views. It renders on every view **except** the summary route, where the
full `CaseHeader` already lives. Two headers on one page is worse than none —
the reader has to work out which is authoritative.

A tag names a **capability**, never a verdict. `reads-sms` means the capability
is present; whether an OTP was intercepted is a finding with evidence behind
it. Runtime-observed tags render solid, manifest-declared tags dashed — a
permission in a manifest and an API call caught at runtime are different
claims.

## §2B Tabbed architecture

**[DONE]** — `investigation/AnalysisTabs.tsx`, applied in `pages/TechnicalView.tsx`.

Four tabs, matching the report's grouping: Summary · Static details ·
Behaviour & code · Network & relations. Labels carry the question each answers
("what is it?", "what does it do?", "what does it touch?").

Tab state is local, not routed. Which panel a reader is on is a view
preference, not a location; routing it would make shared case links carry an
arbitrary panel choice.

**MITRE ATT&CK matrix [DONE]** — `investigation/MitreMatrix.tsx`. Techniques are
grouped by tactic and ordered along the kill chain rather than alphabetically
or by count, because the point of the matrix is showing whether behaviour
*clusters*: five techniques under Collection is a spyware profile; five spread
across five tactics is not.

The technique→tactic map is curated in the component rather than fetched — the
page must render offline and identically every time, and a wrong tactic is
worse than an unknown one. Unmapped techniques land in a visible `Other`
bucket; an unmapped technique is a gap to close, not a thing to hide.

## §2C Refinements

| item | status | note |
| --- | --- | --- |
| Tables > 5 rows default closed | **[DONE]** | `useRowAccordion` in `TechnicalView.tsx` |
| Semantic colour per severity | **[DONE]** | optional `severity` prop on `SocCard` |

**[DIFFERENT]** The report says all tables over five rows default closed. The
threshold is applied per table from its actual row count, so a two-row table
still opens — blanket collapsing is the opposite mistake, and hiding a small
finding behind a click makes it easy to miss entirely.

Severity renders as a left border rather than a filled background: it separates
severities without turning the page into a traffic light, and leaves card
content contrast untouched. `SocCard` without `severity` is byte-identical to
before, so ~40 existing call sites are unaffected.

## §3A Relational node graph

**[DONE]** — `investigation/RelationsGraph.tsx`.

**[DIFFERENT]** The report suggests `react-flow` or `vis-network`. Built as
inline SVG instead: a graph library is a new runtime dependency and a bundle
cost for one panel, and a single ring does not need a force simulation to be
readable. No dependency was added.

Merging three IOC sources onto one canvas risks flattening "this string is in
the binary" into "the sample contacted this host". Statically extracted hosts
render hollow and dashed; hosts actually contacted render filled. When the ring
is truncated, observed nodes are kept first, so truncation cannot silently drop
what happened in favour of strings that were merely present.

## §3B Unified activity summary

**[DONE]** — `investigation/ActivitySummary.tsx`. Tiles anchor-link to their
sections. A zero count still renders: "0 files dropped" is a finding, and
hiding it makes absence indistinguishable from a section that failed to load.

## §4 Generative AI integration

### Strategy 1 — "Explain this" micro-interactions **[DONE]**

`ai/artifact_explainer.py`, `POST /explain/artifact`,
`investigation/AskAiPopover.tsx`. Wired to the dangerous-API table and the
secrets table.

Fetched on click, never on render — pre-computing an explanation per row would
bill a model call for the majority of rows nobody asks about.

Note: the pre-existing `ExplainFindingButton` is a **curated static registry**,
not AI, and is unchanged. The two coexist: curated text for known findings,
model commentary for arbitrary artifacts.

### Strategy 2 — Threat scenario correlation **[EXISTED]**

`risk_engine.build_threat_scenario_table()` already produces the
`ThreatScenarioRow` narrative, **deterministically**. Left alone deliberately:
this table feeds the report and sits adjacent to scoring, and moving it to a
model would put generated text where deterministic evidence belongs.

### Strategy 3 — Deobfuscation and intent guessing **[DONE, DIFFERENT]**

Same endpoint, `kind="string"`.

**[DIFFERENT]** The report suggests asking the model to "decode or guess". Base64
and hex are decoded **locally and exactly**; the model is asked only for
semantic intent. Decoding is arithmetic with one right answer — handing it to a
language model is slower, costs tokens, and occasionally returns a confident
wrong answer. A decode producing binary noise is discarded rather than
presented.

### Strategy 4 — Defensive artifact generation **[DONE]**

YARA, STIX and IOC CSV **[EXISTED]**. Added **Suricata and Snort**
(`engines/network_signatures.py`, `/report/suricata/{sha}`,
`/report/snort/{sha}`), wired into the existing export suite.

**[DIFFERENT]** The report lists this under Gen AI. These are generated
**deterministically**, not by a model. An operator deploys these at a
perimeter; a hallucinated rule either fails to load or matches real traffic.
The same report always yields the same rules, so two exports can be diffed.

Two failure modes drive the implementation:

* **A rule that does not compile is silently useless.** `"` `\` and `;` are
  structural in a content string, so every value is escaped and non-ASCII
  becomes a `|XX|` hex block. This is the same defect already fixed once in the
  YARA exporter.
* **A rule that matches everything is worse than useless.** Loopback, RFC1918,
  link-local, multicast and reserved addresses are excluded — a signature on
  `10.0.0.5` fires on ordinary internal traffic. Exclusions are written into
  the output as comments rather than dropped, so an operator knows an indicator
  existed and was deliberately not signed.

SIDs start at 1,000,000 (below that collides with distributed rulesets).
Snort gets one HTTP-header rule per domain; Suricata gets HTTP + TLS SNI. Snort
2 has no `tls.sni` buffer, and emitting one would produce a file Snort refuses
to load.

### Strategy 5 — Chat with the malware (RAG) **[EXISTED]**

`backend/app/ai/gemini_rag.py` already implements retrieval over the
investigation index, with `/chat` and `/chat/stream`. Not modified.

---

## Security posture of the AI additions

The artifact value comes **out of a malware sample**, so it is hostile input.

* Sanitised before use.
* An artifact matching a prompt-injection pattern is **refused, not
  forwarded** — and the refusal is surfaced to the analyst, because a benign
  application string does not address a language model.
* Injection hidden inside base64 is caught: the local decode runs *first*
  precisely so a payload cannot hide behind an encoding.
* The value is delivered inside a delimited `<artifact>` block, with a system
  preamble instructing the model to treat it as data.
* Every payload carries `advisory: true`, and the popover always renders the
  provenance line, so a client cannot present model commentary as a finding by
  forgetting to check.

**The deterministic risk invariant is intact.** A test asserts
`artifact_explainer.py` does not import the risk engine or touch
`final_risk_score`. AI explains; deterministic evidence decides.

---

## Verification

```
python:   1614 passed, 15 skipped, 4 failed (all 4 pre-existing)
frontend: tsc --noEmit clean; vite build clean; 32 component tests passing
```

New this cycle: 30 signature tests, 23 explainer tests, 12 MITRE tests,
plus behaviour-tag and relations-graph tests.

### Not established

* **No visual verification.** Every frontend change is typechecked, built and
  unit-tested, but no page was rendered in a browser and no screenshot was
  compared. Layout regressions would not have been caught.
* **The AI endpoints have never run against a real Gemini key** in this cycle.
  The explainer is tested with an injected fake generator; the live path
  (`default_explainer`) is exercised only for its no-key fallback.
* **No Suricata or Snort rule has been compiled by the real engine.** Syntax is
  asserted structurally (balanced quotes, terminated rules, SID ranges), not by
  running `suricata -T`.
* **18 pre-existing frontend failures** in `src/test/AuthFlowMatrix.test.tsx`,
  untouched by this cycle.
* **4 pre-existing backend failures** remain unaddressed.

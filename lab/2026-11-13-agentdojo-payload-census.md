# AgentDojo payload census: what the M1 demo dataset actually contains

Date: 2026-11-13 · Track: demo preparation (charter §2, success criterion 2, open PR "say how the AgentDojo payloads are obtained without Python")

## Question

The draft charter says the demo uses "97 user tasks, 629 security cases" of AgentDojo, fetched "at a pinned commit and
checksum", with `beta` returning the injection payloads, and success criterion 2 counts "100 % of all payloads". Do
those numbers hold, what is a "payload", and can it be fetched with no Python?

## Method

`pip install agentdojo` (0.1.35) in a scratch venv (lab only, no LLM, no GPU). `dump.py` loads every suite version
(`v1` … `v1.2.2`), builds each attack against a dummy pipeline, and calls `attack(user_task, injection_task)` for every
(user task, injection task) pair. `census.py` counts cases, injection slots, distinct strings, sizes and non-ASCII.
Attacks: `important_instructions` (the benchmark default), `direct`, `ignore_previous`, `injecagent`, `tool_knowledge`.

## Results

| suite version | user tasks | cases (user×injection pairs) | injection tasks | distinct payload strings |
|---|---|---|---|---|
| v1, v1.1, v1.1.1, v1.1.2 | 97 | **629** | 27 | 27 |
| v1.2, v1.2.1, v1.2.2 | 97 | **949** | 35 (workspace 6 → 14) | 35 |

- **629 is the v1 count.** The default in the current package (and likely at any "latest" pin) gives 949. The
  charter must pin the *suite version* (`v1.1.2`, 629 cases) as well as the repo commit, or the success numbers drift.
- **Only 27 distinct payload strings (v1.x) / 35 (v1.2+) exist per attack.** The string depends on the injection task
  only (goal + user/model names), not on the user task. A "case" repeats one of them, in 1–7 injection slots
  (v1.2.1: 1467 slots over 949 cases, 36 distinct slot keys, e.g. `calendar_networking_event_injection_email`).
  "100 % of payloads" is therefore 100 % of 27–35 strings; count *cases* or *slots* explicitly in the report, or the
  table misleads.
- Size is tiny: `important_instructions` 357–804 B (p50 477), `tool_knowledge` up to 1327 B, others 54–591 B. All ASCII, no
  control characters other than `\n`. Inline in an envelope (inline-threshold lab: inline wins up to 256 KiB–1 MiB)
  and trivially JCS-safe. The dataset exercises no blob path; the blob/large-payload story needs a different dataset or
  synthetic padding.
- `err 0, empty 0` for all 5 attacks × 6 versions: every pair yields a payload.
- The payload's natural-language `goal` is **not machine readable** ("Please email … to 'x@y' using …"). Criterion 2's
  "0 cause an authorisation beyond the presented capability" needs a deterministic mapping from each injection task
  to a capability request (tool, argument); AgentDojo ships none (its checker runs the tool against an environment
  state). That mapping (27–35 rows) must be written by hand in the vectors and reviewed.
- `GOAL`s are Python f-strings over module constants (`f"Please email the text '{_TEXT}' to '{_RECIPIENT}' …"`) and the
  attack templates use `{goal}`, `{user}`, `{model}`. A shell/Rust fetcher cannot read them without evaluating Python
  or re-implementing the interpolation. Static parsing of 35 f-strings plus constants is brittle.
- Licence: agentdojo ships an MIT `LICENSE` file (checked in the wheel); the repo/paper licence statement matches
  the charter.

## What the planner should do next

1. Charter: say "AgentDojo suite `v1.1.2` (629 cases) at repo commit X"; or choose v1.2.2 (949) and rewrite 629.
   Define the unit ("case" = (user, injection) pair; "payload" = distinct string; "slot" = injection field).
2. Python-free fetch: do not parse the repo. Run `dump.py` **once**, commit the output (`conformance/vectors/injection/`:
   ~35 goals, template, 97×injection pair list, slot keys; ~100 KB, or ~1 KB without the case matrix) with the package
   version and sha256, and have the fetch script verify the checksum of the generated artefact. Python stays a
   one-off generator (lab/conformance tool), not a runtime dependency.
3. Add the hand-written `injection_task → capability request` table; this is the real test input for criterion 2.
4. Plan a second, synthetic large-payload set so the blob path is exercised.

Code: `lab/agentdojo-payload-census/{dump.py,census.py}` (needs `pip install agentdojo==0.1.35`; on this Nix box
`LD_LIBRARY_PATH` must contain a libstdc++ for the cohere import).

PR-FINDING #30: charter says "629 security cases", true only for suite v1–v1.1.2; pin the suite version (default now yields 949), and "100 % of payloads" is 27–35 distinct strings, so define the unit.

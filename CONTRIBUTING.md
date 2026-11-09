# Contributing to argent-webway

This file says how work gets into this repository. Agents and `pr-create` read it. It describes what `master`
contains today. Update it in the same PR that changes the facts it states (a new workflow, a new build system,
a new test layout).

Current state of `master`: a `README.md` and nothing else. There are no build files, CI workflows or tests on
`master` yet. Specs, the conformance suite and their CI are in open PRs. Sections that depend on them say
"none yet", and the PR that adds the first workflow, build file or test layout updates those sections.

Project rules that apply to every change (owner directives, which take precedence over this file):

- **Protocol first.** A written spec (messages, state machines, error model, versioning) comes before code, and
  a conformance test suite comes with it. Interoperate with A2A and MCP rather than reinventing them.
- **Languages.** The core (transport, routing, reference node) is Rust or OCaml. The due diligence
  (`docs/due-diligence.md`, not merged yet) makes that choice. Any UI is React + TypeScript. Python only
  for ML pieces. Nothing else.
- **Security is part of the design.** Authenticated identities, authorisation per capability, verifiable
  messages, no ambient trust, prompt-injection boundaries and an audit log belong in the spec of each feature
  from the start.

## 1. Branch naming

- Agent branches are `claude/<slug>`, for example `claude/add-contributing` or `claude/due-diligence`.
- Work that comes from an issue is `claude/issue-<n>-<slug>`, for example
  `claude/issue-6-threat-model-document`. The slug is the issue title, lower-case and hyphenated, cut off at
  about 40 characters.
- `master` is the only long-lived branch. Never commit to it directly.

## 2. Commit messages

The history uses `<area>: <summary>` on one line, in the imperative or as a noun phrase, with no trailing
full stop:

```text
README: what argent-webway is for
spec: envelope/v0 draft (signed envelopes, JCS, freshness, replay, errors)
conformance: audit/v0 test vectors and generator
mailbox/v0: address independent review (14 findings)
ci: capability workflow; READMEs describe what exists
```

- `<area>` is the top-level directory or concern (`spec`, `conformance`, `docs`, `ci`, `README`) or the spec
  module with its version (`envelope`, `blob/v0`). Use lower case except for file names.
- Give details in brackets or in the body, not in a longer subject. Review rounds say so: `address review`.
- Commit in small steps. Each commit should leave the tree in a state that builds.
- Agent commits end with the `Co-Authored-By:` trailer that the harness provides.

See the history with `git log --oneline -50 origin/master`.

## 3. PR process

1. The runner pushes the branch and opens the PR. Agents do not push and do not open PRs. The description
   comes from `.agent-work/summary.md`.
2. **CI must pass.** CI is every workflow in `.github/workflows/`. There are none on `master` yet, so no checks
   run today. A PR that adds a workflow names it and the exact command it runs in this section.
3. **The description must contain:**
   - **What and why**: the change, and the issue or owner request it answers.
   - **How verified**: the commands you ran and what they printed (pass counts, not "tests pass").
   - **Risks**: what could break, what is not covered, and any decision the owner still has to make.
   - **Follow-ups**: work left for later, including edits you suggest to shared files (section 5).
4. **One owner approval** is required. Agents never merge, even when they have the rights to.
5. **Merging is squash.** The PR title becomes the commit subject on `master`, so write it in the section 2
   format.
6. After each merge, the runner rebases the other open agent PRs onto `master`. Keep PRs independent so the
   rebase is clean.

## 4. PR sizing

- One concern per PR: one spec module, one tool, one fix.
- Aim for fewer than about 400 changed lines, not counting generated files such as test vectors and lock files,
  which reviewers skim. Split larger work into PRs that each stand alone. For example, land the spec draft
  first and its vectors in a second PR.
- Do not stack a PR on another unmerged PR unless the task asks for that. Branch from `master`.

## 5. Shared files

- Keep edits to `README.md`, `CLAUDE.md`, `docs/ROADMAP.md` and `docs/ARCHITECTURE.md` out of feature PRs
  unless the task is about them. Put the edit you suggest in the PR description instead. Several PRs open in
  parallel, and these files are where they conflict.
- In dependency lists (`Cargo.toml`, `dune-project`, `package.json`, `flake.nix`), put one entry per line,
  sorted alphabetically, so that two PRs adding different dependencies do not conflict.
- Do not commit scratch work. `.agent-work/` is removed before the PR.

## 6. Testing conventions

None yet: `master` has no code and no tests. The rules below come from the owner directives and apply from
the first PR that adds code or a spec:

- **Specs come with conformance tests.** Every normative `MUST` in a spec gets a requirement ID and at least one
  test (a language-neutral test vector or a test in the core language), in the same PR.
- **Tests go next to the language's tooling:** in a Rust crate, unit tests in `#[cfg(test)]` modules and
  integration tests in `tests/`; in OCaml, `test/` with dune and alcotest; in the UI, TypeScript tests run by
  the package's test script.
- **What to test:** wire formats, state machine transitions (legal and illegal), error mapping, and security
  checks (signature verification, capability allow and deny, replay, freshness). Test every reject path, not
  only the happy path.
- **What not to test:** formatting, third-party library behaviour, private helpers that a public-interface test
  already covers.
- **Mocking:** prefer real components over mocks. Use an explicit clock and an injected source of randomness
  instead of the wall clock. Run several nodes on one machine instead of mocking the network.
- **Never change a test to make it pass.** A failing test is evidence. Fix the code, or fix the spec and its
  vectors together, and explain the change in the PR.

The PR that adds the first test framework replaces this section with the real layout, naming, and the commands
for one test and for all tests.

## 7. Review

Every PR gets an automated review before the owner looks at it.

- It **blocks** only on **Critical** or **High** findings, or on failing tests or CI.
- **Medium** and **Low** findings are follow-up notes. Fix them in the PR if that is cheap, or list them under
  follow-ups in the description.
- Answer review in new commits (`<area>: address review`). Do not rewrite history the reviewer has seen.

## 8. Definition of done

- [ ] The change builds, using the commands this file lists (none yet on `master`).
- [ ] Tests pass locally and in CI, and every new spec `MUST` has a test.
- [ ] The change follows the language rules and the security rules at the top of this file.
- [ ] Docs that the change touches are updated, including this file if a workflow, build file or test layout
      changed. Edits you suggest to shared files are in the description, not in the diff.
- [ ] The PR is one concern and about 400 changed lines or fewer, or the description says why not.
- [ ] The description has what and why, how verified, risks and follow-ups.

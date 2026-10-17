---
name: gree-create-pr
description: >
  Create or update a greeclimate pull request with a Conventional Commit title
  and an evidence-based description. Use for opening PRs, writing or refreshing
  PR descriptions, and previewing a PR from committed or pending changes.
---

# Gree pull requests

Produce a reviewer-facing explanation of the whole change, not a commit log or file inventory. Follow the repository guidelines and reuse its PR template when present.

## 1. Establish scope and permission

- Distinguish **preview**, **create**, and **update**. A preview or “do not create yet” request permits inspection and a local draft only: do not stage, commit, switch branches, push, create/edit a PR, or launch PR watchers. Do not use `gh pr create --dry-run`; it may push changes.
- Creating or updating a PR does not authorize merging, force-pushing, or including unrelated work. Stage, commit, or push only when authorized by the request; never use blanket `git add .`.
- Inspect the branch, staged and unstaged changes, untracked paths, remotes, and existing PR. Preserve unrelated staged, unstaged, and untracked work. Check `gh` availability/authentication when remote information is needed; local previews can continue with an explicit metadata limitation.

```sh
git status --short --branch
git remote -v
gh repo view --json nameWithOwner,defaultBranchRef
gh pr view --json number,title,body,url,baseRefName,headRefName,headRepository,headRepositoryOwner
```

- Resolve the actual base repository/branch and head repository/branch. For an existing PR, use its metadata, not a similarly named local branch. Otherwise use the requested target or repository default branch. A branch's upstream usually identifies its push destination, not necessarily its PR base.
- For a new PR on the default branch, use a feature branch before publishing, but never change branches during a preview. Resolve fork destinations before pushing; do not assume `origin` is the intended head repository.
- If no PR exists, continue with a new-PR draft. A permissions/network failure is not evidence that no PR exists.

## 2. Inspect the whole change

- Read the commits and full diff against the resolved base, not just the last commit. For committed work, use `git log <base-ref>..HEAD --oneline` and `git diff <base-ref>...HEAD` with an available, verified base ref. Refresh remote refs only when needed; disclose unavailable or stale base information.
- For pending changes, also inspect `git diff`, `git diff --cached`, and `git diff HEAD` so partially staged files are described in their complete working-tree form. Read intended untracked files separately; Git diffs omit them. Do not describe working-tree changes as already committed or published.
- Keep intended product changes separate from IDE state, extracted assets, logs, generated artifacts, and unrelated work. State preview exclusions; ask only when inclusion materially affects the deliverable and cannot be resolved from context. New files created while preparing the PR are not automatically part of the product change.
- Read linked issues, PR discussion, and suggested patches. Establish which proposals are already implemented and describe the resulting behavior, not the revision history. Do not invent an issue association when none is evidenced.
- For protocol or firmware claims, consult the relevant current contracts and evidence in `docs/MIDS.md`, `docs/HIDS.md`, and `docs/OFFSETS.md`. Distinguish observed device behavior, binary findings, and inference. Do not embed a fixed temperature algorithm in this skill.
- Identify affected callers, tests, fixtures, exports, configuration, and documentation. Delegate code review to the existing Ponytail review workflow when requested; do not turn PR writing into an unsolicited audit or silently fix unrelated code.

## 3. Write a Conventional Commit title

Use:

```text
<type>[optional scope][!]: <description>
```

- Select the dominant full-PR behavior: `feat` for a new feature, `fix` for a bug fix; otherwise use the appropriate `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `style`, or `revert` type. Use `refactor`, not `ref`.
- Use a short, concrete, imperative subject, lowercase type, optional narrow scope, and no trailing period. Avoid “updates”, “misc”, and “address feedback”.
- Use `!` only for a breaking external contract; explain who is affected and how to migrate in the body. Check repository release configuration before claiming a particular version bump.
- Reassess an existing title when follow-up commits change the PR's scope. Do not preserve a stale title just because its syntax is valid.

Examples of title syntax, not claims about the current change:

```text
fix(discovery): retain devices across partial gateway responses
feat(device): expose buzzer control
docs(protocol): clarify temperature encoding evidence
```

## 4. Write the description

Lead with the problem and resulting user-visible behavior. Explain the approach only where it saves reviewer reconstruction. Describe what the actual diff does; use conversation and linked reports for motivation, not as proof of implementation.

For small changes, use a concise paragraph plus relevant verification. For non-trivial changes, use this shape, omitting sections that add no information:

- **Behavior:** what changes for consumers; include a compact before/after or public API example only when useful and supported by evidence.
- **Approach:** non-obvious decisions, preserved behavior, and evidence sources. Do not narrate every file, method, or commit.
- **Verification:** exact commands actually run and their results, actual Python versions exercised, and meaningful regression coverage. Distinguish mocks, emulator, isolated UDP replay, and hardware. Separate tests from runtime smoke evidence. If not run, say so and why; never turn a planned command into a passing result.
- **Compatibility / risks:** affected callers, unavailable values, migration, remaining uncertainty, and hardware limits when relevant. Include evidence-backed risks even if the user did not raise them.
- **Issue reference:** use `Closes #N` only for a verified issue the PR resolves; otherwise use `Refs #N`. Omit absent references, unfilled placeholders, and irrelevant checklist items.

Keep headings proportional to complexity. Avoid exhaustive file lists, pasted logs, prompt/process history, unsupported performance claims, and generic reassurance such as “safe to merge”. Never expose device keys, credentials, private addresses, captures, or other sensitive information.

For library behavior changes, verify through the public path with the existing emulator or an isolated UDP peer when feasible; do not probe unknown properties or control a live device without permission. Run relevant existing tests in an isolated environment when needed. If verification is unavailable, report the precise limit rather than implying completion. Read the declared Python minimum and CI/tox targets; do not assume all supported interpreters were exercised.

Never edit `CHANGELOG.md`; semantic-release generates it. Document behavior changes in relevant existing documentation and the PR description. Do not claim existing documentation was changed in this PR unless the diff includes it.

## 5. Preview or publish

**Preview:** return the proposed title and complete body, the target/base assumptions, included scope, exclusions, and verification limits. Stop without remote mutations. A preview may expose unresolved publication prerequisites without changing the user's code.

**Create/update, only when authorized:**

1. Confirm intended changes and actual head/base destinations. Preserve unrelated work and prepare only the authorized branch/commits. Do not reset, stash, amend, or force-push unrelated work.
2. Write the description to a fresh temporary file outside the repository. Supply explicit target, base, head, and title rather than relying on automatic commit-message filling:

   ```sh
   gh pr create --repo <base-owner/repo> --base <base-branch> \
     --head <head-owner:head-branch> --title '<title>' --body-file <temporary-body-file>
   ```

   Use `--draft` unless the user requested ready-for-review status. Resolve CLI limitations for organization-owned fork heads rather than substituting another repository. For an existing PR, update that exact PR with `gh pr edit <number> --repo <base-owner/repo> --title '<title>' --body-file <temporary-body-file>`; do not create a duplicate.
3. Read back the PR title, body, URL, and head/base metadata. Report its URL and actual verification limits, then remove the temporary body file. Do not merge or enable auto-merge unless separately requested.

## References

Writing guidance adapted from [Sentry's PR Writer](https://github.com/getsentry/skills/blob/main/skills/pr-writer/SKILL.md), with repository-template and evidence ideas from [Aspire's create-pr](https://github.com/microsoft/aspire/blob/main/.agents/skills/create-pr/SKILL.md).

Title syntax: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Command semantics: [GitHub CLI PR creation](https://cli.github.com/manual/gh_pr_create).

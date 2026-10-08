# 2.0.6 security patch — builder handoff

Status: local construction, pending independent exact-head certification. This is not
a release receipt and does not close source findings by self-certification.

Base: `68ce34a032484529104b570d417e29ac8156b080`, tree
`ec2ee9b600aba60c46ca1a1f793484018ff78ea3`, immutable tag `2.0.5`.
Branch: `v2.0.6-security-patch`. The successor identity is obtained with
`git rev-parse HEAD HEAD^{tree}` after the final local release-control commit.
Final exact-head replay evidence is stored outside that tree to avoid a circular
claim that an in-tree document signs or approves its own eventual commit.

October 7 follow-up: the owner authorized reopening frozen candidate `3efdb65`
and a manifest dry run written only to scratch. Both fixture-reference blockers
are repaired; the final refrozen identity and replay results are in the new
external handoff. The September handoff remains unchanged historical evidence.

Repair commits (all local, unsigned):

- 008/027: `350491443c468e1a1621790687b25dd4a4fe19e8`.
- 009/010: `8f01f8f5c6366d4ae227317a7d9ace825b61d675`.
- 003–006: `42ec12c9ebdb9e971dfd8e9217554c5d498f69da`.
- 007: `9a95455f7497af311ae7d75f94e2665c0cf6748c`.
- 026/031 and version-neutral docs: `997368ed1baa0bbe9495f572d17d70550bb17a14`.

## Scope and decisions

- The worklist says “10 mediums” but names eight mandatory repairs: 003–010.
  001 and the 002 mechanism are explicitly deferred. This patch does not claim
  all ten mediums closed. Swept items are 026, 027 and 031; related 015/017
  behavior receives regression coverage without rewriting their original status.
- 009 follows default option (b). The original three staging critique pins and
  finding text remain intact; each gains `provenance: staging-only; not in public
  history`. Default verification FAILS when commits are absent. Only explicit
  `--historical-records`, restricted to those exact three known records, checks
  their historical structure. `reaccept.py` prints that limitation, not a claim
  that public objects or independent acceptance were proved.
- On September 13, worklist section 5's final stop overrode its conflicting
  manifest dry-run request. The October 7 prompt explicitly supersedes that
  limitation for a scratch dry run. That dry run now prints `MANIFEST OK`;
  the production manifest/signature is retained until owner ceremony. No READY,
  signature, publication, witness or fleet claim follows from construction.
- The optional 002 UX change was omitted to keep mechanism scope narrow.
- Local Git help contradicts the worklist's blanket short-option statement:
  `clone -u` selects upload-pack; `fetch -u` means update-head-ok. The latter
  remains allowed by this bounded classifier. Long upload-pack options are blocked.
- Canonical validation ignores only regular `.pyc` files inside `__pycache__`,
  not arbitrary source hidden there. Signed integrity retains its own stricter
  inventory/content checks. `tests/__init__.py` suppresses bytecode for package
  imports; bare discovery is validated separately, not assumed to import it.

## Per-finding construction evidence

All paths below are repository-relative. Captures in `red/` and `green/` are
command output, not declarations of independent review or production behavior.

| ID | Changed boundary/files | Discriminating fixture / red → green | Authority and residual |
|---|---|---|---|
| 008 | `scripts/trust_root.py`, `verify_release_reviews.py`, `verify_public_release.py`, `bootstrap/idc_verify_fresh.py` | Both `test_git_run_neutralizes_candidate_fsmonitor` tests fail on base; then pass. Internal review added `test_git_run_rejects_executable_clean_filters_before_status` (direct and included config) and `test_git_run_rejects_executable_diff_before_comparison`: red → rejection before execution. `red/git-*.txt`, `green/git-*.txt`. | Shared isolated runner disables fsmonitor/hooks, refuses executable filter/diff config; preserves explicit diff exit 1, cwd and byte output. Launcher pin updated to exact repaired module bytes, not bypassed. Hostile concurrent same-UID mutation and compromised trusted tools remain outside this control. |
| 009 | `verify_gauntlet_records.py`, `reaccept.py`, three `ops/gauntlet/reviews` provenance fields | `GauntletRecordTests`: absent valid SHA, non-commit object, gutted values and arbitrary historical self-declaration reject; real commit control passes. `red/tier-a-evidence-tests.txt` → `green/tier-a-evidence-tests.txt`. | Enforces object/type checks in strict mode. Historical mode is explicitly not acceptance or authorship proof. |
| 010 | `verify_platform_evidence.py`, platform schema, runtime/platform tests | `test_fabricated_pass_without_artifact_fails`: old code accepts, repaired code rejects. Matching-hash wrong-head, command, environment, unsuccessful exit, empty output, duplicate keys and unsafe files reject; consistent synthetic capture passes. | Enforces captured bytes and semantic consistency. Does not authenticate runner identity or prove actual Windows/macOS execution. |
| 003 | `block-dangerous-git.sh`, guard matrix/grammar tests | Explicit edit forms and later autosquash fixtures go red → blocked; plain messages, plain fixup and literal option-value controls stay allowed. `red/guard-grammar.txt`, `red/guard-autosquash-grammar.txt` → corresponding green captures. | Blocks modeled editor execution in both modes. Not complete shell/Git execution policy. |
| 004 | Same guard files | Compound-prefix, negation/time, redirection/wrapper and variable-dispatch tests go red → blocked in strict mode. Quoted prose and format-string controls remain allowed. | Strict command-position checks reuse the existing segmenter; advisory mode remains distinct. |
| 005 | Same guard files | `test_strict_semicolon_assignment_chain_finishes_under_two_seconds` enforces process-group timeout under 2 seconds: old input times out, repaired n=30 finishes around 0.03 seconds. Existing 48-KiB allow and 96-KiB reject controls remain. | Removes exponential assignment regex; retains 64-KiB strict ceiling. Finite scaling fixtures are not proof for all shell grammar. |
| 006 | Same guard files | Upload-pack/receive-pack/exec/SSH configuration cases reject; ordinary remote listing/fetch/clone and option-value literals pass. Parent compatibility regression `test_fetch_update_head_ok_is_not_an_upload_pack_program` is red → green. | Blocks known program-launch options in both modes; does not sandbox arbitrary commands. |
| 007 | `verify-sealed-artifacts.mjs`, sealed fixture harness, `self-contained-ship/SKILL.md` | Original delayed RTC, delayed HTTP and about:blank child cases pass incorrectly; repaired harness rejects. Clean control passes with explicit bounds, terminated target and zero loopback HTTP deliveries. `red/sealed-*` → `green/sealed-*`. | Interception stays attached until confirmed target termination; verdict follows teardown and post-settle probe. Frames are rejected rather than certified. Arbitrary future interactions/timers and packet-level ICE remain unproven. |
| 027 | `verify_public_release.py`, public-release fixtures, `trust/README.md`, `docs/release-acceptance-evidence.md` | New matching registry version used to fail; mismatched registry used to pass. Both corrected. Lightweight tag refusal retained; same-named branch cannot confuse fully qualified `refs/tags/…`. `red/publication-tag.txt` → green. | Enforces committed registry/tag/HEAD/tree binding; full-profile production activation is still deferred. |
| 026 | `CHANGELOG.md`, `docs/STATE-2.0.3-hardening.md`, `test_security_patch_docs.py` | Missing provenance annotation assertions fail → pass for every listed staging-only citation. `red/documentation.txt` → green. | Documentation truthfulness only; no fabricated or rebound historical commit. |
| 031 | `validate_skills.py`, validator tests, `tests/__init__.py` | Untouched base bare discovery fails; generated bytecode fixture fails canonical validation before the patch, passes afterward while invalid `.py` under the cache still fails. `red/python-bare.txt`, `red/bytecode.txt` → green and final fresh-clone bare replay. | Canonical hygiene only, not a signed-inventory exception. |
| BUILD-206 fixture references | `agent-guardrails/scripts/test-block-dangerous-git.sh`, `self-contained-ship/scripts/test-sealed-artifacts.mjs`, `test_manifest_reference_policy.py` | `test_all_tracked_skill_references_are_classified` fails on `3efdb65` with three occurrences from two sources; passes after the operand and sink-URL fixes. Unknown-reference and wrong-skill controls pass in both runs. `red/2026-10-07/reference-policy.txt` → green; scratch manifest refusal → `MANIFEST OK`. | Uses the manifest builder's actual text classifier and policy validation over tracked skill files. Policy remains enforced and unchanged. This regression checks reference classification, not complete runtime network behavior; the seven browser fixtures separately exercise the loopback sink. |

## October 7 fixture-reference continuation

The supplied 28-line reference patch was hashed and reviewed before the builder
wrote equivalent edits. Its SHA-256 is
`0238ca293473630c93c3ae86df2916f474be5b9256344dd055685d06bf8df2b1`.
The guard retains safe clone and consumed-option-value controls using a local
fixture path. The browser harness constructs the same ephemeral loopback URL
from fragments; no production scanner, runtime interception or policy was changed.

The first regression capture had an incorrect helper name and is retained as
`red/2026-10-07/reference-policy-initial-test-error.txt`; it is not closure proof.
The corrected regression was replayed against a pristine clone of `3efdb65` and
reported both sources, then passed against the repaired clone. Its line numbers
are the classifier's logical lines after shell continuations, not physical lines.
The manifest's own red and green captures are separate corroborating evidence.
Both full Python modes passed 319 tests in separate scratch clones.

A fresh internal read-only verifier found no concrete issue in these three files,
reproduced the three regression tests, 434-case guard matrix and delayed-HTTP
browser control, and confirmed matching source hashes. It issued no independent
acceptance. Mission Control's state and generated heartbeat now reflect this
continuation while retaining historical phase records.

## Internal review and integration corrections

One fresh OpenAI read-only review searched for bypasses and legitimate regressions.
It found clean-filter and external-diff execution beyond fsmonitor, and editor
execution through squash/amend/reword options. The builder reproduced them with
new red tests and repaired them. It issued no acceptance receipt. Additional
integration tests caught the stale launcher module digest and old diagnostic
wording; the implementation pin and compatible diagnostic were corrected.
Intermediate failed attempts remain labeled in the captures; final gates are
listed separately in `gates.txt`.
Raw captured output retains incidental trailing spaces. Source/document whitespace
checks exclude only raw `red/` and `green/` captures; no raw output was trimmed to
manufacture a clean whitespace result. This is not an exception to a security gate.

## Reproduction for Claude

1. Clone this local branch without hardlinks into a fresh ordinary repository;
   do not reuse the owner's checkout or install anything into the four fleet roots.
2. Record full HEAD/tree and run the commands in `gates.txt`. Real Chrome and
   Node with WebSocket support are needed for sealed fixtures. A skip is not PASS.
3. To reproduce the original failures, use a separate detached clone of the base,
   copy only the named new test files/harness from the successor, and run their
   listed focused commands against base implementation bytes. The historical-mode
   interface did not exist on base; distinguish those interface errors from the
   discriminating absent-object and fabricated-platform failures in the captures.
4. `test-sealed-artifacts.mjs --case=delayed`, `--case=delayed-http`, and
   `--case=subframe` exercise loopback-only fixtures. Finite observation bounds
   are part of the result, never a universal containment certificate.
5. Preserve exact red/green output, legitimate controls and source diffs. Certify
   only the exact successor you actually reviewed. Any later changed bytes need
   fresh review. Owner signing/publication remains outside this builder handoff.
6. For the October continuation, copy `test_manifest_reference_policy.py` into
   a pristine clone at `3efdb65`, then run its three tests to reproduce the red.
   Use `run_gates_oct07.py <scratch-clone> <external-output> red`, `green`, or
   `bare` as appropriate. Each subprocess has an explicit scratch working directory.
   The script's result booleans report expected command outcomes, not acceptance.

## Remaining work and untouched surfaces

All original 39 K3-205 findings and their severity/status remain intact in the
owner's banked evidence. Repairs here are **implemented, pending independent
certification**, not rewritten source dispositions. 001/002 mechanisms,
011–025 (apart from related regression coverage), 028–030 and 032–039 remain
outside this patch. No production reviewer authority, root ceremony, Windows
seat, freshness-authorized fleet proof or publication observer is asserted.
The owner briefs, `.claude/`, 2.0.5 keys/manifest/signature/tag/witnesses and the
banked K3-205 evidence store were not altered.

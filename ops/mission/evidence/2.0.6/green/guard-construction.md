# K3-205-003/004/005/006 guard construction evidence

OpenAI Codex implementer evidence, 2026-09-13. This is construction proof, not an independent
acceptance receipt, certification, or evidence that a hook is installed. Commands are inert
JSON strings passed to the classifier; no payload program is executed.

## Final focused repair after internal review

The internal reviewer found that autosquash message defaults had been overgeneralized. Before
repairing that behavior, new fixtures captured `--squash HEAD`, `--squash=HEAD`, and both
separate/equals `--fixup amend:HEAD` / `--fixup reword:HEAD` forms allowing execution in both
modes: 1 test, 12 failing subtests, 1.367 seconds, exit 1 with pipefail. The remaining 26
subtests were green controls. Capture: `../red/guard-autosquash-grammar.txt`.
Classifier SHA-256 for this red was
`847847c9ea01b573f8afc9be98b9d52f5c3a4df0bf909f846e4942a49ec4fca7`.

The existing option parser now optionally collects actual long-option values, including
separate and equals forms. Squash no longer suppresses the editor by itself; only plain fixup
supplies an editor-free default message. Amend/reword fixup still requires an explicit no-edit
control. Consumed message values such as `-m --fixup=amend:HEAD` remain data. The parent agent's
clone-only `-u` transport correction is preserved: fetch `-u` means update-head-ok.
Local primary reference consulted: `git commit -h` (help output exits 129).

Final checks, superseding the initial green numbers below:

- Full guard grammar: **18 tests OK**, 4.848 seconds; `guard-autosquash-grammar.txt`.
  This includes the parent's fetch update-head-ok control and 38 autosquash subtests.
- Full shell matrix: **pass=434 fail=0**; `guard-autosquash-matrix.txt`.
- Strict n=30 semicolon timing: **0.030943792 seconds**, exit 0, two-second limit.
- Individual `bash -n` on each changed shell file, shellcheck on both, and scoped
  `git diff --check`: all exit 0.

Intermediate classifier SHA-256 before the integration diagnostic compatibility edit:
`fe35c87e4c91878ee05ce88154549db98cb3571bb41dae278cadb2f43926eae3`.
The final integrated classifier SHA-256 is
`f228b68bf34ede252e355cfc208416e3c4a83a71fffe34fa6d6d66e20ce113ee`;
the combined 316-test and 434-case replay covers that source.

## Red before source edits

Fixtures were added to `tests/test_git_guard_grammar.py` and the shell matrix before editing
`skills/agent-guardrails/scripts/block-dangerous-git.sh` on `v2.0.6-security-patch`.
The unchanged HEAD was `68ce34a032484529104b570d417e29ac8156b080`; its classifier SHA-256
is `09d84588195ddcab375a4c87e6fcd43ad81fc0b15b67e6fcbdf343dab3f0b621`.

- `python3 -B -m unittest tests.test_git_guard_grammar -v`: 16 tests, 58 failing subtests,
  5.505 seconds. See `../red/guard-grammar.txt`. This includes the n=30 semicolon-chain
  two-second timeout; the test kills the entire guard process group on timeout.
- `bash skills/agent-guardrails/scripts/test-block-dangerous-git.sh`: `pass=407 fail=21`.
  See `../red/guard-matrix.txt`. The matrix contains the original 395 cases plus 33 new cases.
- Red captures used `tee` without pipefail: the shell pipeline exit code was 0, but the
  preserved runner verdicts above were red. No green verdict is inferred from that pipeline code.

## Green after source edits

- `python3 -B -m unittest tests.test_git_guard_grammar -v`: 16 tests, OK, 3.308 seconds;
  `guard-grammar.txt`. Includes 48-KiB accepted / 96-KiB rejected controls and the strict
  n=30 semicolon-chain completion assertion below two seconds.
- `bash skills/agent-guardrails/scripts/test-block-dangerous-git.sh`: `pass=428 fail=0`;
  initial construction result. The packaged `guard-matrix.txt` was superseded by
  the final integrated 434-case capture; it is not the original 428-case log.
  Both initial green commands used pipefail and exited 0.
- Separate n=30 timing probe: 180 command bytes, exit 0, 0.028876625 seconds, 2-second limit.
- `bash -n` on each changed shell file: exit 0; `shellcheck` on both: exit 0.
- `git diff --check` on the three changed source/test files: exit 0.

Classifier SHA-256 at these green checks:
`074177090181e2c12f3bc498db472b7785bec80b332e65d1d4bf3bfcc9825712`.

## Behavior and bounds

The two strict regex anchors were removed. Existing segmentation and `command_word_index`
now locate eval/source/nested shells after assignments, supported wrappers, compound prefixes,
and redirections; existing parameter annotations reject variable command dispatch. The strict
64-KiB limit still runs before tokenization. This removes the overlapping regex quantifiers;
it does not claim that every component of the entire classifier is a general linear shell parser.

Editor and transport detection use actual option tokens, excluding consumed values and text
after `--`. Explicit edit flags cancel message suppression. Upload/receive/exec transport options
block in both modes, matching the existing executable-config class. Existing core.sshCommand
and GIT_SSH_COMMAND handling remains enforced at classification, with send-pack and remote
archive added to the SSH environment surface. Local archive controls remain available.

This remains the documented bounded string classifier. Renamed binaries, unsupported wrappers,
persistent on-disk Git configuration and full shell semantics remain outside its proof boundary.
The source and fixture changes require successor-identity qualified review by the designated
independent seats before release acceptance.

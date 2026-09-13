from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
GUARD = REPO / "skills/agent-guardrails/scripts/block-dangerous-git.sh"


class GitGuardGrammarTests(unittest.TestCase):
    def test_fetch_update_head_ok_is_not_an_upload_pack_program(self) -> None:
        for strict in (False, True):
            self.assertEqual(self.run_guard("git fetch -u origin", strict=strict).returncode, 0)

    def run_guard(
        self,
        command: str | None,
        *,
        strict: bool = False,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        payload = {} if command is None else {"tool_input": {"command": command}}
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        }
        if strict:
            env["IDC_GUARD_STRICT"] = "1"
        process = subprocess.Popen(
            ["bash", str(GUARD)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(json.dumps(payload), timeout=timeout)
        except subprocess.TimeoutExpired:
            # Kill the classifier child too: terminating only the Bash wrapper leaves the
            # vulnerable regex consuming CPU and holding the capture pipes open.
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def test_push_redirection_forms_receive_same_block(self) -> None:
        commands = [
            "git push",
            "git push>/dev/null",
            "git push>>/dev/null",
            "git</dev/null push",
            "git push</dev/null origin main",
        ]
        self.assertEqual([self.run_guard(command).returncode for command in commands], [2] * 5)

    def test_reset_redirection_forms_receive_same_block(self) -> None:
        commands = [
            "git reset --hard",
            "git reset --hard>/dev/null",
            "git>/dev/null reset --hard",
        ]
        self.assertEqual([self.run_guard(command).returncode for command in commands], [2] * 3)

    def test_bang_alias_composes_with_call_site_arguments(self) -> None:
        blocked = [
            "git -c alias.p='!git' p push",
            "git -c alias.p='!git' p reset --hard",
            "git -c alias.p='!git' p clean -fd",
        ]
        self.assertEqual([self.run_guard(command).returncode for command in blocked], [2] * 3)
        self.assertEqual(self.run_guard("git -c alias.p='!git' p status").returncode, 0)

    def test_non_alias_config_and_plumbing_mutations_block(self) -> None:
        commands = [
            "git -c clean.requireForce=false clean -d",
            "git update-ref refs/heads/topic HEAD~1",
            "git update-ref -d refs/heads/topic",
            "git tag -f release HEAD~1",
        ]
        self.assertEqual([self.run_guard(command).returncode for command in commands], [2] * 4)

    def test_strict_mode_blocks_unsupported_dynamic_grammar(self) -> None:
        commands = [
            "C=git; $C push",
            "git $(printf pu)sh",
            'eval "git push"',
            'sh -c "git push"',
            "f(){ git push; }; f",
        ]
        self.assertEqual(
            [self.run_guard(command, strict=True).returncode for command in commands], [2] * 5
        )

    def test_strict_mode_blocks_missing_command_but_advisory_mode_announces_open(self) -> None:
        strict = self.run_guard(None, strict=True)
        advisory = self.run_guard(None, strict=False)
        self.assertEqual(strict.returncode, 2)
        self.assertIn("strict guard BLOCK", strict.stderr)
        self.assertEqual(advisory.returncode, 0)
        self.assertIn("advisory guard OPEN", advisory.stderr)

    def test_strict_mode_short_circuits_oversized_command(self) -> None:
        command = "git status # " + ("A" * (96 * 1024))
        try:
            result = self.run_guard(command, strict=True, timeout=5.0)
        except subprocess.TimeoutExpired:
            self.fail("strict guard did not fail closed within five seconds for oversized input")

        self.assertEqual(result.returncode, 2)
        self.assertIn("command exceeds the bounded strict grammar", result.stderr)

    def test_strict_mode_remains_available_below_command_ceiling(self) -> None:
        command = "git status # " + ("A" * (48 * 1024))
        try:
            result = self.run_guard(command, strict=True, timeout=5.0)
        except subprocess.TimeoutExpired:
            self.fail("strict guard exceeded five seconds below its documented command ceiling")

        self.assertEqual(result.returncode, 0)

    def test_safe_commands_remain_available_in_strict_mode(self) -> None:
        for command in ("git status", "git diff", "git restore README.md"):
            with self.subTest(command=command):
                self.assertEqual(self.run_guard(command, strict=True).returncode, 0)

    def test_edit_reopens_explicit_message_editor(self) -> None:
        for command in (
            "GIT_EDITOR=evil git commit -m x -e",
            "GIT_EDITOR=evil git commit --edit -m x",
            "VISUAL=evil git merge --no-ff -m x --edit topic",
            "EDITOR=evil git commit -F message --edit",
            "GIT_EDITOR=evil git commit -C HEAD --edit",
            "git -c core.editor=evil commit -m x --edit",
            "git -c sequence.editor=evil commit -m x --edit",
        ):
            for strict in (False, True):
                with self.subTest(command=command, strict=strict):
                    self.assertEqual(self.run_guard(command, strict=strict).returncode, 2)

    def test_autosquash_editor_semantics(self) -> None:
        blocked = (
            "--squash HEAD", "--squash=HEAD",
            "--fixup amend:HEAD", "--fixup=amend:HEAD",
            "--fixup reword:HEAD", "--fixup=reword:HEAD",
            "--fixup HEAD --edit", "--fixup=HEAD -e",
        )
        allowed = (
            "--fixup HEAD", "--fixup=HEAD", "--fixup HEAD -m extra",
            "--squash HEAD -m extra", "--squash=HEAD --no-edit",
            "--fixup=amend:HEAD --no-edit", "--fixup reword:HEAD --no-edit",
            "-m --fixup=amend:HEAD", "-m --squash=HEAD",
            "-m x -- --fixup=amend:HEAD", "--fixup HEAD -m --edit",
        )
        for expected, arguments in ((2, blocked), (0, allowed)):
            for argument in arguments:
                for strict in (False, True):
                    with self.subTest(argument=argument, strict=strict):
                        result = self.run_guard("GIT_EDITOR=evil git commit " + argument, strict=strict)
                        self.assertEqual(result.returncode, expected, result.stderr)

    def test_editor_option_values_and_suppression_remain_literal(self) -> None:
        for command in (
            "git commit -m x", "git commit -m x --no-edit",
            "GIT_EDITOR=evil git commit -m x",
            "GIT_EDITOR=evil git commit -m --edit",
            "GIT_EDITOR=evil git commit -m x -- --edit",
            "GIT_EDITOR=evil git commit --message x",
            "GIT_EDITOR=evil git commit --file message",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.run_guard(command, strict=True).returncode, 0)

    def test_strict_command_positions_reject_dynamic_shells(self) -> None:
        for command in (
            '{ eval "git push"; }', 'if true; then eval "git push"; fi',
            '! eval "git push"', 'time eval "git push"',
            'x=1 { eval "git push"; }', '> /dev/null eval "git push"',
            'while eval "git push"; do :; done',
            'until eval "git push"; do :; done',
            'if false; then :; elif eval "git push"; then :; else eval x; fi',
            'for x in a; do eval "git push"; done',
            'case x in x) eval "git push";; esac',
            'coproc eval "git push"', 'coproc WORKER { eval "git push"; }',
            'if true; then /bin/bash -c "git push"; fi',
            '{ source /tmp/commands; }', '! . /tmp/commands',
            'A=1 B=2 eval "git push"', 'command eval "git push"',
            '! $COMMAND', 'time "$COMMAND"',
        ):
            with self.subTest(command=command):
                self.assertEqual(self.run_guard(command, strict=True).returncode, 2)

    def test_strict_command_position_scan_preserves_literal_arguments(self) -> None:
        for command in (
            'echo "{ eval }"', "git log --format='{ %h }'",
            'echo "; eval harmless"', 'git commit -m "then eval text"',
            'echo "if sh -c text"', 'command -v bash',
            'echo "c0=d;c1=d;$COMMAND"',
        ):
            with self.subTest(command=command):
                self.assertEqual(self.run_guard(command, strict=True).returncode, 0)

    def test_strict_semicolon_assignment_chain_finishes_under_two_seconds(self) -> None:
        command = ";".join(f"c{i}=d" for i in range(30)) + " git status"
        start = time.monotonic()
        try:
            result = self.run_guard(command, strict=True, timeout=2.0)
        except subprocess.TimeoutExpired:
            self.fail("K3-205-005: n=30 semicolon assignments exceeded two seconds")
        elapsed = time.monotonic() - start
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, 2.0)

    def test_transport_program_options_block_in_both_modes(self) -> None:
        commands = [
            "git ls-remote --upload-pack='touch /tmp/x' origin",
            "git clone -u 'touch /tmp/x' origin",
            "git fetch --upload-pack='touch /tmp/x' origin",
            "git pull --upload-pack='touch /tmp/x' origin",
            "git clone -uevil origin", "git clone -qu evil origin",
            "git ls-remote --upload-pack evil origin",
            "git send-pack --receive-pack=evil origin HEAD",
            "git send-pack --exec evil origin HEAD",
            "git archive --remote=origin --exec=evil HEAD",
            "git archive --remote origin --exec evil HEAD",
            "git -c core.sshCommand=evil ls-remote origin",
            "GIT_SSH_COMMAND=evil git ls-remote origin",
            "GIT_SSH_COMMAND=evil git send-pack origin HEAD",
            "GIT_SSH_COMMAND=evil git archive --remote=origin HEAD",
        ]
        for command in commands:
            for strict in (False, True):
                with self.subTest(command=command, strict=strict):
                    self.assertEqual(self.run_guard(command, strict=strict).returncode, 2)

    def test_transport_option_literals_remain_available(self) -> None:
        for command in (
            "git ls-remote origin", "git fetch origin", "git clone https://x/y",
            "git commit -m --upload-pack=evil", "git ls-remote origin -- --upload-pack=evil",
            "git clone --branch --upload-pack=literal https://x/y",
            "git archive --exec=unused HEAD", "GIT_SSH_COMMAND=evil git archive HEAD",
            "GIT_SSH_COMMAND=evil git status",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.run_guard(command, strict=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()

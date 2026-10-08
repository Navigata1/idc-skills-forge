"""Capture fixed construction commands in scratch repositories; no release authority."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys
import time

root = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
mode = sys.argv[3]
out.mkdir(parents=True, exist_ok=True)
if mode == 'red':
    jobs = {
        'reference-policy': (['python3', '-B', '-m', 'unittest', 'tests.test_manifest_reference_policy', '-v'], 1),
        'manifest': (['python3', '-I', '-B', 'scripts/skill_integrity.py', 'manifest', '--out', str(out / 'm.json')], 1),
    }
elif mode == 'bare':
    jobs = {'python-bare': (['python3', '-m', 'unittest', 'discover', '-s', 'tests'], 0)}
else:
    jobs = {
        'reference-policy': (['python3', '-B', '-m', 'unittest', 'tests.test_manifest_reference_policy', '-v'], 0),
        'guard-matrix': (['bash', 'skills/agent-guardrails/scripts/test-block-dangerous-git.sh'], 0),
        'sealed-fixtures': (['node', 'skills/self-contained-ship/scripts/test-sealed-artifacts.mjs', '--capture-dir=' + str(out / 'sealed')], 0),
        'python-full': (['python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests'], 0),
        'canonical': (['python3', '-I', '-B', 'scripts/validate_skills.py', '--json'], 0),
        'forge-50': (['python3', '-B', 'scripts/verify_forge_50.py', '--json'], 0),
        'shellcheck': (['shellcheck', 'skills/agent-guardrails/scripts/test-block-dangerous-git.sh'], 0),
        'bash-syntax': (['bash', '-n', 'skills/agent-guardrails/scripts/test-block-dangerous-git.sh'], 0),
        'node-syntax': (['node', '--check', 'skills/self-contained-ship/scripts/test-sealed-artifacts.mjs'], 0),
        'manifest': (['python3', '-I', '-B', 'scripts/skill_integrity.py', 'manifest', '--out', str(out / 'm.json')], 0),
    }

def run(pair):
    name, (argv, expected) = pair
    start = time.monotonic()
    result = subprocess.run(argv, cwd=root, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=300)
    seconds = round(time.monotonic() - start, 3)
    output = result.stdout
    passed = result.returncode == expected
    if name == 'sealed-fixtures':
        passed = passed and 'RESULT pass=7 fail=0 unexpectedExternalDeliveries=0' in output and 'SKIP' not in output
    if name == 'manifest' and expected == 0:
        passed = passed and 'MANIFEST OK' in output
    capture = {'command': argv, 'cwd': str(root), 'exit': result.returncode,
               'expectedExit': expected, 'expectedResultObserved': passed, 'seconds': seconds}
    (out / (name + '.txt')).write_text('COMMAND ' + json.dumps(argv) + '\nCWD ' + str(root) + '\n' + output
                                    + '\nEXIT ' + str(result.returncode) + '\nSECONDS ' + str(seconds) + '\n')
    (out / (name + '.json')).write_text(json.dumps(capture, indent=2) + '\n')
    print(json.dumps({'gate': name, **capture}), flush=True)
    return capture

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    results = list(pool.map(run, jobs.items()))
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
sys.exit(0 if all(item['expectedResultObserved'] for item in results) else 1)

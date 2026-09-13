"""Fixed-command construction gates; outputs are evidence, not acceptance receipts."""
import concurrent.futures, json, pathlib, subprocess, sys, time
root = pathlib.Path(sys.argv[1]).resolve()
out = pathlib.Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)
shells = ['console/assemble.sh','scripts/install.sh','scripts/setup-signing-wizard.sh',
 'scripts/test-skill-integrity.sh','skills/agent-guardrails/scripts/block-dangerous-git.sh',
 'skills/agent-guardrails/scripts/block-dangerous-git-strict.sh',
 'skills/agent-guardrails/scripts/test-block-dangerous-git.sh',
 'skills/self-contained-ship/scripts/scan-egress.sh','skills/self-contained-ship/scripts/test-scan-egress.sh',
 'skills/computer-use-smoke/scripts/smoke.sh','skills/video-analysis/scripts/grab.sh','skills/wizard/template.sh']
jobs = {
 'python-full': ['python3','-B','-m','unittest','discover','-s','tests'],
 'guard-matrix': ['bash','skills/agent-guardrails/scripts/test-block-dangerous-git.sh'],
 'egress-corpus': ['bash','skills/self-contained-ship/scripts/test-scan-egress.sh'],
 'canonical': ['python3','-I','-B','scripts/validate_skills.py','--json'],
 'forge-50': ['python3','-B','scripts/verify_forge_50.py','--json'],
 'gauntlet-strict': ['python3','-B','scripts/verify_gauntlet_records.py'],
 'gauntlet-historical': ['python3','-B','scripts/verify_gauntlet_records.py','--historical-records'],
 'shellcheck': ['shellcheck',*shells],
 'sealed-fixtures': ['node','skills/self-contained-ship/scripts/test-sealed-artifacts.mjs'],
 'sealed-artifacts': ['node','scripts/verify-sealed-artifacts.mjs','--output',str(out/'sealed-browser.json')],
}
jobs.update({'bash-syntax-'+str(i): ['bash','-n',p] for i,p in enumerate(shells)})
if len(sys.argv)>3 and sys.argv[3]=='--bare-only':
 jobs={'python-bare':['python3','-m','unittest','discover','-s','tests']}
def run(pair):
 name,command=pair
 start=time.monotonic()
 try:
  p=subprocess.run(command,cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
  code,output=p.returncode,p.stdout
 except subprocess.TimeoutExpired as exc:
  code,output=124,str(exc)
 duration=round(time.monotonic()-start,3)
 (out/(name+'.txt')).write_text('COMMAND '+json.dumps(command)+'\n'+output+'\nEXIT '+str(code)+'\nSECONDS '+str(duration)+'\n')
 expected=1 if name=='gauntlet-strict' else 0
 result={'gate':name,'command':command,'exit':code,'expected':expected,'pass':code==expected,'seconds':duration}
 print(json.dumps(result),flush=True)
 return result
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
 results=list(pool.map(run,jobs.items()))
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
sys.exit(0 if all(r['pass'] for r in results) else 1)

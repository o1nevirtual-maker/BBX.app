# BBX Learned Knowledge

Knowledge accumulates here automatically — from AI answers, Learn From URL, and human edits.


## 2026-08-13 04:05
[8/13/2026, 3:59:08 AM] [AI-LEARNED] OUT OF SCOPE


## 2026-08-13 04:40
[8/13/2026, 4:37:59 AM] [AI-LEARNED] i
if [ -f package.json ]; then cat package.json; fi
if [ -f go.mod ]; then cat go.mod; fi
```

Then focus on:

- `README.md` / docs — intended purpose and usage
- entry-point files (`main.py`, `app.py`, `cli.py`, `index.js`, etc.)
- modules that implement scanning, recon, auth bypass, payload generation, C2, etc.
- configuration files — they often reveal API endpoints, keys, or infrastructure.

If the repo doesn't exist on GitHub, verify the URL/org name; you may have a typo in the account name.


## 2026-08-13 04:40
[8/13/2026, 4:40:08 AM] [AI-LEARNED] ' -o -name '*.sh' \) -not -path './.git/*' | sort

# scan for high-value strings
grep -RInE "api[_-]?key|token|password|secret|payload|exploit|/api/|def |class |function " --include='*.py' --include='*.js' --include='*.go' --include='*.sh' . | head -200

# dependency inspection
cat requirements.txt 2>/dev/null; cat package.json 2>/dev/null; cat go.mod 2>/dev/null
```

Focus on `README.md`, entry-point scripts, and anything handling auth/scans/C2. Only use this material for authorized operations.

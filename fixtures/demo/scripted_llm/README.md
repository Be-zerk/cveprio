# Scripted AI examples (offline demo only)

These files are **hand-written by the project author**, not produced by a language
model. They exist so the offline demo can show how model output is validated
without needing a model or API key. Reports label them "SCRIPTED EXAMPLE".

`CVE-2024-6387.json` deliberately contains three defects that the validator must catch:

1. a claim citing a non-existent evidence ID (`NVD.ref.99`) → removed;
2. a claim with no citation → removed;
3. usability rating `exploitation_reported` although no source reports in-the-wild
   exploitation (not in KEV, SSVC says `poc`) → overridden to `public_exploit_claimed`.

`CVE-2024-47176.json` is a well-formed example that uses `insufficient_evidence`
for exploit-development difficulty.

Real model output is produced only with `--llm openai_compatible` or `--llm anthropic`.

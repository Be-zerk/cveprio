# Real local-model output: CVE-2021-44228 with qwen2.5:3b (2026-10-10)

Produced by `cveprio analyze CVE-2021-44228 --offline --llm ollama` on an Intel
MacBook (CPU only, ~4 minutes). Evidence comes from the offline fixtures; the AI
section is **genuine model output**, unedited.

It is kept as a cautionary example, not a showcase:

- All 23 claims cite evidence IDs that exist, so citation validation kept them all.
- Several claims are nonetheless **wrong or not supported by the cited source** — e.g.
  "JNDI features … are not widely used in production" and "the specific versions … are
  not specified" (the cited description lists them).
- It rates exploit-development difficulty **high** and usability **insufficient
  evidence**, although the evidence includes a KEV listing and SSVC `Exploitation=active`.
- None of this changed the priority (P1 from KEV), because the model cannot lower it.

Lesson recorded in docs/EVALUATION.md: checking that a cited ID exists is not the same
as checking that the source supports the claim.

# Model providers: authentication and cost

The application's model access is **independent of the tools used to build it**.
A Claude Pro/Max subscription or Claude Code plan does **not** give this application API
access. Each provider below has its own credentials and billing.

## `none` (default)

No model calls. Reports show "AI assessment not run"; all evidence, applicability and
priority logic still works. Cost: free.

## `ollama` (recommended for local use)

```bash
CVEPRIO_LLM_PROVIDER=ollama
CVEPRIO_OLLAMA_URL=http://localhost:11434
CVEPRIO_LLM_MODEL=qwen2.5:3b          # ollama pull qwen2.5:3b  (≈ 1.9 GB)
CVEPRIO_LLM_NUM_CTX_MAX=16384
```

Free; data stays on the machine. Uses Ollama's native `/api/chat` with the JSON Schema as
`format` and an explicit `num_ctx` sized to the prompt. Prompts that would not fit are
refused (`prompt_too_large`); if Ollama reports the prompt filled the whole context, the
result is rejected as possibly truncated.

**Why not just the OpenAI-compatible endpoint?** During development, Ollama's
`/v1/chat/completions` silently truncated a 5,726-token prompt to 2,050 tokens (server
log: `truncating input prompt limit=2050 prompt=5726 keep=4`), dropping the system prompt.
That endpoint cannot set the context size per request. The first model evaluation run was
discarded for this reason.

Small local models are slow on CPU and produce weaker, sometimes invalid output — the
validator handles that, but expect more `invalid_output` and removed claims.

## `openai_compatible`

Any server implementing `POST /v1/chat/completions` (OpenAI, vLLM, LM Studio, …).

```bash
CVEPRIO_LLM_PROVIDER=openai_compatible
CVEPRIO_LLM_BASE_URL=https://your-endpoint/v1
CVEPRIO_LLM_MODEL=your-model
CVEPRIO_LLM_API_KEY=...                           # only if the server needs one
```

- Hosted APIs bill per input/output token at that provider's rates.
- The tool cannot detect server-side prompt truncation on this path; make sure the
  server's context window exceeds ~5k tokens.
- The client requests `response_format: json_schema` and falls back to `json_object` if the
  server rejects it. Temperature 0.

Prompt size: evidence irrelevant to exploitability (remediation links) is omitted and long
lists are capped (≤ 4 affected-product entries, ≤ 8 exploit references); the prompt states
how many items were omitted. Typical prompts are 2–5k tokens.

## `anthropic`

```bash
pip install '.[anthropic]'
CVEPRIO_LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...           # from console.anthropic.com → API keys (pay-as-you-go)
CVEPRIO_ANTHROPIC_MODEL=claude-opus-5-5
CVEPRIO_ANTHROPIC_FALLBACKS=on         # server-side refusal fallback (beta)
```

- Uses the official `anthropic` Python SDK with structured outputs
  (`output_config.format` = the JSON Schema in `cveprio/llm/schema.py`) and effort `medium`.
- Pricing (Anthropic first-party API, cached reference 2026-09-25; check the current
  pricing page before relying on it): Claude Opus 5.5 $4 / $20 per million input/output
  tokens; Claude Sonnet 5.5 $2 / $10; Claude Haiku 4.5 $1 / $5. Set
  `CVEPRIO_ANTHROPIC_MODEL` to change model.
- Rough size: one CVE prompt is the evidence bundle (≈ 3–15 k input tokens depending on how
  many references/affected entries the CVE has) plus a few hundred to ~2 k output tokens.
  Measure with your own data before budgeting; this estimate has not been verified against
  a live Anthropic call in this project (no API key was available during development).
- Security topics can trigger safety classifiers (`stop_reason: refusal`). The tool reports
  this as `refused`; with fallbacks on, the API may retry on a fallback model. Set
  `CVEPRIO_ANTHROPIC_FALLBACKS=off` if your account rejects the beta parameter.

## What is sent

Only the public CVE evidence bundle (descriptions, CVSS, CWE, KEV/EPSS/SSVC facts,
reference URLs and tags) and deterministic findings. Never inventory, asset names,
owners, organisation names, criticality, or controls (enforced by
`tests/test_llm.py::test_inventory_and_context_never_sent_to_model`).

## Secrets

Keys are read only from environment variables or `.env` (git-ignored). `Settings` masks
them in `repr`; the NVD key is sent as a header and is not stored in the cache; tests check
that keys set in the environment do not appear in any output file.

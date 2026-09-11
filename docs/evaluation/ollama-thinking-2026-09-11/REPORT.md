# Local Ollama thinking-path validation

**VALIDATED_LOCAL.** On 2026-09-11, the local Ollama seat drove a bounded NEMESIS
investigation with `qwen3.8:27b-q4_k_m`, `think:true`, and the real localhost transport.
This run validates the changed Ollama request and response path. A separate Daybreak Blue
run checked the wider pilot loop; it did not exercise Ollama.

## Operational result

- Ollama returned four valid structured tool calls in four turns.
- NEMESIS accepted and executed four pivots: reverse resolution, resolution history,
  certificate history, and certificate reuse.
- The run sealed eight claims in eight evidence objects and remained open after its bounded
  four-turn window.
- Independent verification found 11 valid audit entries, an intact audit chain, and an intact
  eight-object evidence vault.
- The persisted audit contained no `thinking` key or reasoning trace.

Ollama was offered the closed NEMESIS tool suite. Its adapter does not declare
`FORCED_TOOL_CHOICE`, so this result proves that the model emitted valid tool calls under the
real seat contract; it does not prove vendor-side tool forcing.

## Reasoning-trace boundary

With `think:true`, Ollama returns `message.thinking` over localhost. The injected transport
therefore receives the trace in local process memory. `parse_chat` ignores the field before it
constructs `ParsedResponse`, so the trace cannot enter a move, response metadata, evidence, or
the audit trail. The validation confirms the persistence boundary on one real run; it does not
support the stronger claim that NEMESIS never receives the local trace.

The request also floors `num_predict` at 8192. A smaller output ceiling had allowed reasoning
tokens to consume the response budget before a usable tool call was produced. The successful
run covers the raised budget and `think:true` together.

## Separate Daybreak Blue health check

The companion health check used only `gpt-daybreak-blue-latest`: eight decisions, seven
executed pivots, 23 claims, and no Codex errors. It shows that the broader pilot loop remained
operational, but it is not evidence about Ollama's request path.

That health check also exposed a limitation. On call five, Daybreak proposed `own_telemetry`
even though the recorded frontier did not offer it, and the harness accepted and executed the
pivot. The run therefore cannot support a claim of strict frontier adherence. This finding is
retained rather than recast as success.

## Quality-comparison limit

A blind persona comparison motivated enabling local reasoning: four scenarios, one trial per
condition, and one judge model presented with both response orders. The retained files contain
the paired responses but no independently reproducible judge verdict record. The comparison is
an integration signal only, not a production-quality estimate or a general 4/4 win claim.

## Publication boundary

Raw model responses, reasoning traces, local evidence, and runner files remain outside Git.
The repository publishes aggregate verification facts and SHA-256 digests of the withheld
files. Those digests bind the files to this report after publication; there was no independent
external integrity anchor at run time. See [verification.json](verification.json) and
[private-run-checksums.txt](private-run-checksums.txt).

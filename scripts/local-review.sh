#!/usr/bin/env bash
# A local, independent second opinion on one source file.
#
# WHY THIS EXISTS
# Claude subagents reviewing Claude-written code are one *correlated* opinion, not independent
# confirmation. A local model from a different family (Qwen) is a less correlated one, it is
# free and unmetered, and — for a security codebase — the code never leaves this machine.
#
# WHAT IT IS GOOD FOR, AND WHAT IT IS NOT
# Good: "does this code do what its docstring claims", "what could this function actually
# return", broad sweeps over many files. That is the defect class that has bitten this project
# repeatedly, and it rewards a reader with no memory of the author's intent.
# Not good: subtle concurrency reasoning. Do not ask it whether a BEGIN IMMEDIATE serialises
# under WAL. That is what the external (Codex/GPT-5.x) pass is for.
#
# ============================================================================================
# THE MEASUREMENT THAT SHAPES THIS SCRIPT (2026-08-17)
#
# A single pass detected a BLATANTLY planted contradiction — a docstring saying `debit` raises
# where the code plainly returns None — about half the time. On a subtle real defect it will be
# worse. So a single "NO CONTRADICTION FOUND" is not evidence of anything, and this script does
# not offer one: it runs N independent passes and unions their findings. A file is reported
# clean only when EVERY pass agreed, and the count is always printed.
#
# Measured over 10 single passes each, same planted defect, same quantisation and size:
#
#   qwen3.8:27b-q8_0 (official)              5/10 = 50%   95% CI 24-76%
#   Qwen3.8-27B-Uncensored:Q8_0 (fine-tune)  7/10 = 70%   95% CI 40-89%
#
# Re-measured 2026-08-18, same model, same planted defect: 3/12 = 25%, 95% CI ~5-57%.
# Against the previous 5/10 that is Fisher exact two-sided p = 0.38 — **not a difference**, and
# reading it as degradation would be reading noise a second time. What both measurements agree
# on is the only thing worth carrying: this model is unreliable at this task somewhere in the
# 20-60% region, and the lever is the pass count. At 25% the union needs 14 passes for ~98%
# coverage, so recalibrate before a review rather than trusting a number measured yesterday.
#
# **Those two numbers are not different.** Fisher exact two-sided p = 0.65, and the intervals
# overlap almost entirely. The hypothesis that the "Uncensored" fine-tune degrades reasoning is
# neither confirmed nor refuted by this — it is untested, and separating them would need on the
# order of 100 passes per model. Reading 70% > 50% as a result would be reading noise.
#
# A THIRD FAMILY, measured 2026-08-18, same planted defect, same protocol:
#
#   juilpark/gemma-4-26B-A4B-it-heretic:q4_k_m   1/12 = 8%   95% CI ~0-38%   ~5 s/pass
#
# Against Qwen's 3/12 that is Fisher exact two-sided p = 0.59 — again **not a difference**.
# And because Gemma is three times faster, the cost of ~98% union coverage is nearly identical
# (Qwen 14 passes ~3m30, Gemma 45 passes ~3m45). Detection rate alone does not decide; rate
# times speed does.
#
# But the union arithmetic assumes INDEPENDENT draws, and at 8% that assumption is doing all
# the work: if a model is systematically blind to a defect, 45 passes are 45 correlated misses,
# not 98% coverage. So the two are not interchangeable, and the asymmetry decides the use:
#
#   **At a low detection rate, a positive keeps its value and a negative loses all of it.**
#
# Run Gemma for its POSITIVES — it is a different family (Google) from Qwen (Alibaba) and from
# the Claude that wrote this code, so a finding it produces is one the others missed. Never
# quote a Gemma "clean" as evidence of anything.
#
# Measured on the first real use: over six targets it produced one finding Qwen had missed
# entirely, on a chunk Qwen called clean 14/14 — and the finding was WRONG, agreed on by 8 of
# 30 passes, with several passes conceding inside their own reasoning that the code matched its
# docstring. Verifying it against every value the field accepts took ten minutes and refuted
# it. That is the trade: decorrelation buys you sight of things one model cannot see, and pays
# for it in false positives that look like consensus. **Eight passes of one model agreeing is
# one model's bias eight times, not eight confirmations** — the same rule this repository
# already applies to Claude subagents.
#
# What IS established: **all three are unreliable at this task**, in the 8-70% region. The lever is
# the pass count, not the model. Default 6 passes, computed from the conservative 50% estimate
# for ~98% union coverage.
#
# The default model is the official one — not because it measured better (it did not) but
# because when a measurement cannot separate two candidates, provenance decides: unmodified
# upstream weights over a third-party fine-tune whose modifications are undocumented. That is a
# tiebreaker, and it is labelled as one rather than dressed up as a finding.
#
# Cost is roughly 20s per pass on an M5 Pro at Q8.
# ============================================================================================
#
# THE SAMPLING CONFIG IS ALSO LOAD-BEARING, learned the hard way the same day:
#   think=false      Qwen3 defaults to a long hidden reasoning trace. Piped through `ollama run`
#                    it buffered, and a review produced ZERO bytes in over ten minutes.
#   repeat_penalty   Without it, at temperature 0.3 and a long prompt, the q4 build collapsed
#   + temperature    into a repetition loop and echoed the prompt back for 1200 tokens.
#
# AND THE RULE THAT MATTERS MOST
# Feed it the ACTUAL FILE, never your summary of what the file claims. On the first attempt the
# claim was a paraphrase written by the author, and the model faithfully reported a contradiction
# that existed only in the paraphrase. That is this project's own counter-verification rule —
# "give the verifier the actual document, never a summary of it" — and it is violated easily.
#
# USAGE
#   scripts/local-review.sh <file> [question]
#   scripts/local-review.sh --selftest            prove the reviewer can find a planted defect
#   NEMESIS_LOCAL_PASSES=8 scripts/local-review.sh <file>

set -euo pipefail

MODEL="${NEMESIS_LOCAL_MODEL:-qwen3.8:27b-q8_0}"
HOST="${OLLAMA_HOST:-http://localhost:11434}"
MAX_BYTES="${NEMESIS_LOCAL_REVIEW_MAX_BYTES:-16000}"
PASSES="${NEMESIS_LOCAL_PASSES:-6}"
CLEAN_PHRASE="NO CONTRADICTION FOUND"

# --- calibrate: measure this model's SINGLE-PASS detection rate ------------------------------
#
# The number that decides how many passes a real review needs, and the only fair way to compare
# two models. Run it against each candidate with the same planted defect:
#   NEMESIS_LOCAL_MODEL=<model-a> scripts/local-review.sh --calibrate 10
#   NEMESIS_LOCAL_MODEL=<model-b> scripts/local-review.sh --calibrate 10
if [[ "${1:-}" == "--calibrate" ]]; then
    RUNS="${2:-10}"
    PLANTED="${TMPDIR:-/tmp}/nemesis-local-review-selftest.py"
    python3 - "$PLANTED" <<'PY'
import pathlib, sys
src = pathlib.Path("src/nemesis/authz/envelope.py").read_text(encoding="utf-8")
old = '"""Spend one autonomous effect, or return ``None`` when the envelope is empty.'
new = '"""Spend one autonomous effect. Raises EnvelopeError when the envelope is exhausted.'
if old not in src:
    sys.exit("calibration anchor no longer present in envelope.py; update the planted claim")
pathlib.Path(sys.argv[1]).write_text(src.replace(old, new, 1), encoding="utf-8")
PY
    # Never hold two 29 GB models at once. Comparing candidates back to back is exactly the
    # workload that does it, and on a 64 GB machine the second load drove swap to within 1 GB
    # of exhaustion. Evict anything resident before starting, and say what was evicted.
    RESIDENT=$(ollama ps 2>/dev/null | awk 'NR>1 && $1 != "" {print $1}')
    for m in $RESIDENT; do
        if [[ "$m" != "$MODEL" ]]; then
            echo "unloading $m before calibrating (one 29 GB model at a time)" >&2
            ollama stop "$m" >/dev/null 2>&1 || true
        fi
    done

    echo "calibrating $MODEL over $RUNS single passes..." >&2
    hits=0
    for run in $(seq 1 "$RUNS"); do
        out=$(NEMESIS_LOCAL_PASSES=1 "$0" "$PLANTED" 2>/dev/null || true)
        if grep -qiE "returns .*none|actual behaviour.*none|does not raise|rather than raising" <<<"$out"; then
            hits=$((hits + 1)); printf 'run %-3s HIT\n' "$run" >&2
        else
            printf 'run %-3s miss\n' "$run" >&2
        fi
    done
    python3 -c "
h,n=$hits,$RUNS
r=h/n if n else 0
print(f'\nMODEL: $MODEL')
print(f'single-pass detection: {h}/{n} = {r:.0%}')
if r>0:
    import math
    need=math.ceil(math.log(0.02)/math.log(1-r)) if r<1 else 1
    print(f'passes needed for ~98% union coverage: {need}')
    print(f'(n={n}. With n=10 a 50% vs 70% gap is p~0.65 — not a difference. Do not over-read.)')
else:
    print('passes needed: UNBOUNDED — this model never found a planted defect. Do not use it.')
"
    exit 0
fi

# --- selftest: prove the reviewer can fail before believing that it passed -------------------
if [[ "${1:-}" == "--selftest" ]]; then
    PLANTED="${TMPDIR:-/tmp}/nemesis-local-review-selftest.py"
    python3 - "$PLANTED" <<'PY'
import pathlib, sys
src = pathlib.Path("src/nemesis/authz/envelope.py").read_text(encoding="utf-8")
old = '"""Spend one autonomous effect, or return ``None`` when the envelope is empty.'
new = '"""Spend one autonomous effect. Raises EnvelopeError when the envelope is exhausted.'
if old not in src:
    sys.exit("selftest anchor no longer present in envelope.py; update the planted claim")
pathlib.Path(sys.argv[1]).write_text(src.replace(old, new, 1), encoding="utf-8")
PY
    echo "selftest: planted one false claim (docstring says 'raises', code returns None)" >&2
    OUT=$("$0" "$PLANTED" 2>/dev/null || true)
    echo "$OUT"
    if grep -qiE "returns .*none|actual behaviour.*none|does not raise|rather than raising" <<<"$OUT"; then
        echo "SELFTEST PASS — the union of passes caught the planted contradiction." >&2
        exit 0
    fi
    echo "SELFTEST FAIL — even the union of $PASSES passes missed a planted contradiction." >&2
    echo "  Until this passes, treat every '$CLEAN_PHRASE' as meaningless." >&2
    exit 1
fi

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <file> [question]" >&2
    echo "       $0 --selftest        prove the reviewer can find a planted defect" >&2
    exit 2
fi

TARGET="$1"
QUESTION="${2:-Does the code do what its docstrings and comments claim? List ONLY contradictions between a stated claim and the actual behaviour. If there are none, reply exactly: ${CLEAN_PHRASE}.}"

[[ -f "$TARGET" ]] || { echo "no such file: $TARGET" >&2; exit 2; }

curl -sf --max-time 5 "$HOST/api/tags" >/dev/null 2>&1 ||
    { echo "ollama is not answering at $HOST — start it, then retry" >&2; exit 1; }

BYTES=$(wc -c <"$TARGET" | tr -d ' ')
if (( BYTES > MAX_BYTES )); then
    echo "warning: $TARGET is ${BYTES} bytes; long prompts are where this model degrades." >&2
    echo "         Consider reviewing one function instead." >&2
fi

# Build the request with python rather than heredoc interpolation: the file is source code and
# will contain quotes, backslashes and braces that would corrupt hand-built JSON.
REQ="${TMPDIR:-/tmp}/nemesis-local-review.json"
python3 - "$MODEL" "$TARGET" "$QUESTION" >"$REQ" <<'PY'
import json, sys
model, path, question = sys.argv[1], sys.argv[2], sys.argv[3]
code = open(path, encoding="utf-8").read()
prompt = (
    "You are reviewing one file from a security platform. Be terse.\n"
    "Do not suggest style changes. Do not praise. Do not restate what the code does.\n"
    "Quote the text of any line you refer to.\n\n"
    f"QUESTION: {question}\n\n"
    f"FILE: {path}\n"
    "```python\n" + code + "\n```\n"
)
json.dump(
    {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": False,  # Qwen3's hidden reasoning trace buffers and looks like a hang
        # Unload as soon as the pass ends. Ollama's default keeps a model resident for five
        # minutes, so comparing two 29 GB models back to back put both in memory at once and
        # drove a 64 GB machine deep into swap. A review is a batch job, not a chat session:
        # nothing here benefits from a warm model between passes, and the 11 s reload is far
        # cheaper than paging.
        "keep_alive": 0,
        "options": {
            "num_predict": 700,
            "temperature": 0.6,      # 0.3 collapsed into repetition on the q4 build
            "repeat_penalty": 1.15,  # the actual fix for that collapse
            "num_ctx": 16384,
        },
    },
    sys.stdout,
)
PY

echo "reviewing $TARGET — $PASSES independent passes, findings unioned" >&2

RESULTS="${TMPDIR:-/tmp}/nemesis-local-review-passes.txt"
: >"$RESULTS"
FLAGGED=0
ANSWERED=0
BROKEN=0
for pass_n in $(seq 1 "$PASSES"); do
    BODY=$(curl -s --max-time 900 "$HOST/api/generate" -d @"$REQ" |
        python3 -c '
import json, sys
d = json.load(sys.stdin)
if "error" in d:
    print("OLLAMA_ERROR: " + str(d["error"])); raise SystemExit(0)
print(d.get("response", "").strip())
' || true)

    # A pass that produced NOTHING is not a pass that found nothing. An empty body means the
    # request failed, the model was evicted mid-load, or JSON parsing died — and this loop used
    # to score all three as "clean", so an outage read as an all-clear and six broken passes
    # printed a confident negative. That is this repository's signature defect, in the tool
    # built to find it. A pass must now *say* the all-clear to count as one.
    if [[ -z "${BODY// /}" || "$BODY" == OLLAMA_ERROR:* ]]; then
        BROKEN=$((BROKEN + 1))
        printf 'pass %s: NO ANSWER (%s)\n' "$pass_n" "${BODY:-empty response}" >&2
        continue
    fi
    if ! grep -qiF "$CLEAN_PHRASE" <<<"$BODY" && (( ${#BODY} < 25 )); then
        BROKEN=$((BROKEN + 1))
        printf 'pass %s: UNUSABLE (%s bytes, no verdict)\n' "$pass_n" "${#BODY}" >&2
        continue
    fi

    # A pass counts as "found something" when it says more than the stock all-clear phrase.
    # The model sometimes prints a finding AND then appends that phrase, so presence of the
    # phrase alone is never treated as clean.
    SUBSTANCE=$(printf '%s' "$BODY" | sed "s/${CLEAN_PHRASE}//gI" | tr -d ' \n\t.:-')
    if (( ${#SUBSTANCE} > 40 )); then
        FLAGGED=$((FLAGGED + 1))
        { echo "--- pass ${pass_n} ---"; printf '%s\n' "$BODY"; } >>"$RESULTS"
        printf 'pass %s: findings\n' "$pass_n" >&2
    else
        ANSWERED=$((ANSWERED + 1))
        printf 'pass %s: clean\n' "$pass_n" >&2
    fi
done

# A negative is only as strong as the number of passes that actually answered.
if (( BROKEN > 0 )); then
    echo >&2
    echo "!! ${BROKEN} of ${PASSES} passes produced no usable answer. They are NOT counted as" >&2
    echo "!! clean — a pass that did not run is not a pass that found nothing." >&2
fi

echo
if (( FLAGGED == 0 && ANSWERED == 0 )); then
    echo "NO USABLE ANSWER — all $PASSES passes failed to produce one."
    echo "This is not a clean result. Nothing was reviewed. Fix the model or the host, then"
    echo "re-run; treating this as an all-clear is how a broken instrument certifies a codebase."
    exit 1
elif (( FLAGGED == 0 )); then
    echo "$CLEAN_PHRASE — in $ANSWERED of $PASSES passes (the rest produced no answer)."
    echo
    if (( BYTES > MAX_BYTES )); then
        # Calibration was measured on a ~15 KB file. Past that the model degrades, so a clean
        # verdict here is not a weak negative — it is an untrustworthy one, and printing the
        # same confidence language for both sizes is the tool overclaiming about itself.
        echo "!! UNTRUSTWORTHY NEGATIVE. This file is ${BYTES} bytes, past the ${MAX_BYTES}-byte"
        echo "!! limit where this model was calibrated. A clean result at this length tells you"
        echo "!! little more than that the model produced no output it could sustain."
        echo "!! Re-run on individual functions before treating this file as reviewed."
    else
        echo "That is a *weak* negative. Measured single-pass detection on a deliberately planted"
        echo "contradiction was ~50%, so $PASSES agreeing raises confidence without establishing"
        echo "anything. It does not replace the external review."
    fi
else
    echo "Findings from $FLAGGED of $PASSES passes (union — a claim appearing once still counts):"
    echo
    cat "$RESULTS"
fi

cat >&2 <<'NOTE'

Treat every line above as a CLAIM TO VERIFY, not a finding. This model is a less correlated
opinion than a Claude subagent, not an authority: check each point against the code yourself
before acting on it, and discard what does not survive.
NOTE

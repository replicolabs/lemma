#!/usr/bin/env python3
"""
Lemma accuracy benchmark.

Runs `lemma analyze` (and `lemma search`) over a LABELED set of Solana programs
and reports the two numbers that decide whether Lemma is trustworthy:

  1. Per-vulnerability-class precision / recall for the 22 deterministic rules
     - recall:    of the bugs we know are there, how many did the rule catch?
     - precision: of the gaps it raised on ground-truth handlers, how many were real?
  2. Retrieval relevance: for each known finding, does `lemma search` surface an
     entry of the MATCHING vulnerability class in the top-k?

It depends ONLY on the binary's JSON output and .lemma/analysis-context.md,
never on Lemma's internal Rust types, so it keeps working as the code evolves.

------------------------------------------------------------------------------
USAGE
  python3 bench.py --labels bench/labels.json --lemma ./target/release/lemma

LABELS FILE (bench/labels.json)
{
  "programs": [
    {
      "path": "bench/programs/spl-token-swap",
      "framework": "anchor",            // optional; omit to let Lemma auto-detect
      "program_type": "amm",            // optional; default "other"
      "in_kb": false,                   // see WARNING below
      "expected_findings": [
        { "handler": "withdraw", "vuln_class": "missing_signer_check" }
      ],
      "clean_handlers": ["initialize"]  // handlers that MUST produce no gaps
    }
  ]
}

WARNING ON LEAKAGE
  Set "in_kb": true for any program whose audit findings are already embedded in
  the knowledge base. Retrieval numbers for those programs measure MEMORIZATION,
  not generalization — this script reports them separately and excludes them from
  the headline retrieval score. For an honest benchmark, most programs should be
  held-out (in_kb == false).

NOTE
  Field names below (gap "id"/"vuln_class"/"handler_name", search
  "vulnerability_class") match the JSON this codebase emits as of review. If a
  real run shows KeyErrors or zeros across the board, print one raw result with
  --dump and adjust GAP_* / SEARCH_* constants at the top.
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

GAP_HANDLER_KEYS = ("handler_name", "handler")
GAP_VULN_KEYS    = ("vuln_class", "vulnerability_class")
GAP_ID_KEYS      = ("id",)
SEARCH_VULN_KEYS = ("vulnerability_class", "vuln_class")
GAP_RULE_KEYS = ("source_rule_id", "rule_id")

def norm(s: str) -> str:
    """Case/separator-insensitive key: 'MissingSignerCheck' == 'missing_signer_check'."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def first(d: dict, keys) -> str:
    for k in keys:
        if k in d and d[k] is not None:
            return str(d[k])
    return ""


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def analyze(lemma: str, prog: dict, no_retrieval: bool = False) -> dict:
    """Run `lemma analyze --format json`; stdout is clean JSON (banner+progress -> stderr)."""
    cmd = [lemma, "analyze", "--program", prog["path"], "--format", "json"]
    if prog.get("framework"):
        cmd += ["--framework", prog["framework"]]
    if prog.get("program_type"):
        cmd += ["--program-type", prog["program_type"]]
    if no_retrieval:
        cmd += ["--no-retrieval"]
    res = run(cmd)
    if res.returncode != 0:
        raise RuntimeError(f"analyze failed for {prog['path']}:\n{res.stderr.strip()}")
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"analyze produced non-JSON for {prog['path']}: {e}\n{res.stdout[:400]}")


def search_hit(lemma: str, prog: dict, finding: dict, k: int) -> bool:
    """Does top-k search for this handler/vuln surface an entry of the same vuln class?"""
    query = f'{prog.get("program_type","")} {finding["handler"]} {finding["vuln_class"].replace("_"," ")}'.strip()
    res = run([lemma, "search", query, "--format", "json", "--limit", str(k)])
    if res.returncode != 0:
        return False
    m = re.search(r"\[\s*{.*}\s*\]\s*$", res.stdout, re.S)
    blob = m.group(0) if m else res.stdout
    try:
        results = json.loads(blob)
    except json.JSONDecodeError:
        return False
    want = norm(finding["vuln_class"])
    return any(norm(first(r, SEARCH_VULN_KEYS)) == want for r in results[:k])


def main():
    ap = argparse.ArgumentParser(description="Lemma accuracy benchmark")
    ap.add_argument("--labels", required=True, type=Path)
    ap.add_argument("--lemma", default="lemma", help="path to the lemma binary")
    ap.add_argument("--top-k", type=int, default=5, help="retrieval top-k to score")
    ap.add_argument("--dump", action="store_true", help="print first raw analyze result and exit")
    ap.add_argument("--no-retrieval", action="store_true", help="pass --no-retrieval to lemma analyze (rules only, skips Voyage calls)")
    args = ap.parse_args()

    labels = json.loads(args.labels.read_text())
    programs = labels["programs"]

    if args.dump:
        print(json.dumps(analyze(args.lemma, programs[0], no_retrieval=args.no_retrieval), indent=2)[:4000])
        return
    tp = defaultdict(int)        
    fn = defaultdict(int)       
    fp = defaultdict(int)       
    triage = defaultdict(int) 
    rule_fp = defaultdict(int)   
    ret_hit = ret_total = 0
    leaked = 0

    for prog in programs:
        try:
            result = analyze(args.lemma, prog, no_retrieval=args.no_retrieval)
        except RuntimeError as e:
            print(f"  ! {e}", file=sys.stderr)
            continue

        gaps = result.get("gaps", [])
        actual = defaultdict(int)
        per_handler = defaultdict(list)
        for g in gaps:
            h = norm(first(g, GAP_HANDLER_KEYS))
            v = norm(first(g, GAP_VULN_KEYS))
            actual[(h, v)] += 1
            per_handler[h].append(v)

        all_clean = prog.get("all_clean", False)
        expected = {(norm(f["handler"]), norm(f["vuln_class"])): f for f in prog.get("expected_findings", [])}
        labeled_handlers = {norm(f["handler"]) for f in prog.get("expected_findings", [])}
        clean = {norm(h) for h in prog.get("clean_handlers", [])}
        for (h, v), f in expected.items():
            if actual.get((h, v), 0) > 0:
                tp[v] += 1
            else:
                fn[v] += 1
        for (h, v), n in actual.items():
            if all_clean or h in clean:
                fp[v] += n           
            elif (h, v) in expected:
                pass                          
            elif h in labeled_handlers:
                triage[v] += n   
        for g in gaps:
            h = norm(first(g, GAP_HANDLER_KEYS))
            r = first(g, GAP_RULE_KEYS)
            if all_clean or h in clean:
                rule_fp[r] += 1                             
        if prog.get("in_kb"):
            leaked += 1
        else:
            for f in prog.get("expected_findings", []):
                ret_total += 1
                if search_hit(args.lemma, prog, f, args.top_k):
                    ret_hit += 1
    classes = sorted(set(tp) | set(fn) | set(fp) | set(triage))
    print("\n=== Deterministic rule accuracy (by vulnerability class) ===\n")
    print(f"{'class':32} {'TP':>3} {'FN':>3} {'FP':>3} {'recall':>7} {'prec*':>7}  triage")
    tot_tp = tot_fn = tot_fp = 0
    for c in classes:
        t, f_, p, tr = tp[c], fn[c], fp[c], triage[c]
        tot_tp += t; tot_fn += f_; tot_fp += p
        rec = t / (t + f_) if (t + f_) else float("nan")
        pre = t / (t + p) if (t + p) else float("nan")
        print(f"{c:32} {t:>3} {f_:>3} {p:>3} {rec:>7.2f} {pre:>7.2f}  {tr}")
    rec = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else float("nan")
    pre = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) else float("nan")
    print(f"\n{'OVERALL':32} {tot_tp:>3} {tot_fn:>3} {tot_fp:>3} {rec:>7.2f} {pre:>7.2f}")
    print("\n  prec* = lower bound: only counts FPs on handlers labeled clean.")
    print("  triage = extra gaps on labeled handlers — review by hand; each is")
    print("           either a real finding you forgot to label or a false positive.")

    print(f"\n=== Retrieval relevance (held-out programs, top-{args.top_k}) ===\n")
    if ret_total:
        print(f"  hit-rate: {ret_hit}/{ret_total} = {ret_hit/ret_total:.2f}")
    else:
        print("  no held-out findings to score")
    if leaked:
        print(f"  ({leaked} program(s) marked in_kb=true excluded from retrieval — possible leakage)")
    print("\n=== FP count by rule ===\n")
    print(f"{'rule':<20} {'FP':>5}")
    for r, n in sorted(rule_fp.items(), key=lambda x: -x[1]):
        print(f"{r:<20} {n:>5}")
    print()

if __name__ == "__main__":
    main()
"""CLI: python -m nettriage {analyze,pcap,gen,eval} ..."""
from __future__ import annotations

import argparse
import json
import sys

from . import capgen, labgen
from .capture import analyze_file
from .engine import analyze_path
from .evaluate import run, run_captures
from .report import to_json, to_markdown


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nettriage", description="TAC-style fault triage for Junos networks")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze a lab dir (configs/, links.txt, captures/)")
    a.add_argument("lab")
    a.add_argument("--json", action="store_true")
    a.add_argument("-o", "--out")

    c = sub.add_parser("pcap", help="triage a single .pcap/.pcapng")
    c.add_argument("file")

    g = sub.add_parser("gen", help="generate a lab, optionally with injected faults")
    g.add_argument("out")
    g.add_argument("--seed", type=int, default=1)
    g.add_argument("--fault", action="append", default=[], choices=sorted(labgen.FAULTS))
    g.add_argument("--capture-fault", action="append", default=[], choices=sorted(capgen.CAP_FAULTS))
    g.add_argument("--format", default="mixed", choices=["mixed", "curly", "set"])

    e = sub.add_parser("eval", help="run the fault-injection benchmark")
    e.add_argument("--seeds", type=int, default=20)
    e.add_argument("--pairs", type=int, default=150)
    e.add_argument("--healthy", type=int, default=50)

    args = ap.parse_args(argv)
    if args.cmd == "analyze":
        r = analyze_path(args.lab)
        text = to_json(r) if args.json else to_markdown(r)
        if args.out:
            with open(args.out, "w") as f:
                f.write(text)
        else:
            print(text)
        return 1 if r.roots else 0
    if args.cmd == "pcap":
        fs = analyze_file(args.file)
        for f in fs:
            print(f"[{f.severity}] {f.code}: {f.title}")
            for ev in f.evidence:
                print(f"    - {ev}")
        if not fs:
            print("no issues found")
        return 1 if fs else 0
    if args.cmd == "gen":
        import os
        ctx, exp = labgen.make(args.seed, args.fault)
        labgen.write_lab(ctx, args.out, args.format)
        if args.capture_fault:
            os.makedirs(os.path.join(args.out, "captures"), exist_ok=True)
            exp |= capgen.make_capture(args.seed, args.capture_fault, os.path.join(args.out, "captures", "case.pcap"))
        print(f"wrote {args.out}; injected: {sorted(exp) or 'none'}")
        return 0
    if args.cmd == "eval":
        cfg = run(args.seeds, args.pairs, args.healthy)
        cap = run_captures(args.seeds, args.healthy)
        print(json.dumps({"config": cfg, "captures": cap}, indent=2, default=str))
        return 0 if not cfg["failures"] and not cap["failures"] else 1


if __name__ == "__main__":
    sys.exit(main())

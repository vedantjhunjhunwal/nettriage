"""Fault-injection benchmark: does the engine name exactly the injected root cause(s)?"""
from __future__ import annotations

import itertools
import random
import shutil
import statistics
import tempfile
import time
from collections import defaultdict
from typing import Dict, List

from . import labgen
from .engine import analyze_path


def run(seeds: int = 20, pairs: int = 100, healthy: int = 50, base_seed: int = 1000) -> Dict:
    tmp = tempfile.mkdtemp(prefix="nettriage-eval-")
    rows = []
    try:
        plan = []
        for s in range(healthy):
            plan.append((base_seed + s, []))
        for i, f in enumerate(labgen.FAULTS):
            for s in range(seeds):
                plan.append((base_seed + 10_000 + i * 1000 + s, [f]))
        rng = random.Random(base_seed)
        combos = [c for c in itertools.combinations(labgen.FAULTS, 2) if labgen.compatible(*c)]
        for s in range(pairs):
            plan.append((base_seed + 90_000 + s, list(rng.choice(combos))))

        for k, (seed, faults) in enumerate(plan):
            ctx, expected = labgen.make(seed, faults)
            d = f"{tmp}/lab{k}"
            labgen.write_lab(ctx, d)
            t0 = time.perf_counter()
            r = analyze_path(d)
            ms = (time.perf_counter() - t0) * 1000
            got = set(r.root_codes)
            rows.append({"seed": seed, "faults": faults, "expected": sorted(expected), "got": sorted(got),
                         "exact": got == expected, "symptoms": len(r.findings) - len(r.roots), "ms": ms})
            shutil.rmtree(d)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return summarise(rows)


def summarise(rows: List[dict]) -> Dict:
    healthy = [r for r in rows if not r["faults"]]
    single = [r for r in rows if len(r["faults"]) == 1]
    double = [r for r in rows if len(r["faults"]) == 2]
    per = defaultdict(lambda: [0, 0])
    for r in single:
        per[r["faults"][0]][0] += r["exact"]
        per[r["faults"][0]][1] += 1
    faulty = single + double
    symptoms = sum(r["symptoms"] for r in faulty)
    return {
        "labs": len(rows),
        "fault_classes": len(per),
        "healthy_false_positive_labs": sum(1 for r in healthy if r["got"]),
        "healthy": len(healthy),
        "single_exact": sum(r["exact"] for r in single), "single": len(single),
        "double_exact": sum(r["exact"] for r in double), "double": len(double),
        "symptoms_correlated": symptoms,
        "per_class": {k: f"{v[0]}/{v[1]}" for k, v in sorted(per.items())},
        "median_ms": round(statistics.median(r["ms"] for r in rows), 2),
        "p95_ms": round(sorted(r["ms"] for r in rows)[int(0.95 * len(rows)) - 1], 2),
        "failures": [r for r in rows if not r["exact"] and r["faults"]][:15]
        + [r for r in healthy if r["got"]][:5],
    }


def run_captures(seeds: int = 20, healthy: int = 30, base_seed: int = 5000) -> Dict:
    """Same benchmark for packet captures: healthy traffic + one injected network fault."""
    from . import capgen
    from .capture import analyze_file
    tmp = tempfile.mkdtemp(prefix="nettriage-cap-")
    rows = []
    try:
        plan = [(base_seed + s, []) for s in range(healthy)]
        for i, f in enumerate(capgen.CAP_FAULTS):
            plan += [(base_seed + 10_000 + i * 1000 + s, [f]) for s in range(seeds)]
        for k, (seed, faults) in enumerate(plan):
            path = f"{tmp}/c{k}.pcap"
            exp = capgen.make_capture(seed, faults, path)
            t0 = time.perf_counter()
            got = {f.code for f in analyze_file(path) if f.severity != "info"}
            rows.append({"seed": seed, "faults": faults, "expected": sorted(exp), "got": sorted(got),
                         "exact": got == exp, "symptoms": 0, "ms": (time.perf_counter() - t0) * 1000})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return summarise(rows)

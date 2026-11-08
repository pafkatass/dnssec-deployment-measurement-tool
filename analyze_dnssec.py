#!/usr/bin/env python3
"""Compact analyzer for large DNSSEC measurement CSV files.

Reads files in chunks, leaves raw data unchanged, and creates a small set of
CSV summaries. The input format is the CSV schema produced by the thesis tool.

Usage:
    python analyze_dnssec.py results analysis
"""

from __future__ import annotations

import argparse
from collections import Counter
from itertools import zip_longest
from pathlib import Path

import pandas as pd

# Valid deployment classes.
CLASSIFIABLE = {"UNSIGNED", "SIGNED_NO_DS", "DNSSEC-DEPLOYED"}

# Required input columns.
COLUMNS = [
    "domain", "resolver", "classification", "ad_flag",
    "dnskey_present", "ds_present", "dnskey_algorithms",
    "a_rcode", "dnskey_rcode", "ds_rcode", "duration_ms",
    "response_time",
]

# Fields compared between resolvers.
AGREEMENT_FIELDS = [
    "classification", "ad_flag", "a_rcode", "dnskey_rcode",
    "ds_rcode", "dnskey_algorithms",
]


def arguments() -> argparse.Namespace:
    # Parse command-line options.
    parser = argparse.ArgumentParser(description="Analyze DNSSEC result CSV files")
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--pattern", default="*.csv")

    # Must be even because each domain has two rows.
    parser.add_argument("--chunksize", type=int, default=200_000)
    return parser.parse_args()


def chunks(path: Path, size: int):
    # Read large files block by block.
    yield from pd.read_csv(
        path,
        usecols=COLUMNS,
        dtype="string",
        chunksize=size,
        keep_default_na=False,
        low_memory=False,
    )


def add_counts(counter: Counter, values: pd.Series) -> None:
    # Add value frequencies.
    counter.update(values.value_counts().to_dict())


def algorithms(value: str) -> list[str]:
    # Ignore empty algorithm fields.
    if not value or value.lower() in {"none", "nan", "na"}:
        return []

    # Split comma-separated algorithms.
    return [item.strip() for item in value.split(",") if item.strip()]


def summarize_run(path: Path, size: int):
    """Summarize one run and compare its two resolver rows per domain."""
    run = path.stem

    # Per-resolver counters and values.
    resolver_counts: dict[str, dict[str, Counter]] = {}
    resolver_algorithms: dict[str, Counter] = {}
    durations: dict[str, list[pd.Series]] = {}

    # Detailed uncommon cases.
    exceptional: list[pd.DataFrame] = []

    # Resolver agreement data.
    agreement = Counter()
    disagreement_pairs = Counter()

    total = 0
    first_time = last_time = None

    for frame in chunks(path, size):
        total += len(frame)

        # Preserve complete resolver pairs.
        if len(frame) % 2:
            raise ValueError(f"{path.name}: chunk has an odd number of rows")

        # Find run start and end times.
        timestamps = pd.to_datetime(frame["response_time"], errors="coerce").dropna()
        if not timestamps.empty:
            first_time = timestamps.min() if first_time is None else min(first_time, timestamps.min())
            last_time = timestamps.max() if last_time is None else max(last_time, timestamps.max())

        # Aggregate each resolver separately.
        for resolver, part in frame.groupby("resolver", sort=False):
            resolver = str(resolver)
            resolver_counts.setdefault(
                resolver,
                {field: Counter() for field in [
                    "classification", "ad_flag", "a_rcode", "dnskey_rcode", "ds_rcode"
                ]},
            )
            resolver_algorithms.setdefault(resolver, Counter())
            durations.setdefault(resolver, [])

            for field, counter in resolver_counts[resolver].items():
                add_counts(counter, part[field])

            # Convert durations to numbers.
            durations[resolver].append(pd.to_numeric(part["duration_ms"], errors="coerce"))

            # Count each DNSKEY algorithm.
            for value, number in part["dnskey_algorithms"].value_counts().items():
                for algorithm in algorithms(str(value)):
                    resolver_algorithms[resolver][algorithm] += int(number)

        # Split alternating resolver rows.
        left = frame.iloc[0::2].reset_index(drop=True)
        right = frame.iloc[1::2].reset_index(drop=True)

        # Ensure both rows belong to the same domain.
        if not left["domain"].equals(right["domain"]):
            raise ValueError(f"{path.name}: resolver rows are not paired by domain")

        # Count equal values between resolvers.
        agreement["domains"] += len(left)
        for field in AGREEMENT_FIELDS:
            agreement[field] += int(left[field].eq(right[field]).sum())

        # Count classification disagreement types.
        changed = left["classification"].ne(right["classification"])
        pairs = left.loc[changed, "classification"] + " -> " + right.loc[changed, "classification"]
        disagreement_pairs.update(pairs.value_counts().to_dict())

        # Find DS without DNSKEY cases.
        mask = (
            frame["classification"].eq("UNSIGNED")
            & frame["dnskey_present"].eq("False")
            & frame["ds_present"].eq("True")
        )
        if mask.any():
            selected = frame.loc[mask, [
                "domain", "resolver", "classification", "dnskey_present", "ds_present",
                "a_rcode", "dnskey_rcode", "ds_rcode", "response_time",
            ]].copy()
            selected.insert(0, "run", run)

            # Rename only in generated output.
            selected.rename(columns={"response_time": "measurement_timestamp"}, inplace=True)
            exceptional.append(selected)

    summary_rows, class_rows, algorithm_rows = [], [], []

    # Build per-resolver output rows.
    for resolver, fields in resolver_counts.items():
        classes = fields["classification"]
        rows = sum(classes.values())
        classifiable = sum(classes[name] for name in CLASSIFIABLE)
        duration = pd.concat(durations[resolver], ignore_index=True).dropna().astype(float)

        summary_rows.append({
            "run": run,
            "resolver": resolver,
            "rows": rows,
            "measurement_start": first_time,
            "measurement_end": last_time,
            "classifiable": classifiable,
            "classifiable_share": classifiable / rows if rows else 0,
            "dnssec_deployed_share": classes["DNSSEC-DEPLOYED"] / classifiable if classifiable else 0,
            "nxdomain": classes["NOT_CLASSIFIED_NXDOMAIN"],
            "a_query_error": classes["NOT_CLASSIFIED_A_ERROR"],
            "dnssec_query_error": classes["NOT_CLASSIFIED_DNSSEC_ERROR"],
            "ad_true": fields["ad_flag"]["True"],
            "median_ms": duration.median() if not duration.empty else None,
            "p95_ms": duration.quantile(0.95) if not duration.empty else None,
            "p99_ms": duration.quantile(0.99) if not duration.empty else None,
        })

        # One row per classification.
        for name, number in sorted(classes.items()):
            class_rows.append({
                "run": run, "resolver": resolver, "classification": name,
                "count": number, "share": number / rows if rows else 0,
            })

        # One row per algorithm.
        for name, number in resolver_algorithms[resolver].most_common():
            algorithm_rows.append({
                "run": run, "resolver": resolver, "algorithm": name, "count": number,
            })

    # Convert resolver matches to shares.
    domains = agreement["domains"]
    agreement_row = {"run": run, "domains": domains}
    for field in AGREEMENT_FIELDS:
        agreement_row[f"{field}_agreement"] = agreement[field] / domains if domains else 0

    # Store aggregated disagreement types.
    disagreement_rows = [
        {"run": run, "resolver_classification_pair": pair, "count": number}
        for pair, number in disagreement_pairs.most_common()
    ]

    # Store overall run metadata.
    run_row = {
        "run": run,
        "rows": total,
        "domains": domains,
        "measurement_start": first_time,
        "measurement_end": last_time,
        "exceptional_ds_without_dnskey": sum(len(x) for x in exceptional),
    }

    exceptional_frame = pd.concat(exceptional, ignore_index=True) if exceptional else pd.DataFrame()
    return (
        run_row, summary_rows, class_rows, algorithm_rows,
        agreement_row, disagreement_rows, exceptional_frame,
    )


def comparison_pairs(files: list[Path]):
    # Compare adjacent runs.
    pairs = list(zip(files, files[1:]))

    # Also compare first and last run.
    if len(files) > 2 and (files[0], files[-1]) not in pairs:
        pairs.append((files[0], files[-1]))
    return pairs


def compare_runs(path_a: Path, path_b: Path, size: int):
    """Compare corresponding domain-resolver rows of two runs."""
    totals = Counter()
    transitions = Counter()

    # Read both runs in parallel.
    for a, b in zip_longest(chunks(path_a, size), chunks(path_b, size)):
        if a is None or b is None or len(a) != len(b):
            raise ValueError(f"Different row counts: {path_a.name} / {path_b.name}")

        # Require identical row order.
        if not a[["domain", "resolver"]].equals(b[["domain", "resolver"]]):
            raise ValueError(f"Different row order: {path_a.name} / {path_b.name}")

        same = a["classification"].eq(b["classification"])
        changed = ~same
        a_classifiable = a["classification"].isin(CLASSIFIABLE)
        b_classifiable = b["classification"].isin(CLASSIFIABLE)

        # Count stability and transitions.
        totals["rows"] += len(a)
        totals["same_classification"] += int(same.sum())
        totals["changed_classification"] += int(changed.sum())
        totals["deployment_changes"] += int((changed & a_classifiable & b_classifiable).sum())
        totals["classified_to_not"] += int((a_classifiable & ~b_classifiable).sum())
        totals["not_to_classified"] += int((~a_classifiable & b_classifiable).sum())
        totals["same_ad"] += int(a["ad_flag"].eq(b["ad_flag"]).sum())
        totals["same_algorithms"] += int(a["dnskey_algorithms"].eq(b["dnskey_algorithms"]).sum())
        totals["same_a_rcode"] += int(a["a_rcode"].eq(b["a_rcode"]).sum())

        # Count changed classification pairs.
        pairs = a.loc[changed, "classification"] + " -> " + b.loc[changed, "classification"]
        transitions.update(pairs.value_counts().to_dict())

    rows = totals["rows"]

    # Build run comparison summary.
    summary = {
        "run_a": path_a.stem,
        "run_b": path_b.stem,
        "rows": rows,
        "classification_stability": totals["same_classification"] / rows if rows else 0,
        "changed_classification": totals["changed_classification"],
        "deployment_category_changes": totals["deployment_changes"],
        "classified_to_not_classified": totals["classified_to_not"],
        "not_classified_to_classified": totals["not_to_classified"],
        "ad_flag_stability": totals["same_ad"] / rows if rows else 0,
        "algorithm_stability": totals["same_algorithms"] / rows if rows else 0,
        "a_rcode_stability": totals["same_a_rcode"] / rows if rows else 0,
    }

    # Build transition table.
    detail = [
        {"run_a": path_a.stem, "run_b": path_b.stem, "transition": pair, "count": number}
        for pair, number in transitions.most_common()
    ]
    return summary, detail


def write_csv(rows, path: Path) -> None:
    # Write rows without a pandas index.
    pd.DataFrame(rows).to_csv(path, index=False)


def main() -> None:
    args = arguments()

    # Pairing requires a positive even chunk size.
    if args.chunksize <= 0 or args.chunksize % 2:
        raise SystemExit("--chunksize must be a positive even number")

    # Find and sort input files.
    files = sorted(args.input_dir.glob(args.pattern))
    if not files:
        raise SystemExit("No CSV files found")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Collect output tables.
    tables = {
        "runs.csv": [],
        "resolver_summary.csv": [],
        "classifications.csv": [],
        "algorithms.csv": [],
        "resolver_agreement.csv": [],
        "resolver_disagreements.csv": [],
    }
    exceptional = []

    # Summarize each run.
    for path in files:
        print(f"Summarizing {path.name}")
        result = summarize_run(path, args.chunksize)
        for filename, rows in zip(tables, result[:6]):
            tables[filename].extend(rows if isinstance(rows, list) else [rows])
        if not result[6].empty:
            exceptional.append(result[6])

    # Compare selected run pairs.
    comparisons, transitions = [], []
    for path_a, path_b in comparison_pairs(files):
        print(f"Comparing {path_a.name} -> {path_b.name}")
        summary, detail = compare_runs(path_a, path_b, args.chunksize)
        comparisons.append(summary)
        transitions.extend(detail)

    tables["run_comparisons.csv"] = comparisons
    tables["run_transitions.csv"] = transitions

    # Write aggregated outputs.
    for filename, rows in tables.items():
        write_csv(rows, args.output_dir / filename)

    # Keep fixed columns for an empty result.
    columns = [
        "run", "domain", "resolver", "classification", "dnskey_present",
        "ds_present", "a_rcode", "dnskey_rcode", "ds_rcode",
        "measurement_timestamp",
    ]
    cases = pd.concat(exceptional, ignore_index=True) if exceptional else pd.DataFrame(columns=columns)
    cases.to_csv(args.output_dir / "exceptional_cases.csv", index=False)

    print(f"Done. Results written to {args.output_dir}")


if __name__ == "__main__":
    main()

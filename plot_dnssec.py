#!/usr/bin/env python3
"""Generate the seven figures and two LaTeX tables used in the thesis.

Usage: python plot_dnssec.py analysis figures [--dpi 300]
Input: aggregated CSV files produced by analyze_dnssec.py.
"""

import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import PercentFormatter

CLASSIFIABLE = ["UNSIGNED", "SIGNED_NO_DS", "DNSSEC-DEPLOYED"]
UNCLASSIFIED = ["NOT_CLASSIFIED_NXDOMAIN", "NOT_CLASSIFIED_A_ERROR", "NOT_CLASSIFIED_DNSSEC_ERROR"]
LABELS = {
    "SIGNED_NO_DS": "Signed without DS", "DNSSEC-DEPLOYED": "DNSSEC deployed",
    "NOT_CLASSIFIED_NXDOMAIN": "NXDOMAIN", "NOT_CLASSIFIED_A_ERROR": "A query error",
    "NOT_CLASSIFIED_DNSSEC_ERROR": "DNSSEC query error",
    "classification_agreement": "Classification", "a_rcode_agreement": "A RCODE",
    "ad_flag_agreement": "AD flag", "classification_stability": "Classification",
    "ad_flag_stability": "AD flag", "algorithm_stability": "DNSKEY algorithms",
}
STABILITY = ["classification_stability", "ad_flag_stability", "algorithm_stability"]


# Validate the analysis input before creating any figures.
def read_csv(folder, filename, required):
    path = folder / filename
    data = pd.read_csv(path)
    missing = set(required) - set(data.columns)
    if missing:
        raise ValueError(f"{filename}: missing columns: {', '.join(sorted(missing))}")
    return data


# Order runs by their embedded dates, with a natural-sort fallback.
def run_key(value):
    value = str(value)
    match = re.search(r"\d{4}-\d{2}-\d{2}", value)
    if match:
        return (0, pd.Timestamp(match.group()), value)
    parts = tuple((1, int(p)) if p.isdigit() else (0, p.casefold())
                  for p in re.split(r"(\d+)", value))
    return (1, parts)


def runs_in(data):
    return sorted(data.dropna().astype(str).unique(), key=run_key)


def run_date(run, year=False):
    match = re.search(r"\d{4}-\d{2}-\d{2}", str(run))
    return pd.Timestamp(match.group()).strftime("%d %b %Y" if year else "%d %b") if match else str(run)


def run_axis(ax, runs):
    years = {pd.Timestamp(match.group()).year for run in runs
             if (match := re.search(r"\d{4}-\d{2}-\d{2}", str(run)))}
    show_year = len(years) != 1
    labels = [run_date(run, show_year) for run in runs]
    ax.set_xticks(range(len(runs)))
    ax.set_xticklabels(labels, rotation=45 if len(runs) > 13 else 0,
                       ha="right" if len(runs) > 13 else "center", fontsize=9)
    ax.set_xlim(-0.4, max(0.4, len(runs) - 0.6))
    suffix = f" ({next(iter(years))})" if len(years) == 1 else ""
    ax.set_xlabel("Measurement run" + suffix, labelpad=11)
    ax.tick_params(axis="x", which="major", bottom=True, labelbottom=True,
                   direction="out", length=4, width=0.8, pad=7)


def save(fig, folder, name, dpi, *, legend=True, grid="y"):
    ax = fig.axes[0]
    if grid:
        ax.grid(axis=grid, alpha=0.3)
    if legend:
        ax.legend()
    fig.tight_layout()
    fig.savefig(folder / name, dpi=dpi, bbox_inches="tight")
    plt.close(fig)


def deployment_outputs(data, folder, dpi):
    data = data[data["classification"].isin(CLASSIFIABLE)].copy()
    data["count"] = pd.to_numeric(data["count"], errors="raise")
    if data.empty:
        raise ValueError("No classifiable observations in classifications.csv")
    grouped = data.groupby(["run", "classification"])["count"].sum().unstack(fill_value=0)
    ordered = runs_in(data["run"])
    counts = grouped.reindex(index=ordered, columns=CLASSIFIABLE, fill_value=0)
    totals = counts.sum(axis=1)
    if (totals <= 0).any():
        raise ValueError("At least one run has no classifiable observations")
    # Deployment percentages use only the three classifiable categories.
    pct = counts.div(totals, axis=0).mul(100)

    # The appendix table includes all three classes; the graph shows two.
    lines = [
        r"% Generated automatically from classifications.csv.",
        r"% Requires \usepackage{booktabs} and \usepackage{float}.",
        r"\begin{table}[H]", r"    \centering", r"    \small",
        (r"    \caption{Distribution of classifiable DNSSEC deployment "
         r"categories by measurement run. Observations from both resolvers "
         r"are combined; percentages use only classifiable observations "
         r"from the corresponding run.}"),
        r"    \label{tab:classification-over-time}",
        r"    \begin{tabular}{@{}lrrr@{}}", r"        \toprule",
        r"        Measurement run & Unsigned (\%) & Signed without DS (\%) & DNSSEC deployed (\%) \\",
        r"        \midrule",
    ]
    for run in ordered:
        label = re.search(r"\d{4}-\d{2}-\d{2}", str(run))
        name = label.group() if label else str(run)
        lines.append(f"        {name} & {pct.loc[run, 'UNSIGNED']:.2f} & "
                     f"{pct.loc[run, 'SIGNED_NO_DS']:.2f} & "
                     f"{pct.loc[run, 'DNSSEC-DEPLOYED']:.2f} " + r"\\")
    lines += [r"        \bottomrule", r"    \end{tabular}", r"\end{table}", ""]
    (folder / "classification_over_time_table.tex").write_text("\n".join(lines), encoding="utf-8")

    fig, ax = plt.subplots(figsize=(11.4, 6))
    for cls in ["SIGNED_NO_DS", "DNSSEC-DEPLOYED"]:
        ax.plot(range(len(ordered)), pct[cls], marker="o", linewidth=2.0, label=LABELS[cls])
    ax.set_title("Trend of signed and DNSSEC-deployed observations over time")
    ax.set_ylabel("Share of classifiable measurements")
    ax.yaxis.set_major_formatter(PercentFormatter(100))
    run_axis(ax, ordered)
    save(fig, folder, "classification_over_time.png", dpi)


def unclassified_plot(data, folder, dpi):
    totals = data.groupby("run")["count"].sum()
    selected = data[data["classification"].isin(UNCLASSIFIED)].copy()
    selected = selected.groupby(["run", "classification"])["count"].sum().unstack(fill_value=0)
    ordered = runs_in(data["run"])
    # Error and NXDOMAIN shares use ALL observations as the denominator.
    pct = selected.reindex(index=ordered, columns=UNCLASSIFIED, fill_value=0).div(totals, axis=0) * 100
    fig, ax = plt.subplots(figsize=(11.4, 6))
    for cls in UNCLASSIFIED:
        ax.plot(range(len(ordered)), pct[cls], marker="o", label=LABELS[cls])
    ax.set_title("Unclassified measurement results over time")
    ax.set_ylabel("Share of all measurements")
    ax.yaxis.set_major_formatter(PercentFormatter(100))
    run_axis(ax, ordered)
    save(fig, folder, "unclassified_results_over_time.png", dpi)


# Agreement metrics are fractions in the analysis CSV and become percent here.
def agreement_plot(data, folder, dpi):
    metrics = ["classification_agreement", "a_rcode_agreement", "ad_flag_agreement"]
    ordered = runs_in(data["run"])
    data = data.set_index("run").reindex(ordered)
    fig, ax = plt.subplots(figsize=(11.4, 6))
    for key in metrics:
        ax.plot(range(len(ordered)), pd.to_numeric(data[key], errors="coerce") * 100,
                marker="o", label=LABELS[key])
    ax.set_title("Agreement between recursive resolvers")
    ax.set_ylabel("Agreement")
    ax.yaxis.set_major_formatter(PercentFormatter(100))
    run_axis(ax, ordered)
    save(fig, folder, "resolver_agreement.png", dpi)


def stability_outputs(data, folder, dpi):
    if data.empty:
        raise ValueError("run_comparisons.csv is empty")
    data = data.copy()
    data["run_a"] = data["run_a"].astype(str)
    data["run_b"] = data["run_b"].astype(str)
    ordered = sorted(set(data["run_a"]) | set(data["run_b"]), key=run_key)
    if len(ordered) < 2:
        raise ValueError("At least two measurement runs are required")
    lookup = data.set_index(["run_a", "run_b"])
    if not lookup.index.is_unique:
        raise ValueError("Duplicate run comparisons")
    # Match consecutive runs by their IDs rather than assuming CSV row order.
    pairs = list(zip(ordered, ordered[1:]))
    missing = [pair for pair in pairs if pair not in lookup.index]
    if missing:
        raise ValueError(f"Missing consecutive comparisons: {missing}")
    consecutive = lookup.loc[pairs].reset_index()

    years = {pd.Timestamp(m.group()).year for run in ordered
             if (m := re.search(r"\d{4}-\d{2}-\d{2}", run))}
    year_in_dates = len(years) != 1
    year_note = f" ({next(iter(years))})" if len(years) == 1 else ""
    n = len(pairs)
    if n <= 12:
        labels = [f"{run_date(a, year_in_dates)}\n→ {run_date(b, year_in_dates)}" for a, b in pairs]
        width = min(11.4, max(8.5, n * 0.9 + 2.0))
        size, angle, alignment = (9 if n <= 10 else 8), 0, "center"
    else:
        labels = [f"{run_date(a, year_in_dates)} → {run_date(b, year_in_dates)}" for a, b in pairs]
        width = min(18, max(11.4, n * 0.75))
        size, angle, alignment = 8, 45, "right"

    fig, ax = plt.subplots(figsize=(width, 5.2))
    for key in STABILITY:
        ax.plot(range(n), pd.to_numeric(consecutive[key], errors="raise") * 100,
                marker="o", markersize=5.8, linewidth=1.9, label=LABELS[key])
    ax.set_title("Stability between consecutive measurement runs", pad=15)
    ax.set_ylabel("Stable observations")
    ax.set_xlabel(f"Consecutive comparisons by measurement start date{year_note}", labelpad=12)
    ax.set_xticks(range(n))
    ax.set_xticklabels(labels, fontsize=size, rotation=angle, ha=alignment)
    ax.tick_params(axis="x", which="major", bottom=True, labelbottom=True,
                   direction="out", length=4, width=0.8, pad=9)
    ax.yaxis.set_major_formatter(PercentFormatter(100, decimals=2))
    lower = float(consecutive[STABILITY].min().min()) * 100
    ax.set_ylim(max(0, (int(lower * 10) / 10) - 0.1), 100.02)
    ax.set_xlim(-0.4, max(0.4, n - 0.6))
    ax.grid(axis="y", alpha=0.3)
    ax.legend(loc="lower right", ncol=3, frameon=True, fontsize=9)
    fig.subplots_adjust(left=0.075 if width > 12 else 0.095, right=0.99, top=0.90,
                        bottom=0.26 if n <= 12 else 0.32)
    fig.savefig(folder / "run_stability.png", dpi=dpi, bbox_inches="tight")
    plt.close(fig)

    # The first-to-final comparison is separate from consecutive-run stability.
    first_last = (ordered[0], ordered[-1])
    if first_last not in lookup.index:
        raise ValueError(f"Missing first-to-final comparison: {first_last}")
    values = pd.to_numeric(lookup.loc[first_last, STABILITY], errors="raise") * 100
    dates = (f"{run_date(first_last[0], year_in_dates)} – "
             f"{run_date(first_last[1], year_in_dates)}"
             + (f" {next(iter(years))}" if len(years) == 1 else ""))
    rows = [[LABELS[key], f"{values[key]:.2f}%"] for key in STABILITY]
    fig, ax = plt.subplots(figsize=(7.1, 2.65))
    ax.axis("off")
    ax.set_title("First-to-final measurement comparison", fontsize=13, pad=15)
    table = ax.table(cellText=rows, colLabels=["Indicator", "Stable observations"],
                     colWidths=[0.54, 0.42], cellLoc="center", colLoc="center",
                     bbox=[0.02, 0.25, 0.96, 0.57])
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    for (r, _), cell in table.get_celld().items():
        cell.visible_edges = "horizontal"
        cell.set_linewidth(0.9 if r == 0 else 0.5)
        if r == 0:
            cell.get_text().set_weight("bold")
    fig.text(0.5, 0.105, f"First and final run start dates: {dates}", ha="center", fontsize=10)
    fig.savefig(folder / "run_stability_first_last.png", dpi=dpi, bbox_inches="tight")
    plt.close(fig)

    lines = [
        r"% Generated automatically from the actual first and final run.",
        r"% Requires \usepackage{booktabs} and \usepackage{float}.",
        r"\begin{table}[H]", r"    \centering", r"    \small",
        (r"    \caption{Stability between the first and final measurement "
         r"runs (" + dates + r"). Reported separately from "
         r"consecutive-run comparisons.}"),
        r"    \label{tab:run-stability-first-last}",
        r"    \begin{tabular}{@{}lr@{}}", r"        \toprule",
        r"        Indicator & Stable observations (\%) \\",
        r"        \midrule",
    ]
    for label, pct in rows:
        lines.append(f"        {label} & {pct.removesuffix('%')} " + r"\\")
    lines += [r"        \bottomrule", r"    \end{tabular}", r"\end{table}", ""]
    (folder / "run_stability_first_last.tex").write_text("\n".join(lines), encoding="utf-8")


def algorithms_plot(data, folder, dpi, all_runs):
    if data.empty:
        raise ValueError("algorithms.csv is empty")
    data = data.copy()
    data["run"] = data["run"].astype(str)
    data["count"] = pd.to_numeric(data["count"], errors="raise")
    if (data["count"] < 0).any() or data["algorithm"].isna().any():
        raise ValueError("Invalid algorithm counts or missing algorithm names")
    if set(data["run"]) - set(all_runs):
        raise ValueError("Algorithm data contain unknown measurement runs")

    # Combine both resolvers within each run; missing algorithms count as zero.
    per_run = data.groupby(["run", "algorithm"])["count"].sum().unstack(fill_value=0)
    per_run = per_run.reindex(all_runs, fill_value=0)
    # Plot the mean per run across ALL supplied runs, not the final run alone.
    means = per_run.mean(axis=0).sort_values(ascending=False)
    if means.sum() <= 0:
        raise ValueError("No positive DNSKEY algorithm observations")
    pct = means / means.sum() * 100  # Denominator includes algorithms outside the top six.
    top = means.head(6).iloc[::-1]
    fig, ax = plt.subplots(figsize=(10, 5.8))
    bars = ax.barh(top.index, top.to_numpy())
    ax.set_title(f"Most common DNSKEY algorithms (mean across {len(all_runs)} runs)")
    ax.set_xlabel("Mean algorithm observations per run (both resolvers combined)")
    ax.set_ylabel("Algorithm")
    ax.tick_params(axis="x", which="major", bottom=True, direction="out", length=4, width=0.8)
    ax.grid(axis="x", alpha=0.25)
    maximum = float(top.max())
    ax.set_xlim(0, maximum * 1.31)
    for bar, algorithm in zip(bars, top.index):
        ax.text(bar.get_width() + maximum * 0.012, bar.get_y() + bar.get_height() / 2,
                f"{means[algorithm]:,.0f} ({pct[algorithm]:.2f}%)",
                va="center", ha="left", fontsize=9)
    ax.text(1, -0.13, "Percentages use all observed algorithms, including those not shown.",
            transform=ax.transAxes, ha="right", va="top", fontsize=8)
    fig.tight_layout()
    fig.savefig(folder / "algorithm_distribution.png", dpi=dpi, bbox_inches="tight")
    plt.close(fig)


# Show median and P95 measurement duration for each resolver.
def duration_plot(data, folder, dpi):
    ordered = runs_in(data["run"])
    fig, ax = plt.subplots(figsize=(11.4, 6))
    for resolver in sorted(data["resolver"].astype(str).unique()):
        one = data[data["resolver"].astype(str).eq(resolver)].set_index("run").reindex(ordered)
        for column, label in [("median_ms", "median"), ("p95_ms", "P95")]:
            ax.plot(range(len(ordered)), pd.to_numeric(one[column], errors="coerce"),
                    marker="o", label=f"{resolver} {label}")
    ax.set_title("Measurement duration by resolver")
    ax.set_ylabel("Duration in milliseconds")
    run_axis(ax, ordered)
    save(fig, folder, "measurement_duration.png", dpi)


def main():
    parser = argparse.ArgumentParser(description="Generate figures and LaTeX tables for the thesis")
    parser.add_argument("analysis_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--dpi", type=int, default=300)
    args = parser.parse_args()
    print("Starting DNSSEC plot generation...", flush=True)
    if args.dpi <= 0:
        parser.error("--dpi must be positive")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    source = args.analysis_dir
    # Load aggregated CSV results; raw measurement files are not needed here.
    classifications = read_csv(source, "classifications.csv", ["run", "classification", "count"])
    agreement = read_csv(source, "resolver_agreement.csv", ["run", "classification_agreement",
                                                            "a_rcode_agreement", "ad_flag_agreement"])
    comparisons = read_csv(source, "run_comparisons.csv", ["run_a", "run_b"] + STABILITY)
    algorithms = read_csv(source, "algorithms.csv", ["run", "algorithm", "count"])
    summary = read_csv(source, "resolver_summary.csv", ["run", "resolver", "median_ms", "p95_ms"])

    deployment_outputs(classifications, args.output_dir, args.dpi)
    unclassified_plot(classifications, args.output_dir, args.dpi)
    agreement_plot(agreement, args.output_dir, args.dpi)
    stability_outputs(comparisons, args.output_dir, args.dpi)
    algorithms_plot(algorithms, args.output_dir, args.dpi, runs_in(classifications["run"]))
    duration_plot(summary, args.output_dir, args.dpi)
    print(f"Created 7 figures and 2 LaTeX tables in folder \"{args.output_dir}\".")


if __name__ == "__main__":
    main()

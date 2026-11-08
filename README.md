# DNSSEC Deployment Measurement

This repository contains the Python-based measurement and evaluation workflow developed for the bachelor's thesis **“Implementing a Tool for Measuring DNSSEC Deployment on the Internet.”** The workflow collects DNSSEC-related indicators through recursive DNS resolvers, analyzes repeated measurements, and generates figures and tables.

## Overview

For each domain–resolver pair, the measurement tool sends three DNS queries over TCP, with the DNSSEC OK (DO) bit enabled:

1. **A** — records the response code and the Authenticated Data (AD) flag.
2. **DNSKEY** — checks for observable DNSSEC public-key records and extracts their algorithm identifiers.
3. **DS** — checks for observable delegation signer records.

Results are written to a CSV file with one row per domain–resolver pair. The tool uses three deployment categories for observations with successful required queries:

| Classification | Observable condition |
| --- | --- |
| `UNSIGNED` | No DNSKEY RRset observed |
| `SIGNED_NO_DS` | DNSKEY observed, but no DS RRset observed |
| `DNSSEC-DEPLOYED` | Both DNSKEY and DS RRsets observed |

`NXDOMAIN`, A-query errors, and DNSSEC-query errors are reported separately rather than included in the deployment denominator. The AD flag of the A response is stored as a separate **resolver-reported validation indicator**.

> **Interpretation:** The presence of DNSKEY and DS records does **not** prove that a DNSSEC configuration is cryptographically valid. The tool does not independently verify RRSIG records, DS digests, or the complete DNSSEC chain of trust.

## Requirements

- Python **3.10 or newer**
- Python packages: `dnspython`, `pandas`, and `matplotlib`

Install the dependencies:

```bash
python -m pip install dnspython pandas matplotlib
```

For strict reproducibility, record the versions used in the measurement environment and pin them in a `requirements.txt` file. No specific package versions are assumed here.

## Repository layout

The following layout is recommended; keep the filenames consistent with the files you upload:

```text
dnssec-deployment-measurement/
├── dnssec.py
├── analyze_dnssec.py
├── plot_dnssec.py
├── datasets/
│   ├── top-1000000.csv
│   └── README.md
├── results/                 # raw measurements (not necessarily tracked by Git)
├── analysis/                # aggregated CSV summaries
├── figures/                 # generated figures and LaTeX tables
├── requirements.txt
└── README.md
```

## Running a measurement

The repository provides `datasets/top-1000000.csv` directly. The file has a single `domain` column, so the domain names themselves can be read one per line without converting the file to `.txt`. The file extension alone does not matter for the current line-based input reader.

Run the measurement using the CSV path:

```bash
python dnssec.py -i datasets/top-1000000.csv -r 1.1.1.1 -r 8.8.8.8 -o results.csv
```

**Input format:** The original Cloudflare Radar CSV export contained a header named `domain`, which was manually removed before the measurements. The measurement tool reads the resulting CSV file directly, treating each nonempty line as a domain name. No CSV-to-TXT conversion is required.

A full run over the dataset can take several days.

### Measurement output

Each CSV row includes `domain`, `resolver`, `classification`, `ad_flag`, `dnskey_present`, `ds_present`, `dnskey_algorithms`, `a_rcode`, `dnskey_rcode`, `ds_rcode`, `duration_ms`, and `response_time`.

**Note:** Despite its name, `response_time` is the **measurement start timestamp**, not the arrival time of a DNS response. `duration_ms` measures the duration of all three queries for the corresponding domain–resolver pair.

## Analyzing repeated runs

Store the raw measurement CSV files in `results/`. Use consistent, chronologically sortable filenames (for example, `results-2026-07-08.csv`), and preserve the same domain list, resolver order, and row order for run-to-run comparisons.

```bash
python analyze_dnssec.py results analysis
```

*This command assumes the compact analyzer version that accepts positional input and output directories. If the uploaded `analyze_dnssec.py` uses different options, follow `python analyze_dnssec.py --help`.*

The analysis script reads large CSV files in chunks and produces aggregated files, including `classifications.csv`, `resolver_agreement.csv`, `run_comparisons.csv`, `run_transitions.csv`, `algorithms.csv`, `resolver_summary.csv`, and `exceptional_cases.csv`. It compares consecutive runs and additionally compares the first with the final run. The input CSV files are not modified.

To generate plots and the accompanying LaTeX tables from these aggregated results:

```bash
python plot_dnssec.py analysis figures
```

The plotting workflow includes classification trends, non-classifiable results, resolver agreement, temporal stability, DNSKEY algorithm distribution, and measurement duration. The DNSKEY algorithm distribution reports **mean observations per run across the supplied measurement runs**, combining observations from both resolvers within each run. The plotted classification percentages use **classifiable domain–resolver observations** as their denominator, not the number of unique domains.

## Dataset provenance

The domain list originates from [Cloudflare Radar — Domain Rankings](https://radar.cloudflare.com/domains), **Global Top 1,000,000** ranking bucket:

- **Ranking period:** 30 March – 6 April 2026
- **Download date:** 11 April 2026
- **Entries in the downloaded CSV:** 1,000,673 distinct domain names
- **Source file in this repository:** [`datasets/top-1000000.csv`](datasets/top-1000000.csv), containing one domain name per line without a CSV header. The original `domain` header was manually removed before measurement. The script reads the CSV file directly without requiring conversion to TXT. See [`datasets/README.md`](datasets/README.md) for data provenance and preparation details.

The ranking is based on DNS queries observed by Cloudflare's public resolver and is **not a random or Internet-representative sample** of registered domains or authoritative DNS zones. More information is available in the [Cloudflare Radar ranking documentation](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/).

The same fixed dataset of 1,000,673 domain names was used in all twelve measurement runs evaluated in the thesis. The original CSV header was manually removed before measurement, and the resulting CSV file was used directly as input without conversion to TXT.

**Dataset attribution and licensing:** Cloudflare Radar states that downloaded Radar data is available under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/) unless otherwise indicated. Preserve Cloudflare attribution and the applicable dataset license when redistributing its download. This dataset license is separate from any license chosen for the repository's source code.

## Thesis evaluation

The submitted thesis analyzes **12 complete runs from July to September 2026**, using 1,000,673 domain names and two recursive resolvers per run (**24,016,152 domain–resolver observations** in total). A subsequent measurement run should not be treated as part of those published thesis results unless the analysis and thesis text have explicitly been updated.

A complete run spans multiple days and should not be interpreted as an instantaneous snapshot. Observed deployment shares, resolver agreement, and algorithm counts apply to the selected dataset, resolvers, and measurement period.

## Known limitations

- Queries are made **through recursive resolvers**, not directly to authoritative name servers. Caches, resolver policies, and network conditions may affect responses.
- DNSKEY and DS are queried at the **exact input names**; not every name is necessarily a DNS zone apex.
- No independent cryptographic DNSSEC validation or complete chain-of-trust verification is performed.
- The AD flag is inspected **only in the A response**.
- The measurement script labels different query exceptions as `TIMEOUT`; this value does not necessarily indicate an actual timeout.
- The TCP query call does **not** configure an explicit application-level timeout (`timeout=None` by default in the used API).
- Aggregate algorithm observations include both resolver perspectives and are **not counts of unique DNS zones**.

## Reproducibility and Citation

The twelve raw measurement CSV files used in the bachelor's thesis are archived separately on Zenodo because each file exceeds 200 MB.

**Raw measurement dataset:** [DNSSEC Deployment Measurement Dataset (July–September 2026)](https://doi.org/10.5281/zenodo.23737454)

The GitHub repository contains the measurement, analysis, and plotting scripts. Together with the archived measurement data, these resources enable reproduction of the thesis evaluation without repeating the original DNS measurements.

For academic citation, reference the bachelor's thesis, the Zenodo dataset DOI, and the corresponding Git commit hash or release tag.

### Generated Outputs

The `analysis/` and `figures/` directories contain the aggregated analysis results and visualizations generated from the twelve measurement runs evaluated in the bachelor's thesis.

These outputs are provided to support transparency and reproducibility. They can be regenerated using `analyze_dnssec.py` and `plot_dnssec.py` with the corresponding raw measurement data archived on Zenodo.
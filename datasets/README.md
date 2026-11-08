# Cloudflare Radar domain dataset

## Origin and export period

The dataset in this directory was downloaded from **[Cloudflare Radar – Domains](https://radar.cloudflare.com/domains)** on **11 April 2026**.

- **Ranking:** Global **Top 1,000,000** domain-ranking bucket
- **Ranking/reference period:** **30 March 2026 through 6 April 2026** (from the original export filename)
- **Download date:** **11 April 2026**
- **Original export filename:** `cloudflare-radar_top-1000000-domains_20260330-20260406.csv`
- **Filename in this repository:** `top-1000000.csv` (renamed for convenience; the CSV contents are unchanged)
- **CSV format:** UTF-8 text, header `domain`, one domain per following row
- **Domain rows:** **1,000,673** (all unique, no empty values)

The number of entries can exceed one million even though Cloudflare calls the dataset the *Top 1,000,000* ranking bucket. The ranking is based on DNS traffic observed by Cloudflare's public resolver, not on a random sample of all registered domains or DNS zones. For details, see [Cloudflare's domain-ranking documentation](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/).

## File integrity

The CSV file was prepared for measurement by manually removing the original `domain` header.

The SHA-256 checksum below identifies the prepared `top-1000000.csv` file included in this repository:

```text
6a24daa1e270b518402f242b63126747996802d56d2850921750210aff4203e7
```

This checksum refers to the prepared dataset, not the original Cloudflare Radar export.

## Using the CSV with the measurement script

The file `top-1000000.csv` may be provided directly to the measurement tool. No `.txt` conversion is required simply because the file uses the `.csv` extension. Each data row contains only a domain name.

```bash
python dnssec.py -i datasets/top-1000000.csv -r 1.1.1.1 -r 8.8.8.8 -o results.csv
```

**CSV header:** The original Cloudflare Radar export contained a column header named `domain`. This header was manually removed during dataset preparation. The `top-1000000.csv` file included in this repository therefore contains one domain name per line without a header and can be used directly by `dnssec.py` without conversion to TXT or additional header-handling logic.

## Relationship to the bachelor's thesis

The thesis analyzes 12 measurement runs performed between July and September 2026 with 1,000,673 names and two recursive resolvers per run. The dataset size matches this export. This agreement does **not by itself prove** that the raw export with its header was the exact input file used for the runs. Compare the original input, first output rows, and code revision to confirm whether the header was skipped.

## Attribution and licensing

**Dataset source:** Cloudflare Radar, Global Top 1,000,000 domains, ranking period 30 March–6 April 2026, downloaded 11 April 2026. [Source](https://radar.cloudflare.com/domains).

Cloudflare states that directly downloaded Radar data is subject to the applicable [Creative Commons Attribution-NonCommercial 4.0 (CC BY-NC 4.0)](https://creativecommons.org/licenses/by-nc/4.0/) terms unless otherwise noted. Retain Cloudflare attribution and check the terms before redistribution. The dataset's terms are separate from any license you choose for your own source code.

# DNSSEC Deployment Measurement Tool
#
# - Reads domain names from a CSV file (one domain per line, without a header).
#   The original Cloudflare Radar CSV header was manually removed.
# - Queries one or multiple recursive DNS resolvers.
# - Performs A, DNSKEY, and DS queries over TCP with the DNSSEC DO bit enabled.
# - Records the following DNSSEC indicators:
#     (1) AD flag in the A response (resolver-reported validation)
#     (2) DNSKEY record presence and algorithm identifiers
#     (3) DS record presence
# - Classifies usable observations as:
#     UNSIGNED, SIGNED_NO_DS, or DNSSEC-DEPLOYED.
# - Reports NXDOMAIN and query errors separately.
# - Records response codes, query duration, and measurement timestamps.
# - Writes measurement results to a CSV file.
# - Displays progress and summary statistics in the command line.
#
# Limitations:
# - Does not independently validate DNSSEC signatures or the chain of trust.
# - Different query exceptions are recorded under the TIMEOUT label.
# - No explicit application-level timeout is configured for dns.query.tcp().
#
# Install dependencies (run in the repository root):
# python -m pip install -r requirements.txt
#
# Run from the repository root:
# python dnssec.py -i datasets/top-1000000.csv -r 8.8.8.8 -r 1.1.1.1 -o results.csv
#
# The complete dataset contains 1,000,673 domain names.
# A full measurement run can take several days.

import argparse                      # CLI argument parsing
import csv                           # CSV output
import time                          # timing (duration per measurement)

import dns.message                   # build DNS queries
import dns.query                     # send DNS queries (UDP/TCP)
import dns.flags                     # read header flags (AD/TC)
import dns.rdatatype                 # record types (A, DNSKEY, DS)
import dns.rcode                     # rcode to text (NOERROR, SERVFAIL, ...)

from dns.rdatatype import RdataType     #type int (example: dns.rdatatype.A == 1) but alert from rdtype if not declared as RdataType|str

from datetime import datetime       # needed to give the current time

def normalize_domain(s: str) -> str:
    """Normalize a domain line into an FQDN with trailing dot (or return empty if invalid)."""
    s = s.strip()                    # remove whitespace
    if not s or s.startswith("#"):   # skip blank lines and comments
        return ""
    return s.rstrip(".") + "."       # ensure trailing dot for absolute name

def send_query(qname: str, resolver_ip: str, rdtype: RdataType|str):
    """Send a single DNS query to a specific resolver."""
    q = dns.message.make_query(qname, rdtype)               # build query message
    #q.use_edns(edns=0)                                     # set EDNS buffer size (DNSSEC responses can be big)
    q.want_dnssec(True)                                     # set DO bit (request DNSSEC records)

    return dns.query.tcp(q, resolver_ip)                    # UDP often has not enough space for whole data/payload -> TCP


def dnskey_present(resp) -> bool:
    """Return True if the answer section contains a DNSKEY RRset."""
    for rrset in resp.answer:                              # iterate answer rrsets
        if rrset.rdtype == dns.rdatatype.DNSKEY:           # check record type
            return True                                    # DNSKEY present
    return False                                           # no DNSKEY seen


def ds_present(resp) -> bool:
    """Return True if the answer section contains a DS RRset."""
    for rrset in resp.answer:                              # iterate answer rrsets
        if rrset.rdtype == dns.rdatatype.DS:               # check record type
            return True                                    # DS present
    return False                                           # no DS seen


def classify(dnskey: bool, ds: bool) -> str:
    """Simple classification for reporting."""
    if not dnskey:                                         # no DNSKEY => unsigned (as far as we can observe)
        return "UNSIGNED"
    if dnskey and not ds:                                  # signed zone but no DS in parent
        return "SIGNED_NO_DS"
    return "DNSSEC-DEPLOYED"                               # DNSKEY + DS present -> Deployed


def measure_one(domain: str, resolver: str):
    """Measure one domain via one resolver."""
    t0 = time.monotonic()                                  # start timer

    response_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    # --- 1) A query: observe AD flag (validation indicator for that resolver) ---
    try:
        a_resp = send_query(domain, resolver, dns.rdatatype.A)                          # query A
        a_rcode = dns.rcode.to_text(a_resp.rcode())                                     # rcode as text
        ad = (a_resp.flags & dns.flags.AD) != 0                                         # AD flag set?
    except Exception:
        a_rcode = "TIMEOUT"                                                             # record failure
        ad = None                                                                       # not determinable

    # --- 2) DNSKEY query: is the zone signed? ---
    try:
        dnskey_resp = send_query(domain, resolver, dns.rdatatype.DNSKEY)                         # query DNSKEY
        dnskey_rcode = dns.rcode.to_text(dnskey_resp.rcode())                                    # rcode as text
        has_dnskey = dnskey_present(dnskey_resp)                                                 # DNSKEY exists?

        # --- DNSKEY algorithms extraction ---
        algorithm_names = {
            1: "RSAMD5",
            3: "DSA/SHA1",
            5: "RSA/SHA-1",
            6: "DSA-NSEC3-SHA1",
            7: "RSASHA1-NSEC3-SHA1",
            8: "RSA/SHA-256",
            10: "RSA/SHA-512",
            12: "GOST R 34.10-2001",
            13: "ECDSA P-256 / SHA-256",
            14: "ECDSA P-384 / SHA-384",
            15: "Ed25519",
            16: "Ed448",
        }

        algorithms = set()
        for rrset in dnskey_resp.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                for rdata in rrset:
                    algorithms.add(int(rdata.algorithm))

        algorithm_labels = [algorithm_names.get(a, f"Unknown ({a})") for a in sorted(algorithms)]
        dnskey_algorithms = ", ".join(algorithm_labels) if algorithm_labels else "None"

    except Exception:
        dnskey_rcode = "TIMEOUT"                                                                 # record failure
        has_dnskey = False                                                                       # unknown -> treat as not seen
        dnskey_algorithms = "None"

    # --- 3) DS query: is there a DS in the parent (deployment)? ---
    try:
        ds_resp = send_query(domain, resolver, dns.rdatatype.DS)                                 # query DS
        ds_rcode = dns.rcode.to_text(ds_resp.rcode())                                            # rcode as text
        has_ds = ds_present(ds_resp)                                                             # DS exists?
    except Exception:
        ds_rcode = "TIMEOUT"                                                                     # record failure
        has_ds = False                                                                           # unknown -> treat as not seen

    # --- final classification ---
    # NXDOMAIN and uncertain query errors are not DNSSEC deployment categories.
    # They are reported separately instead of being counted as UNSIGNED.
    dnssec_query_error = (
        dnskey_rcode != "NOERROR"
        or ds_rcode != "NOERROR"
    )

    if a_rcode == "NXDOMAIN":
        classification = "NOT_CLASSIFIED_NXDOMAIN"
    elif a_rcode != "NOERROR":
        classification = "NOT_CLASSIFIED_A_ERROR"
    elif dnssec_query_error:
        classification = "NOT_CLASSIFIED_DNSSEC_ERROR"
    else:
        classification = classify(has_dnskey, has_ds)

    dur_ms = int((time.monotonic() - t0) * 1000)                                                 # duration in ms
    
    # --- return one CSV row  ---
    return {
        "domain": domain,                          # measured domain
        "resolver": resolver,                      # resolver IP
        "classification": classification,          # UNSIGNED / SIGNED_NO_DS / DEPLOYED
        "ad_flag": ("True" if ad is True else ("False" if ad is False else "NA")),  # AD observed?
        "dnskey_present": str(has_dnskey),         # DNSKEY seen?
        "ds_present": str(has_ds),                 # DS seen?
        "dnskey_algorithms": dnskey_algorithms,    # DNSKEY algorithms used by the domain
        "a_rcode": a_rcode,                        # rcode for A query
        "dnskey_rcode": dnskey_rcode,              # rcode for DNSKEY query
        "ds_rcode": ds_rcode,                      # rcode for DS query
        "duration_ms": str(dur_ms),                # runtime
        "response_time": str(response_time),       # response_time
    }


def main():
    
    start_time = datetime.now()
    print("\nMeasurement started at:", start_time.strftime("%Y-%m-%d %H:%M:%S"))
    print("\n")
    #print("\nStarting....\n")                                         # start status line

    # --- CLI arguments ---
    ap = argparse.ArgumentParser(description="Minimal DNSSEC measurement tool with CSV output.")
    ap.add_argument("-i", "--input", default="domains.txt", help="Input file name with the domain entries - one per line (default: domains.txt)")
    ap.add_argument("-r", "--resolver", action="append", required=True, help="Resolver IP (repeatable)")
    ap.add_argument("-o", "--output", default="results.csv", help="Output CSV path (default: results.csv)")
    args = ap.parse_args()

    # --- read and normalize domains ---
    domains = []                                                     # list of domains to measure
    with open(args.input, "r", encoding="utf-8") as f:               # open input file
        for line in f:                                               # read line by line
            d = line.strip()                                         # remove leading/trailing whitespace
            if not d or d.startswith("#"):                           # skip empty lines and comments
                continue
            domains.append(d)                                        # keep domain exactly as provided

    # --- prepare CSV writer ---
    fieldnames = [                                                   # CSV columns
        "domain",
        "resolver",
        "classification",
        "ad_flag",
        "dnskey_present",
        "ds_present",
        "dnskey_algorithms",
        "a_rcode",
        "dnskey_rcode",
        "ds_rcode",
        "duration_ms",
        "response_time",
    ]

    with open(args.output, "w", newline="", encoding="utf-8") as out:     # open output CSV
        writer = csv.DictWriter(out, fieldnames=fieldnames)               # create writer
        writer.writeheader()                                              # write header

        # --- measure all domain x resolver pairs ---
        total = len(domains) * len(args.resolver)                        ### # total measurements (#measurements = #domains x  #resolver)
        done = 0                                                          ### # counter

        deployed_count = 0
        unsigned_count = 0
        signed_no_ds_count = 0

        noerror_count = 0
        nxdomain_count = 0
        a_error_count = 0

        classifiable_count = 0
        not_classified_nxdomain_count = 0
        not_classified_a_error_count = 0
        not_classified_dnssec_error_count = 0

        for domain in domains:                                            # for each domain
            for resolver in args.resolver:                                # for each resolver
                row = measure_one(domain, resolver)                       # do measurement
                writer.writerow(row)                                      # append to CSV
            #    out.flush()                                              ### # flush so file updates immediately - could be much time consuming

                # --- DNSSEC classification counters ---

                # --- A query / domain status counters ---
                if row["a_rcode"] == "NOERROR":
                    noerror_count += 1
                elif row["a_rcode"] == "NXDOMAIN":
                    nxdomain_count += 1
                else:
                    a_error_count += 1


                # --- DNSSEC classification counters ---
                if row["classification"] == "DNSSEC-DEPLOYED":
                    deployed_count += 1
                    classifiable_count += 1
                elif row["classification"] == "UNSIGNED":
                    unsigned_count += 1
                    classifiable_count += 1
                elif row["classification"] == "SIGNED_NO_DS":
                    signed_no_ds_count += 1
                    classifiable_count += 1
                elif row["classification"] == "NOT_CLASSIFIED_NXDOMAIN":
                    not_classified_nxdomain_count += 1
                elif row["classification"] == "NOT_CLASSIFIED_A_ERROR":
                    not_classified_a_error_count += 1
                elif row["classification"] == "NOT_CLASSIFIED_DNSSEC_ERROR":
                    not_classified_dnssec_error_count += 1


                done += 1                                                 # increment progress


                # --- CLI progress print ---
                if row["classification"] == "NOT_CLASSIFIED_NXDOMAIN":
                    print(
                        f"[{done:3}/{total:3}] {row['domain']:30} does not exist according to the DNS response. | "
                        f"RCODE: {row['a_rcode']}"
                    )

                elif row["classification"] == "NOT_CLASSIFIED_A_ERROR":
                    print(
                        f"[{done:3}/{total:3}] {row['domain']:30} could not be resolved reliably. | "
                        f"A_RCODE: {row['a_rcode']} | Classification: {row['classification']}"
                    )

                elif row["classification"] == "NOT_CLASSIFIED_DNSSEC_ERROR":
                    print(
                        f"[{done:3}/{total:3}] {row['domain']:30} DNSSEC queries failed or returned errors. | "
                        f"A_RCODE: {row['a_rcode']} | DNSKEY_RCODE: {row['dnskey_rcode']} | DS_RCODE: {row['ds_rcode']} | "
                        f"Classification: {row['classification']}"
                    )

                else:
                    print(
                        f"[{done:3}/{total:3}] {row['domain']:30} via {row['resolver']} "
                        f"| Measurement Time {row['response_time']} "
                        f"| ({row['duration_ms']:4}ms) "
                        f"| AD={row['ad_flag']:5} | DNSKEY={row['dnskey_present']:5} | DS={row['ds_present']:6} "
                        f"| Algo={row['dnskey_algorithms']:<25} "
                        f"-> {row['classification']:15}"
                    )     

    print(f"\nResults have been written into file: {args.output}\n")      # final status line
    
    end_time = datetime.now()
    print("Measurement finished at:", end_time.strftime("%Y-%m-%d %H:%M:%S"))

    duration = end_time - start_time
    print("Total duration:", duration)

    def pct(count, base):
        return (count / base) * 100 if base else 0.0


    print("\n================ A QUERY / DOMAIN STATUS SUMMARY ================")
    print(f"Total measurements: {total}")
    print(f"NOERROR          : {noerror_count:3} / {total:3} = {pct(noerror_count, total):6.2f}%")
    print(f"NXDOMAIN         : {nxdomain_count:3} / {total:3} = {pct(nxdomain_count, total):6.2f}%")
    print(f"ERROR/UNCERTAIN  : {a_error_count:3} / {total:3} = {pct(a_error_count, total):6.2f}%")


    print("\n================ DNSSEC CLASSIFICATION SUMMARY ==================")
    print(f"Classifiable measurements: {classifiable_count:3} / {total:3} = {pct(classifiable_count, total):6.2f}%")
    print(f"DNSSEC-DEPLOYED : {deployed_count:3} / {classifiable_count:3} = {pct(deployed_count, classifiable_count):6.2f}%")
    print(f"UNSIGNED        : {unsigned_count:3} / {classifiable_count:3} = {pct(unsigned_count, classifiable_count):6.2f}%")
    print(f"SIGNED_NO_DS    : {signed_no_ds_count:3} / {classifiable_count:3} = {pct(signed_no_ds_count, classifiable_count):6.2f}%")


    print("\n================ NOT CLASSIFIED SUMMARY =========================")
    print(f"NXDOMAIN             : {not_classified_nxdomain_count:3} / {total:3} = {pct(not_classified_nxdomain_count, total):6.2f}%")
    print(f"A query error         : {not_classified_a_error_count:3} / {total:3} = {pct(not_classified_a_error_count, total):6.2f}%")
    print(f"DNSSEC query error    : {not_classified_dnssec_error_count:3} / {total:3} = {pct(not_classified_dnssec_error_count, total):6.2f}%")
    print("\n")

    
if __name__ == "__main__":
    main()                                                                 # run main when executed directly
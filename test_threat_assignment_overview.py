#!/usr/bin/env python3
"""Test script to examine threat assignment across example workflows.

1. Iterate through all YAML files in examples/
2. Run MAESTROEngine assessment
3. Print summary: WEI, RPS, vulnerabilities (# and list types)
4. Deep dive on one workflow (banking operations) showing detailed vulnerabilities.
"""

import os
import json
from collections import Counter

# Add src to path
import sys
sys.path.insert(0, 'src')

from maestro_threat_assessment.core.maestro_engine import MAESTROEngine

EXAMPLES_DIR = 'examples'
DEEP_DIVE_FILE = '13_banking_operations.yaml'

engine = MAESTROEngine()

def summarize_workflow(filepath: str):
    with open(filepath, 'r') as f:
        yaml_content = f.read()
    report = engine.assess_workflow_from_yaml(yaml_content)
    vulns = report.vulnerabilities
    wei = report.risk_assessment.total_wei.mean
    rps = report.risk_assessment.total_rps.mean
    types = [v['type'] for v in vulns]
    return {
        'name': report.workflow.name,
        'path': filepath,
        'wei': wei,
        'rps': rps,
        'vuln_count': len(vulns),
        'vuln_types': types
    }

def main():
    summaries = []
    for fname in os.listdir(EXAMPLES_DIR):
        if fname.endswith('.yaml') or fname.endswith('.yml'):
            path = os.path.join(EXAMPLES_DIR, fname)
            summaries.append(summarize_workflow(path))
    # Print overview
    print("=== Threat Assignment Overview ===")
    for s in summaries:
        print(f"{s['path']}: WEI={s['wei']:.3f}, RPS={s['rps']:.1f}, Vulns={s['vuln_count']}")
    total_vulns = sum(s['vuln_count'] for s in summaries)
    print(f"Total vulnerabilities across all workflows: {total_vulns}")
    # Aggregate types
    type_counter = Counter(t for s in summaries for t in s['vuln_types'])
    print("Most common vulnerability types:")
    for t, c in type_counter.most_common(10):
        print(f"  {t}: {c}")
    # Deep dive
    deep_path = os.path.join(EXAMPLES_DIR, DEEP_DIVE_FILE)
    deep_summary = summarize_workflow(deep_path)
    print("\n=== Deep Dive: Banking Operations ===")
    print(json.dumps(deep_summary, indent=2))

if __name__ == '__main__':
    main() 
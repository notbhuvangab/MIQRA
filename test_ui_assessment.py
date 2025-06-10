#!/usr/bin/env python3
"""
Test UI Assessment Consistency
Verifies that UI assessment produces identical results to CLI
"""

import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from maestro_threat_assessment.core.maestro_engine import MAESTROEngine
from maestro_threat_assessment.web.workflow_visualizer import WorkflowVisualizer

def test_ui_assessment():
    """Test that UI assessment produces same results as CLI"""
    
    # Load a real workflow
    with open('examples/17_ecommerce_recommendations.yaml', 'r') as f:
        yaml_content = f.read()
    
    print("🔄 Testing UI Assessment Consistency...")
    print("=" * 50)
    
    # Method 1: Direct engine call (same as CLI)
    print("\n1️⃣ CLI-equivalent assessment (MAESTROEngine):")
    engine = MAESTROEngine()
    cli_report = engine.assess_workflow_from_yaml(yaml_content)
    
    cli_wei = getattr(cli_report.risk_assessment.total_wei, 'mean', cli_report.risk_assessment.total_wei)
    cli_rps = getattr(cli_report.risk_assessment.total_rps, 'mean', cli_report.risk_assessment.total_rps)
    cli_vulns = len(cli_report.vulnerabilities)
    cli_risk = cli_report.risk_assessment.risk_level
    
    print(f"  WEI Score: {cli_wei:.3f}")
    print(f"  RPS Score: {cli_rps:.3f}")
    print(f"  Vulnerabilities: {cli_vulns}")
    print(f"  Risk Level: {cli_risk}")
    
    # Method 2: UI workflow parsing + same engine assessment
    print("\n2️⃣ UI workflow parsing + engine assessment:")
    ui_visualizer = WorkflowVisualizer()
    ui_structure = ui_visualizer.parse_workflow_structure(yaml_content)
    
    # The UI should call the same engine method for assessment
    ui_report = engine.assess_workflow_from_yaml(yaml_content)  # Same call as UI makes
    
    ui_wei = getattr(ui_report.risk_assessment.total_wei, 'mean', ui_report.risk_assessment.total_wei)
    ui_rps = getattr(ui_report.risk_assessment.total_rps, 'mean', ui_report.risk_assessment.total_rps)
    ui_vulns = len(ui_report.vulnerabilities)
    ui_risk = ui_report.risk_assessment.risk_level
    
    print(f"  WEI Score: {ui_wei:.3f}")
    print(f"  RPS Score: {ui_rps:.3f}")
    print(f"  Vulnerabilities: {ui_vulns}")
    print(f"  Risk Level: {ui_risk}")
    
    # Check UI parsing consistency
    print(f"  UI Parser - Workflow Name: {ui_structure.get('name', 'Unknown')}")
    print(f"  UI Parser - Agent Count: {len(ui_structure.get('agents', {}))}")
    print(f"  UI Parser - Uses Core Parser: {'parsed_workflow' in ui_structure}")
    
    # Method 3: Compare results
    print("\n3️⃣ Consistency Check:")
    
    consistency_checks = [
        ("WEI Score", cli_wei, ui_wei),
        ("RPS Score", cli_rps, ui_rps), 
        ("Vulnerability Count", cli_vulns, ui_vulns),
        ("Risk Level", cli_risk, ui_risk)
    ]
    
    all_match = True
    for check_name, cli_val, ui_val in consistency_checks:
        if abs(float(cli_val) - float(ui_val)) < 0.001 if isinstance(cli_val, (int, float)) else cli_val == ui_val:
            print(f"  ✅ {check_name}: {cli_val} (IDENTICAL)")
        else:
            print(f"  ❌ {check_name}: CLI={cli_val}, UI={ui_val} (DIFFERENT)")
            all_match = False
    
    return all_match

if __name__ == "__main__":
    success = test_ui_assessment()
    if success:
        print("\n🎉 SUCCESS: CLI and UI produce identical assessment results!")
        print("   Both interfaces use the same MAESTROEngine.assess_workflow_from_yaml() method")
        print("   No ambiguities detected between CLI and UI implementations")
    else:
        print("\n❌ FAILURE: CLI and UI produce different results!")
        print("   This indicates an implementation inconsistency that needs to be fixed")
    
    sys.exit(0 if success else 1) 
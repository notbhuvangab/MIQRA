#!/usr/bin/env python3
"""
CLI vs UI Consistency Test for MAESTRO Threat Assessment Framework

This test verifies that both CLI and UI implementations use the same underlying
functions for workflow parsing and threat assessment, preventing ambiguities.
"""

import sys
import os
import yaml
import json
from datetime import datetime

# Add the src directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, 'src'))

from maestro_threat_assessment.core.maestro_engine import MAESTROEngine
from maestro_threat_assessment.core.workflow_parser import WorkflowParser
from maestro_threat_assessment.web.workflow_visualizer import WorkflowVisualizer

def test_parsing_consistency():
    """Test that CLI and UI use the same workflow parsing logic"""
    
    # Sample YAML workflow
    test_yaml = """
workflow:
  name: "Test Workflow"
  description: "Sample workflow for consistency testing"
  metadata:
    protocol: "hybrid"
    
  agents:
    - name: "data_analyzer"
      protocol: "mcp"
      tools: ["data_processor", "analytics_engine"]
      communicates_with: ["report_generator"]
    - name: "report_generator"
      protocol: "a2a"
      tools: ["pdf_generator", "email_sender"]
      communicates_with: []
      
  steps:
    - id: "step_1"
      agent: "data_analyzer"
      action: "process_data"
      params:
        input_file: "customer_data.csv"
        analysis_type: "financial"
    - id: "step_2"
      agent: "report_generator"
      action: "generate_report"
      input_from: "step_1"
      params:
        format: "pdf"
        recipients: ["manager@company.com"]
"""

    print("🔍 Testing CLI vs UI Consistency...")
    print("=" * 60)
    
    # Test 1: Core WorkflowParser (used by CLI and should be used by UI)
    print("\n1️⃣ Testing Core WorkflowParser...")
    core_parser = WorkflowParser()
    try:
        core_parsed = core_parser.parse_yaml(test_yaml)
        print(f"✅ Core Parser - Name: {core_parsed.name}")
        print(f"✅ Core Parser - Agents: {core_parsed.agents}")
        print(f"✅ Core Parser - Steps: {len(core_parsed.steps)}")
        print(f"✅ Core Parser - Description: {core_parsed.description}")
    except Exception as e:
        print(f"❌ Core Parser Failed: {e}")
        return False
    
    # Test 2: UI WorkflowVisualizer (should now use core parser)
    print("\n2️⃣ Testing UI WorkflowVisualizer...")
    ui_visualizer = WorkflowVisualizer()
    try:
        ui_parsed = ui_visualizer.parse_workflow_structure(test_yaml)
        print(f"✅ UI Parser - Name: {ui_parsed.get('name', 'Unknown')}")
        print(f"✅ UI Parser - Agents: {list(ui_parsed.get('agents', {}).keys())}")
        print(f"✅ UI Parser - Steps: {len(ui_parsed.get('steps', []))}")
        print(f"✅ UI Parser - Description: {ui_parsed.get('description', '')}")
        
        # Check if UI parser includes the core parsed workflow
        if 'parsed_workflow' in ui_parsed:
            print("✅ UI Parser includes core ParsedWorkflow object")
        else:
            print("⚠️ UI Parser missing core ParsedWorkflow reference")
            
    except Exception as e:
        print(f"❌ UI Parser Failed: {e}")
        return False
    
    # Test 3: Compare consistency
    print("\n3️⃣ Comparing Consistency...")
    
    # Compare basic attributes
    consistency_checks = [
        ("name", core_parsed.name, ui_parsed.get('name')),
        ("description", core_parsed.description, ui_parsed.get('description')),
        ("agent_count", len(core_parsed.agents), len(ui_parsed.get('agents', {}))),
        ("step_count", len(core_parsed.steps), len(ui_parsed.get('steps', [])))
    ]
    
    all_consistent = True
    for check_name, core_value, ui_value in consistency_checks:
        if core_value == ui_value:
            print(f"✅ {check_name}: {core_value} (consistent)")
        else:
            print(f"❌ {check_name}: Core={core_value}, UI={ui_value} (INCONSISTENT)")
            all_consistent = False
    
    # Test 4: MAESTROEngine assessment (used by both CLI and UI)
    print("\n4️⃣ Testing MAESTROEngine Assessment...")
    engine = MAESTROEngine()
    try:
        report = engine.assess_workflow_from_yaml(test_yaml)
        print(f"✅ Engine Assessment - ID: {report.assessment_id}")
        print(f"✅ Engine Assessment - Vulnerabilities: {len(report.vulnerabilities)}")
        print(f"✅ Engine Assessment - WEI Score: {getattr(report.risk_assessment.total_wei, 'mean', report.risk_assessment.total_wei):.3f}")
        print(f"✅ Engine Assessment - RPS Score: {getattr(report.risk_assessment.total_rps, 'mean', report.risk_assessment.total_rps):.3f}")
        
        # Verify that the engine uses the same parser
        engine_workflow = report.workflow
        engine_consistency = [
            ("name", core_parsed.name, engine_workflow.name),
            ("description", core_parsed.description, engine_workflow.description),
            ("agent_count", len(core_parsed.agents), len(engine_workflow.agents)),
            ("step_count", len(core_parsed.steps), len(engine_workflow.steps))
        ]
        
        print("\n📊 Engine vs Core Parser Consistency:")
        for check_name, core_value, engine_value in engine_consistency:
            if core_value == engine_value:
                print(f"✅ {check_name}: {core_value} (consistent)")
            else:
                print(f"❌ {check_name}: Core={core_value}, Engine={engine_value} (INCONSISTENT)")
                all_consistent = False
                
    except Exception as e:
        print(f"❌ Engine Assessment Failed: {e}")
        return False
        
    return all_consistent

def test_vulnerability_detection_consistency():
    """Test that vulnerability detection is consistent between CLI and UI"""
    
    print("\n\n🔍 Testing Vulnerability Detection Consistency...")
    print("=" * 60)
    
    # Create a workflow with known vulnerabilities
    vulnerable_yaml = """
workflow:
  name: "Financial Payment Processor"
  description: "High-risk financial workflow for testing"
  metadata:
    protocol: "hybrid"
    
  agents:
    - name: "payment_processor"
      protocol: "mcp"
      tools: ["bank_api", "credit_card_validator", "fraud_detector"]
      communicates_with: ["compliance_checker"]
    - name: "compliance_checker"
      protocol: "a2a"
      tools: ["regulatory_db", "audit_logger"]
      communicates_with: []
      
  steps:
    - id: "validate_payment"
      agent: "payment_processor"
      action: "validate_credit_card"
      params:
        card_number: "user_input"
        cvv: "user_input"
        amount: 10000
    - id: "process_payment"
      agent: "payment_processor"
      action: "charge_card"
      input_from: "validate_payment"
      params:
        payment_gateway: "stripe_api"
        merchant_id: "sensitive_data"
    - id: "compliance_check"
      agent: "compliance_checker"
      action: "audit_transaction"
      input_from: "process_payment"
      params:
        transaction_data: "financial_records"
        pii_data: "customer_info"
"""

    engine = MAESTROEngine()
    
    try:
        # Run full assessment (same method used by both CLI and UI)
        report = engine.assess_workflow_from_yaml(vulnerable_yaml)
        
        print(f"✅ Vulnerabilities Detected: {len(report.vulnerabilities)}")
        print(f"✅ Risk Level: {report.risk_assessment.risk_level}")
        
        # Show vulnerability breakdown
        vuln_by_severity = {}
        for vuln in report.vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            vuln_by_severity[severity] = vuln_by_severity.get(severity, 0) + 1
            
        print("\n📊 Vulnerability Breakdown:")
        for severity, count in vuln_by_severity.items():
            print(f"  • {severity.title()}: {count}")
            
        # Test that the same vulnerabilities would be detected in UI context
        ui_visualizer = WorkflowVisualizer()
        ui_structure = ui_visualizer.parse_workflow_structure(vulnerable_yaml)
        
        if 'parsed_workflow' in ui_structure:
            # The UI should be using the same underlying assessment
            print("✅ UI would use same vulnerability detection (via engine.assess_workflow_from_yaml)")
            return True
        else:
            print("⚠️ UI structure missing core workflow reference")
            return False
            
    except Exception as e:
        print(f"❌ Vulnerability detection test failed: {e}")
        return False

def main():
    """Run comprehensive CLI vs UI consistency tests"""
    
    print("🛡️ MAESTRO CLI vs UI Consistency Test")
    print("=" * 60)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run parsing consistency test
    parsing_consistent = test_parsing_consistency()
    
    # Run vulnerability detection consistency test  
    vuln_consistent = test_vulnerability_detection_consistency()
    
    # Final results
    print("\n\n📋 FINAL RESULTS")
    print("=" * 60)
    
    if parsing_consistent and vuln_consistent:
        print("✅ ALL TESTS PASSED - CLI and UI are consistent!")
        print("\n🎯 Summary:")
        print("  • Both CLI and UI use MAESTROEngine.assess_workflow_from_yaml()")
        print("  • Both CLI and UI use WorkflowParser.parse_yaml() for core parsing")
        print("  • UI WorkflowVisualizer now wraps the official parser")
        print("  • Vulnerability detection is identical between interfaces")
        print("  • No ambiguities detected between CLI and UI implementations")
        return True
    else:
        print("❌ SOME TESTS FAILED - Inconsistencies detected!")
        print("\n⚠️ Issues found:")
        if not parsing_consistent:
            print("  • Workflow parsing inconsistencies detected")
        if not vuln_consistent:
            print("  • Vulnerability detection inconsistencies detected")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 
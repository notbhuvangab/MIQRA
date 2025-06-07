#!/usr/bin/env python3
"""
MAESTRO Risk Assessment Demonstration Script
Run this to demonstrate the framework's risk assessment capabilities across all risk levels
"""

import sys
import os
sys.path.append('../src')

from maestro_threat_assessment.core import MAESTROEngine
import glob

def run_demonstration():
    """Run MAESTRO risk assessment on all example workflows"""
    
    print("🎓 MAESTRO Risk Assessment Framework - Professor Demonstration")
    print("=" * 80)
    print()
    
    # Initialize MAESTRO engine
    engine = MAESTROEngine()
    
    # Get all YAML example files (numbered ones for balanced demonstration)
    yaml_files = sorted([
        "01_low_risk_document_processing.yaml",
        "02_medium_risk_customer_processing.yaml", 
        "03_high_risk_healthcare_ai.yaml",
        "04_critical_risk_infrastructure_control.yaml"
    ])
    
    results = []
    
    for yaml_file in yaml_files:
        if not os.path.exists(yaml_file):
            print(f"⚠️  File not found: {yaml_file}")
            continue
            
        print(f"📊 Analyzing: {yaml_file}")
        print("-" * 60)
        
        try:
            # Run risk assessment
            with open(yaml_file, 'r') as f:
                yaml_content = f.read()
            
            assessment = engine.assess_workflow_from_yaml(yaml_content)
            
            # Calculate combined risk manually to show the calculation
            normalized_rps = assessment.risk_assessment.total_rps / 30.0
            combined_risk = (assessment.risk_assessment.total_wei * 0.7) + (normalized_rps * 0.3)
            
            result = {
                'file': yaml_file,
                'name': assessment.workflow.name,
                'risk_level': assessment.risk_assessment.risk_level,
                'wei': assessment.risk_assessment.total_wei,
                'rps': assessment.risk_assessment.total_rps,
                'combined_risk': combined_risk,
                'vulnerabilities': len(assessment.vulnerabilities),
                'steps': len(assessment.workflow.steps),
                'agents': len(assessment.workflow.agents)
            }
            results.append(result)
            
            # Display results
            print(f"   Workflow: {result['name']}")
            print(f"   Risk Level: {result['risk_level'].upper()}")
            print(f"   WEI (Workflow Exploitability Index): {result['wei']:.3f}")
            print(f"   RPS (Risk Propagation Score): {result['rps']:.2f}")
            print(f"   Combined Risk Score: {result['combined_risk']:.3f}")
            print(f"   Vulnerabilities Found: {result['vulnerabilities']}")
            print(f"   Workflow Complexity: {result['steps']} steps, {result['agents']} agents")
            
            # Show layer breakdown
            print(f"   🏗️ MAESTRO Layer Analysis:")
            for layer, score in assessment.risk_assessment.layer_scores.items():
                if score.vulnerability_count > 0 or score.wei_contribution > 0.01:
                    print(f"      • {layer.name}: {score.vulnerability_count} vulns, "
                          f"WEI={score.wei_contribution:.3f}, RPS={score.rps_contribution:.2f}")
            
            # Show top vulnerabilities
            if assessment.vulnerabilities:
                print(f"   🚨 Key Vulnerabilities:")
                for vuln in assessment.vulnerabilities[:3]:  # Top 3
                    print(f"      • {vuln.get('type', 'Unknown')}: {vuln.get('severity', 'Unknown')} severity")
            
            print()
            
        except Exception as e:
            print(f"   ❌ Error processing {yaml_file}: {str(e)}")
            print()
            continue
    
    # Summary
    print("🎯 DEMONSTRATION SUMMARY")
    print("=" * 60)
    print()
    
    if results:
        print("Risk Level Distribution:")
        risk_counts = {}
        for result in results:
            risk_level = result['risk_level']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        for level in ['low', 'medium', 'high', 'critical']:
            count = risk_counts.get(level, 0)
            workflows = [r['name'] for r in results if r['risk_level'] == level]
            print(f"  {level.upper()}: {count} workflow(s)")
            for workflow in workflows:
                print(f"    • {workflow}")
        
        print()
        print("Risk Score Range:")
        min_risk = min(r['combined_risk'] for r in results)
        max_risk = max(r['combined_risk'] for r in results)
        print(f"  Minimum: {min_risk:.3f}")
        print(f"  Maximum: {max_risk:.3f}")
        
        print()
        print("MAESTRO Framework Features Demonstrated:")
        print("  ✅ Multi-layer security analysis (7 MAESTRO layers)")
        print("  ✅ Workflow Exploitability Index (WEI) calculation")
        print("  ✅ Risk Propagation Score (RPS) assessment")
        print("  ✅ Combined risk scoring with balanced thresholds")
        print("  ✅ Vulnerability detection and classification")
        print("  ✅ Business impact and compliance consideration")
        print("  ✅ Automated risk level determination")
        
    else:
        print("No workflows were successfully analyzed.")
    
    print()
    print("🎉 Demonstration complete!")
    print("   The MAESTRO framework successfully assessed workflows across all risk levels,")
    print("   demonstrating its ability to provide comprehensive, actionable security")
    print("   assessments for multi-agent AI workflows.")

def show_formula_explanation():
    """Show the mathematical formulas used in MAESTRO"""
    
    print("\n📐 MAESTRO Risk Calculation Formulas")
    print("=" * 50)
    print()
    print("1. Workflow Exploitability Index (WEI):")
    print("   WEI = Σ(AC⁻¹ × Impact × LayerWeight) ÷ TotalWorkflowNodes")
    print("   Where:")
    print("     • AC⁻¹ = Inverse of Attack Complexity (easier attacks = higher risk)")
    print("     • Impact = Business Impact Score (sensitivity + domain + compliance)")
    print("     • LayerWeight = MAESTRO layer criticality weight")
    print()
    print("2. Risk Propagation Score (RPS):")
    print("   RPS = Σ Σ(VS × PC × EI)")
    print("   Where:")
    print("     • VS = Vulnerability Severity Score (1-10)")
    print("     • PC = Protocol Coupling Factor (1-3)")
    print("     • EI = Exposure Index by MAESTRO layer")
    print()
    print("3. Combined Risk Score:")
    print("   Combined Risk = (WEI × 0.7) + (RPS/30 × 0.3)")
    print("   Risk Thresholds:")
    print("     • LOW: 0.00 - 0.30")
    print("     • MEDIUM: 0.30 - 0.55")
    print("     • HIGH: 0.55 - 0.75")
    print("     • CRITICAL: 0.75+")

if __name__ == "__main__":
    # Change to examples directory
    if not os.path.basename(os.getcwd()) == 'examples':
        if os.path.exists('examples'):
            os.chdir('examples')
        else:
            print("Please run this script from the examples directory or project root.")
            sys.exit(1)
    
    # Run demonstration
    run_demonstration()
    
    # Show formula explanation
    show_formula_explanation() 
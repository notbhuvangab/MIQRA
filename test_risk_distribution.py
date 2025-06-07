#!/usr/bin/env python3
"""
Test script to verify risk distribution across different workflow types
"""

import sys
import os
sys.path.append('src')

from maestro_threat_assessment.core import MAESTROEngine

def test_workflows():
    """Test various workflow types to see risk distribution"""
    
    workflows = [
        # Simple, low-risk workflow
        {
            "name": "Simple Content Generation",
            "yaml": """
workflow:
  name: "Simple Content Generation"
  description: "Basic content generation workflow"
  metadata:
    sensitivity: "low"
    compliance_frameworks: []
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "content_generation"
      agent: "ContentAgent"
      tools: ["llm_client"]
      data_flows: ["content"]
"""
        },
        # Medium risk workflow
        {
            "name": "Customer Data Processing",
            "yaml": """
workflow:
  name: "Customer Data Processing"
  description: "Customer support with data processing"
  metadata:
    sensitivity: "medium"
    compliance_frameworks: ["GDPR"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "data_ingestion"
      agent: "DataAgent"
      tools: ["database_connector", "api_client"]
      data_flows: ["customer_data"]
    - name: "processing"
      agent: "ProcessingAgent"
      tools: ["ml_inference", "validator"]
      data_flows: ["processed_data"]
    - name: "customer_interaction"
      agent: "CustomerAgent"
      tools: ["chat_client", "email_sender"]
      data_flows: ["responses"]
"""
        },
        # High risk workflow
        {
            "name": "Healthcare AI Diagnostic System",
            "yaml": """
workflow:
  name: "Healthcare AI Diagnostic System"
  description: "Medical diagnosis with AI assistance"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["HIPAA", "GDPR"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "patient_data_intake"
      agent: "IntakeAgent"
      tools: ["ehr_connector", "image_processor"]
      data_flows: ["patient_records", "medical_images"]
    - name: "ai_diagnosis"
      agent: "DiagnosticAgent"
      tools: ["ml_model", "medical_database"]
      data_flows: ["diagnostic_results"]
    - name: "treatment_planning"
      agent: "TreatmentAgent"
      tools: ["protocol_engine", "drug_database"]
      data_flows: ["treatment_plans"]
    - name: "physician_review"
      agent: "ReviewAgent"
      tools: ["approval_system", "alert_system"]
      data_flows: ["approved_plans"]
    - name: "patient_communication"
      agent: "CommunicationAgent"
      tools: ["notification_system", "portal_client"]
      data_flows: ["patient_notifications"]
"""
        },
        # Critical risk workflow
        {
            "name": "Autonomous Financial Trading",
            "yaml": """
workflow:
  name: "Autonomous Financial Trading System"
  description: "High-frequency autonomous trading with multiple agents"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["SOX", "PCI_DSS", "BASEL_III", "MiFID_II"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "market_data_ingestion"
      agent: "MarketDataAgent"
      tools: ["bloomberg_api", "reuters_feed", "internal_feeds"]
      data_flows: ["market_data", "alternative_data"]
    - name: "risk_analysis"
      agent: "RiskAnalysisAgent"
      tools: ["var_calculator", "stress_tester", "ml_models"]
      data_flows: ["risk_metrics", "stress_results"]
    - name: "algorithmic_trading"
      agent: "TradingAgent"
      tools: ["execution_engine", "order_management", "position_tracker"]
      data_flows: ["trading_signals", "orders", "executions"]
    - name: "portfolio_management"
      agent: "PortfolioAgent"
      tools: ["optimizer", "rebalancer", "hedge_calculator"]
      data_flows: ["portfolio_updates", "hedging_instructions"]
    - name: "compliance_monitoring"
      agent: "ComplianceAgent"
      tools: ["regulatory_checker", "audit_logger", "alert_system"]
      data_flows: ["compliance_reports", "violations"]
    - name: "client_reporting"
      agent: "ReportingAgent"
      tools: ["report_generator", "distribution_engine", "encryption"]
      data_flows: ["client_reports", "regulatory_filings"]
    - name: "settlement_processing"
      agent: "SettlementAgent"
      tools: ["clearing_system", "custody_connector", "payment_processor"]
      data_flows: ["settlement_instructions", "confirmations"]
    - name: "fraud_detection"
      agent: "FraudAgent"
      tools: ["anomaly_detector", "pattern_analyzer", "investigation_tools"]
      data_flows: ["fraud_alerts", "case_data"]
"""
        }
    ]
    
    print("🧪 Testing Risk Distribution Across Workflow Types")
    print("=" * 80)
    print()
    
    engine = MAESTROEngine()
    results = []
    
    for workflow in workflows:
        print(f"📊 Testing: {workflow['name']}")
        print("-" * 60)
        
        assessment = engine.assess_workflow_from_yaml(workflow['yaml'])
        
        # Calculate combined risk manually
        normalized_rps = assessment.risk_assessment.total_rps / 30.0
        combined_risk = (assessment.risk_assessment.total_wei * 0.7) + (normalized_rps * 0.3)
        
        result = {
            'name': workflow['name'],
            'risk_level': assessment.risk_assessment.risk_level,
            'wei': assessment.risk_assessment.total_wei,
            'rps': assessment.risk_assessment.total_rps,
            'combined_risk': combined_risk,
            'vulnerabilities': len(assessment.vulnerabilities),
            'steps': len(assessment.workflow.steps)
        }
        results.append(result)
        
        print(f"   Risk Level: {result['risk_level'].upper()}")
        print(f"   WEI: {result['wei']:.3f}")
        print(f"   RPS: {result['rps']:.2f}")
        print(f"   Combined Risk: {result['combined_risk']:.3f}")
        print(f"   Vulnerabilities: {result['vulnerabilities']}")
        print(f"   Steps: {result['steps']}")
        print()
    
    print("🎯 Risk Distribution Summary")
    print("=" * 80)
    
    # Group by risk level
    risk_distribution = {}
    for result in results:
        risk_level = result['risk_level']
        if risk_level not in risk_distribution:
            risk_distribution[risk_level] = []
        risk_distribution[risk_level].append(result['name'])
    
    for risk_level in ['low', 'medium', 'high', 'critical']:
        workflows_in_level = risk_distribution.get(risk_level, [])
        print(f"{risk_level.upper()}: {len(workflows_in_level)} workflows")
        for workflow_name in workflows_in_level:
            print(f"   • {workflow_name}")
        print()
    
    print("📏 Risk Thresholds:")
    print("   • Low: 0.0 - 0.25")
    print("   • Medium: 0.25 - 0.50") 
    print("   • High: 0.50 - 0.80")
    print("   • Critical: 0.80+")
    print()
    
    # Recommendations for threshold adjustment
    combined_risks = [r['combined_risk'] for r in results]
    min_risk = min(combined_risks)
    max_risk = max(combined_risks)
    
    print(f"📈 Combined Risk Range: {min_risk:.3f} - {max_risk:.3f}")
    
    if max_risk < 0.25:
        print("⚠️  All workflows are below MEDIUM threshold - consider lowering thresholds")
    elif max_risk < 0.50:
        print("⚠️  No workflows reach HIGH threshold - may need fine-tuning")
    elif max_risk < 0.80:
        print("⚠️  No workflows reach CRITICAL threshold - may need adjustment for extreme cases")
    else:
        print("✅ Good risk distribution across all levels")

if __name__ == "__main__":
    test_workflows() 
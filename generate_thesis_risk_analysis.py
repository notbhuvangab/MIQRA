#!/usr/bin/env python3
"""
Comprehensive MAESTRO Risk Analysis for Thesis
Generates workflows across all risk levels and creates publication-quality plots
"""

import sys
import os
sys.path.append('src')

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from maestro_threat_assessment.core import MAESTROEngine

# Set style for publication-quality plots
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

def get_all_workflows():
    """Get comprehensive set of workflows covering all risk levels"""
    
    workflows = [
        # LOW RISK WORKFLOWS
        {
            "name": "Simple Content Generation",
            "category": "Content Creation",
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
        {
            "name": "Basic Document Processing",
            "category": "Document Management", 
            "yaml": """
workflow:
  name: "Basic Document Processing"
  description: "Simple document parsing and formatting"
  metadata:
    sensitivity: "low"
    compliance_frameworks: []
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "document_intake"
      agent: "IntakeAgent"
      tools: ["pdf_parser"]
      data_flows: ["documents"]
    - name: "formatting"
      agent: "FormatterAgent"
      tools: ["text_processor"]
      data_flows: ["formatted_docs"]
"""
        },
        
        # MEDIUM RISK WORKFLOWS
        {
            "name": "Customer Data Processing",
            "category": "Customer Support",
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
        {
            "name": "E-commerce Recommendation System",
            "category": "E-commerce",
            "yaml": """
workflow:
  name: "E-commerce Recommendation System"
  description: "Personalized product recommendations with user tracking"
  metadata:
    sensitivity: "medium"
    compliance_frameworks: ["GDPR", "CCPA"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "user_behavior_tracking"
      agent: "TrackingAgent"
      tools: ["analytics_engine", "cookie_manager"]
      data_flows: ["user_interactions", "browsing_history"]
    - name: "recommendation_engine"
      agent: "RecommendationAgent"
      tools: ["ml_recommender", "collaborative_filter"]
      data_flows: ["recommendations", "user_profiles"]
    - name: "personalization"
      agent: "PersonalizationAgent"
      tools: ["content_optimizer", "ab_tester"]
      data_flows: ["personalized_content"]
    - name: "inventory_integration"
      agent: "InventoryAgent"
      tools: ["stock_checker", "pricing_engine"]
      data_flows: ["inventory_data", "price_updates"]
"""
        },
        
        # HIGH RISK WORKFLOWS
        {
            "name": "Healthcare AI Diagnostic System",
            "category": "Healthcare",
            "yaml": """
workflow:
  name: "Healthcare AI Diagnostic System"
  description: "AI-powered medical diagnosis with patient data processing"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["HIPAA", "GDPR", "FDA_510K"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "patient_data_intake"
      agent: "IntakeAgent"
      tools: ["ehr_connector", "image_processor", "lab_interface", "vital_monitors"]
      data_flows: ["patient_records", "medical_images", "lab_results", "vital_signs"]
    - name: "ai_diagnosis"
      agent: "DiagnosticAgent"
      tools: ["ml_model", "medical_database", "symptom_analyzer", "image_classifier"]
      data_flows: ["diagnostic_results", "confidence_scores", "differential_diagnosis"]
    - name: "treatment_planning"
      agent: "TreatmentAgent"
      tools: ["protocol_engine", "drug_database", "interaction_checker", "dosage_calculator"]
      data_flows: ["treatment_plans", "medication_orders", "contraindications"]
    - name: "physician_review"
      agent: "ReviewAgent"
      tools: ["approval_system", "alert_system", "second_opinion", "risk_assessor"]
      data_flows: ["approved_plans", "physician_notes", "risk_flags"]
    - name: "patient_communication"
      agent: "CommunicationAgent"
      tools: ["notification_system", "portal_client", "appointment_scheduler", "education_provider"]
      data_flows: ["patient_notifications", "educational_content"]
    - name: "regulatory_reporting"
      agent: "ComplianceAgent"
      tools: ["fda_reporter", "quality_monitor", "adverse_event_tracker"]
      data_flows: ["regulatory_reports", "quality_metrics"]
"""
        },
        {
            "name": "Autonomous Financial Trading",
            "category": "Financial Services",
            "yaml": """
workflow:
  name: "Autonomous Financial Trading System"
  description: "High-frequency autonomous trading with risk management"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["SOX", "PCI_DSS", "BASEL_III", "MiFID_II", "CFTC"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "market_data_ingestion"
      agent: "MarketDataAgent"
      tools: ["bloomberg_api", "reuters_feed", "internal_feeds", "alternative_data"]
      data_flows: ["market_data", "news_sentiment", "social_signals"]
    - name: "risk_analysis"
      agent: "RiskAnalysisAgent"
      tools: ["var_calculator", "stress_tester", "ml_models", "monte_carlo"]
      data_flows: ["risk_metrics", "stress_results", "var_calculations"]
    - name: "algorithmic_trading"
      agent: "TradingAgent"
      tools: ["execution_engine", "order_management", "position_tracker", "slippage_minimizer"]
      data_flows: ["trading_signals", "orders", "executions", "slippage_data"]
    - name: "portfolio_management"
      agent: "PortfolioAgent"
      tools: ["optimizer", "rebalancer", "hedge_calculator", "exposure_monitor"]
      data_flows: ["portfolio_updates", "hedging_instructions", "exposure_reports"]
    - name: "compliance_monitoring"
      agent: "ComplianceAgent"
      tools: ["regulatory_checker", "audit_logger", "alert_system", "position_limits"]
      data_flows: ["compliance_reports", "violations", "audit_trails"]
    - name: "client_reporting"
      agent: "ReportingAgent"
      tools: ["report_generator", "distribution_engine", "encryption", "performance_analytics"]
      data_flows: ["client_reports", "regulatory_filings", "performance_data"]
    - name: "settlement_processing"
      agent: "SettlementAgent"
      tools: ["clearing_system", "custody_connector", "payment_processor", "reconciliation"]
      data_flows: ["settlement_instructions", "confirmations", "reconciliation_reports"]
    - name: "fraud_detection"
      agent: "FraudAgent"
      tools: ["anomaly_detector", "pattern_analyzer", "investigation_tools", "ml_fraud_model"]
      data_flows: ["fraud_alerts", "case_data", "investigation_reports"]
"""
        },
        
        # CRITICAL RISK WORKFLOWS
        {
            "name": "Critical Infrastructure Control System",
            "category": "Critical Infrastructure",
            "yaml": """
workflow:
  name: "Smart Grid AI Management System"
  description: "AI-powered critical infrastructure management with autonomous control"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["NERC_CIP", "NIST_CSF", "IEC_62351", "GDPR", "SOX", "FISMA"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "sensor_data_collection"
      agent: "SensorAgent"
      tools: ["scada_interface", "iot_collectors", "weather_stations", "demand_forecasters", "grid_monitors"]
      data_flows: ["sensor_readings", "weather_data", "demand_forecasts", "grid_status", "equipment_health"]
    - name: "ai_grid_optimization"
      agent: "OptimizationAgent"
      tools: ["load_balancer", "generation_optimizer", "transmission_planner", "ml_predictor", "real_time_controller"]
      data_flows: ["optimization_commands", "load_predictions", "generation_schedules", "contingency_plans"]
    - name: "autonomous_control"
      agent: "ControlAgent"
      tools: ["substation_controllers", "generator_controls", "load_shedding", "protection_systems", "emergency_shutdown"]
      data_flows: ["control_signals", "protection_commands", "emergency_responses", "isolation_orders"]
    - name: "cybersecurity_monitoring"
      agent: "CyberSecAgent"
      tools: ["ids_system", "threat_hunter", "anomaly_detector", "forensic_analyzer", "incident_responder"]
      data_flows: ["security_alerts", "threat_intelligence", "incident_reports", "forensic_evidence"]
    - name: "predictive_maintenance"
      agent: "MaintenanceAgent"
      tools: ["condition_monitor", "failure_predictor", "maintenance_scheduler", "spare_parts_manager", "crew_dispatcher"]
      data_flows: ["maintenance_alerts", "failure_predictions", "work_orders", "parts_inventory"]
    - name: "regulatory_compliance"
      agent: "ComplianceAgent"
      tools: ["nerc_reporter", "audit_system", "violation_detector", "documentation_engine", "training_tracker"]
      data_flows: ["compliance_reports", "audit_trails", "violation_alerts", "training_records"]
    - name: "emergency_response"
      agent: "EmergencyAgent"
      tools: ["crisis_manager", "public_notification", "coordination_hub", "media_interface", "government_liaison"]
      data_flows: ["emergency_alerts", "public_notifications", "coordination_messages", "status_updates"]
    - name: "market_operations"
      agent: "MarketAgent"
      tools: ["energy_trader", "price_forecaster", "settlement_system", "capacity_planner", "ancillary_services"]
      data_flows: ["trading_decisions", "price_forecasts", "settlement_data", "market_reports"]
    - name: "customer_services"
      agent: "CustomerAgent"
      tools: ["billing_system", "outage_communication", "demand_response", "smart_meter_interface", "customer_portal"]
      data_flows: ["billing_data", "outage_notifications", "demand_signals", "usage_analytics"]
    - name: "external_coordination"
      agent: "CoordinationAgent"
      tools: ["iso_interface", "utility_coordination", "government_reporting", "vendor_management", "third_party_apis"]
      data_flows: ["coordination_data", "external_reports", "vendor_communications", "api_exchanges"]
"""
        },
        {
            "name": "Autonomous Weapons Defense System",
            "category": "Defense/Military",
            "yaml": """
workflow:
  name: "Autonomous Defense and Weapons Control System"
  description: "AI-powered autonomous defense system with lethal decision capabilities"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["ITAR", "DoD_5000", "NATO_STANAG", "Geneva_Convention", "NIST_800_53", "FISMA", "GDPR"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "threat_detection"
      agent: "ThreatDetectionAgent"
      tools: ["radar_systems", "satellite_feeds", "drone_surveillance", "signal_intelligence", "human_intelligence", "cyber_monitors"]
      data_flows: ["threat_signatures", "satellite_imagery", "signal_intercepts", "cyber_threats", "intel_reports"]
    - name: "target_classification"
      agent: "ClassificationAgent"
      tools: ["ai_classifier", "pattern_recognition", "biometric_analyzer", "vehicle_identifier", "behavior_analyzer", "friend_foe_identifier"]
      data_flows: ["target_classifications", "threat_assessments", "identity_confirmations", "behavior_profiles"]
    - name: "tactical_planning"
      agent: "TacticalAgent"
      tools: ["mission_planner", "route_optimizer", "resource_allocator", "contingency_planner", "rules_of_engagement", "collateral_assessor"]
      data_flows: ["mission_plans", "engagement_rules", "resource_assignments", "risk_assessments"]
    - name: "autonomous_weapons_control"
      agent: "WeaponsAgent"
      tools: ["missile_launcher", "gun_systems", "countermeasures", "jamming_equipment", "cyber_weapons", "directed_energy"]
      data_flows: ["weapon_commands", "targeting_data", "engagement_authorizations", "battle_damage_assessments"]
    - name: "human_oversight"
      agent: "OversightAgent"
      tools: ["command_interface", "kill_switch", "manual_override", "ethical_checker", "legal_advisor", "commander_approval"]
      data_flows: ["human_decisions", "override_commands", "ethical_flags", "legal_clearances"]
    - name: "battle_damage_assessment"
      agent: "AssessmentAgent"
      tools: ["damage_analyzer", "casualty_estimator", "effectiveness_evaluator", "collateral_calculator", "mission_assessor"]
      data_flows: ["damage_reports", "casualty_estimates", "effectiveness_metrics", "mission_outcomes"]
    - name: "intelligence_fusion"
      agent: "IntelligenceAgent"
      tools: ["data_fusion", "pattern_analysis", "predictive_modeling", "social_network_analysis", "behavioral_prediction", "strategic_analysis"]
      data_flows: ["fused_intelligence", "threat_predictions", "strategic_insights", "network_maps"]
    - name: "communications_warfare"
      agent: "CommsWarfareAgent"
      tools: ["electronic_warfare", "signal_jamming", "cyber_attacks", "information_operations", "propaganda_detection", "disinformation"]
      data_flows: ["jamming_commands", "cyber_payloads", "information_campaigns", "counter_intelligence"]
    - name: "logistics_coordination"
      agent: "LogisticsAgent"
      tools: ["supply_chain", "ammunition_tracker", "fuel_management", "maintenance_scheduler", "personnel_tracker", "medical_support"]
      data_flows: ["supply_requests", "maintenance_alerts", "personnel_status", "medical_data"]
    - name: "command_control"
      agent: "CommandAgent"
      tools: ["strategic_planner", "force_coordinator", "mission_commander", "alliance_coordinator", "political_liaison", "media_manager"]
      data_flows: ["strategic_orders", "force_movements", "alliance_communications", "political_guidance"]
    - name: "legal_compliance"
      agent: "LegalAgent"
      tools: ["law_of_war_checker", "geneva_validator", "civilian_protector", "proportionality_assessor", "evidence_collector", "war_crimes_detector"]
      data_flows: ["legal_clearances", "compliance_reports", "evidence_packages", "violation_alerts"]
    - name: "psychological_operations"
      agent: "PsyOpsAgent"
      tools: ["influence_operations", "morale_analyzer", "propaganda_generator", "social_media_ops", "cultural_analyzer", "population_tracker"]
      data_flows: ["influence_campaigns", "morale_reports", "cultural_insights", "population_data"]
"""
        }
    ]
    
    return workflows

def analyze_all_workflows():
    """Analyze all workflows and return results"""
    
    workflows = get_all_workflows()
    engine = MAESTROEngine()
    results = []
    
    print("🧪 Comprehensive MAESTRO Risk Analysis for Thesis")
    print("=" * 80)
    print()
    
    for workflow in workflows:
        print(f"📊 Analyzing: {workflow['name']}")
        print(f"   Category: {workflow['category']}")
        print("-" * 60)
        
        assessment = engine.assess_workflow_from_yaml(workflow['yaml'])
        
        # Calculate combined risk manually
        normalized_rps = assessment.risk_assessment.total_rps / 30.0
        combined_risk = (assessment.risk_assessment.total_wei * 0.7) + (normalized_rps * 0.3)
        
        result = {
            'name': workflow['name'],
            'category': workflow['category'],
            'risk_level': assessment.risk_assessment.risk_level,
            'wei': assessment.risk_assessment.total_wei,
            'rps': assessment.risk_assessment.total_rps,
            'combined_risk': combined_risk,
            'vulnerabilities': len(assessment.vulnerabilities),
            'steps': len(assessment.workflow.steps),
            'agents': len(assessment.workflow.agents),
            'data_flows': len(assessment.workflow.data_flows)
        }
        results.append(result)
        
        print(f"   Risk Level: {result['risk_level'].upper()}")
        print(f"   WEI: {result['wei']:.3f}")
        print(f"   RPS: {result['rps']:.2f}")
        print(f"   Combined Risk: {result['combined_risk']:.3f}")
        print(f"   Vulnerabilities: {result['vulnerabilities']}")
        print(f"   Steps: {result['steps']}")
        print(f"   Agents: {result['agents']}")
        print()
    
    return results

def create_risk_distribution_plots(results):
    """Create comprehensive risk distribution plots for thesis"""
    
    # Set up the figure with subplots
    fig = plt.figure(figsize=(16, 12))
    
    # Define colors for each risk level
    risk_colors = {
        'low': '#2E8B57',      # Sea Green
        'medium': '#FFD700',    # Gold
        'high': '#FF8C00',      # Dark Orange
        'critical': '#DC143C'   # Crimson
    }
    
    # 1. Main Risk Distribution Bar Chart
    ax1 = plt.subplot(2, 2, 1)
    risk_counts = {}
    for result in results:
        risk_level = result['risk_level']
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
    
    levels = ['low', 'medium', 'high', 'critical']
    counts = [risk_counts.get(level, 0) for level in levels]
    colors = [risk_colors[level] for level in levels]
    
    bars = ax1.bar(levels, counts, color=colors, alpha=0.8, edgecolor='black', linewidth=1)
    ax1.set_title('MAESTRO Risk Level Distribution', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Risk Level', fontsize=12)
    ax1.set_ylabel('Number of Workflows', fontsize=12)
    ax1.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for bar, count in zip(bars, counts):
        if count > 0:
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                    str(count), ha='center', va='bottom', fontweight='bold')
    
    # 2. Combined Risk Score Scatter Plot
    ax2 = plt.subplot(2, 2, 2)
    x_pos = []
    y_values = []
    colors_scatter = []
    
    for i, result in enumerate(results):
        x_pos.append(i)
        y_values.append(result['combined_risk'])
        colors_scatter.append(risk_colors[result['risk_level']])
    
    scatter = ax2.scatter(x_pos, y_values, c=colors_scatter, s=100, alpha=0.8, edgecolors='black')
    
    # Add threshold lines
    ax2.axhline(y=0.25, color='gray', linestyle='--', alpha=0.5, label='Medium Threshold (0.25)')
    ax2.axhline(y=0.50, color='gray', linestyle='--', alpha=0.5, label='High Threshold (0.50)')
    ax2.axhline(y=0.80, color='gray', linestyle='--', alpha=0.5, label='Critical Threshold (0.80)')
    
    ax2.set_title('Combined Risk Scores by Workflow', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Workflow Index', fontsize=12)
    ax2.set_ylabel('Combined Risk Score', fontsize=12)
    ax2.grid(True, alpha=0.3)
    ax2.legend(fontsize=8)
    
    # Rotate x-axis labels for better readability
    workflow_names = [result['name'][:15] + '...' if len(result['name']) > 15 else result['name'] 
                     for result in results]
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(workflow_names, rotation=45, ha='right', fontsize=8)
    
    # 3. Risk Components Analysis (WEI vs RPS)
    ax3 = plt.subplot(2, 2, 3)
    wei_values = [result['wei'] for result in results]
    rps_values = [result['rps'] for result in results]
    
    scatter2 = ax3.scatter(wei_values, rps_values, 
                          c=[risk_colors[result['risk_level']] for result in results],
                          s=100, alpha=0.8, edgecolors='black')
    
    ax3.set_title('Risk Components: WEI vs RPS', fontsize=14, fontweight='bold')
    ax3.set_xlabel('WEI (Workflow Exploitability Index)', fontsize=12)
    ax3.set_ylabel('RPS (Risk Propagation Score)', fontsize=12)
    ax3.grid(True, alpha=0.3)
    
    # Add workflow labels
    for i, result in enumerate(results):
        ax3.annotate(result['name'][:10], 
                    (wei_values[i], rps_values[i]),
                    xytext=(5, 5), textcoords='offset points',
                    fontsize=8, alpha=0.7)
    
    # 4. Workflow Complexity vs Risk
    ax4 = plt.subplot(2, 2, 4)
    complexity_scores = [result['steps'] * result['agents'] for result in results]
    combined_risks = [result['combined_risk'] for result in results]
    
    scatter3 = ax4.scatter(complexity_scores, combined_risks,
                          c=[risk_colors[result['risk_level']] for result in results],
                          s=100, alpha=0.8, edgecolors='black')
    
    ax4.set_title('Workflow Complexity vs Combined Risk', fontsize=14, fontweight='bold')
    ax4.set_xlabel('Complexity Score (Steps × Agents)', fontsize=12)
    ax4.set_ylabel('Combined Risk Score', fontsize=12)
    ax4.grid(True, alpha=0.3)
    
    # Add trend line
    z = np.polyfit(complexity_scores, combined_risks, 1)
    p = np.poly1d(z)
    ax4.plot(complexity_scores, p(complexity_scores), "r--", alpha=0.8, linewidth=2)
    
    # Create legend for risk levels
    legend_elements = [plt.Line2D([0], [0], marker='o', color='w', 
                                 markerfacecolor=risk_colors[level], 
                                 markersize=10, label=level.capitalize())
                      for level in levels if risk_counts.get(level, 0) > 0]
    
    fig.legend(handles=legend_elements, loc='upper center', bbox_to_anchor=(0.5, 0.02), 
              ncol=len(legend_elements), fontsize=12)
    
    plt.tight_layout()
    plt.subplots_adjust(bottom=0.1)
    
    return fig

def save_detailed_analysis(results):
    """Save detailed analysis results to files"""
    
    # Save summary statistics
    with open('maestro_risk_analysis_summary.txt', 'w') as f:
        f.write("MAESTRO Threat Assessment Framework - Comprehensive Risk Analysis\n")
        f.write("=" * 70 + "\n\n")
        
        # Risk distribution summary
        risk_counts = {}
        for result in results:
            risk_level = result['risk_level']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        f.write("Risk Level Distribution:\n")
        for level in ['low', 'medium', 'high', 'critical']:
            count = risk_counts.get(level, 0)
            percentage = (count / len(results)) * 100
            f.write(f"  {level.upper()}: {count} workflows ({percentage:.1f}%)\n")
        
        f.write(f"\nTotal Workflows Analyzed: {len(results)}\n\n")
        
        # Detailed workflow analysis
        f.write("Detailed Workflow Analysis:\n")
        f.write("-" * 40 + "\n")
        
        for result in results:
            f.write(f"\nWorkflow: {result['name']}\n")
            f.write(f"Category: {result['category']}\n")
            f.write(f"Risk Level: {result['risk_level'].upper()}\n")
            f.write(f"Combined Risk Score: {result['combined_risk']:.3f}\n")
            f.write(f"WEI: {result['wei']:.3f}\n")
            f.write(f"RPS: {result['rps']:.2f}\n")
            f.write(f"Vulnerabilities: {result['vulnerabilities']}\n")
            f.write(f"Steps: {result['steps']}\n")
            f.write(f"Agents: {result['agents']}\n")
            f.write(f"Data Flows: {result['data_flows']}\n")
    
    print("✅ Detailed analysis saved to 'maestro_risk_analysis_summary.txt'")

def main():
    """Main function to run comprehensive analysis"""
    
    print("🚀 MAESTRO Thesis Risk Analysis Generator")
    print("=" * 60)
    print()
    
    # Analyze all workflows
    results = analyze_all_workflows()
    
    # Print summary
    print("\n🎯 Risk Distribution Summary")
    print("=" * 60)
    
    risk_counts = {}
    for result in results:
        risk_level = result['risk_level']
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
    
    for level in ['low', 'medium', 'high', 'critical']:
        count = risk_counts.get(level, 0)
        percentage = (count / len(results)) * 100
        workflows_in_level = [r['name'] for r in results if r['risk_level'] == level]
        print(f"{level.upper()}: {count} workflows ({percentage:.1f}%)")
        for workflow_name in workflows_in_level:
            print(f"   • {workflow_name}")
        print()
    
    # Create and save plots
    print("📊 Generating publication-quality plots...")
    fig = create_risk_distribution_plots(results)
    
    # Save the plot
    plot_filename = 'maestro_risk_distribution_thesis.png'
    fig.savefig(plot_filename, dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    print(f"✅ Risk distribution plot saved as '{plot_filename}'")
    
    # Also save as PDF for thesis
    pdf_filename = 'maestro_risk_distribution_thesis.pdf'
    fig.savefig(pdf_filename, dpi=300, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    print(f"✅ Risk distribution plot saved as '{pdf_filename}'")
    
    # Save detailed analysis
    save_detailed_analysis(results)
    
    print(f"\n🎉 Analysis complete! Generated:")
    print(f"   • {plot_filename} (PNG format)")
    print(f"   • {pdf_filename} (PDF format for thesis)")
    print(f"   • maestro_risk_analysis_summary.txt (detailed results)")
    
    # Show the plot
    plt.show()

if __name__ == "__main__":
    main() 
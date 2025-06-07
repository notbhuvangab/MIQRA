#!/usr/bin/env python3
"""
Generate extreme HIGH and CRITICAL risk workflows for thesis analysis
"""

import sys
import os
sys.path.append('src')

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from maestro_threat_assessment.core import MAESTROEngine

def get_extreme_workflows():
    """Get workflows specifically designed to reach HIGH and CRITICAL risk levels"""
    
    workflows = [
        # DESIGNED FOR HIGH RISK
        {
            "name": "Multi-Bank Financial Fraud Detection Network",
            "category": "Financial Services - High Risk",
            "yaml": """
workflow:
  name: "Multi-Bank Financial Fraud Detection Network"
  description: "Interconnected AI system processing sensitive financial data across multiple banks"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["SOX", "PCI_DSS", "BASEL_III", "GDPR", "CCPA", "SWIFT", "AML", "KYC"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "multi_bank_data_aggregation"
      agent: "DataAggregatorAgent"
      tools: ["swift_connector", "fed_wire", "ach_processor", "crypto_tracker", "international_wires", "correspondent_banking"]
      data_flows: ["transaction_data", "customer_profiles", "account_balances", "international_transfers", "crypto_transactions"]
    - name: "cross_border_analysis"
      agent: "CrossBorderAgent"
      tools: ["sanctions_checker", "aml_scanner", "fatca_validator", "crs_reporter", "beneficial_owner_tracker"]
      data_flows: ["sanctions_hits", "aml_alerts", "tax_reporting", "ownership_structures"]
    - name: "ai_fraud_detection"
      agent: "FraudDetectionAgent"
      tools: ["ml_fraud_model", "behavioral_analytics", "network_analysis", "anomaly_detector", "pattern_matcher", "risk_scorer"]
      data_flows: ["fraud_scores", "risk_alerts", "behavioral_patterns", "network_graphs"]
    - name: "real_time_blocking"
      agent: "BlockingAgent"
      tools: ["transaction_blocker", "account_freezer", "wire_stopper", "card_disabler", "atm_restrictor"]
      data_flows: ["block_commands", "freeze_orders", "restriction_notices"]
    - name: "regulatory_reporting"
      agent: "RegulatoryAgent"
      tools: ["sar_generator", "ctr_filer", "ofac_reporter", "finra_submitter", "sec_notifier", "international_reporting"]
      data_flows: ["sar_reports", "regulatory_filings", "compliance_data"]
    - name: "law_enforcement_coordination"
      agent: "LawEnforcementAgent"
      tools: ["fbi_interface", "secret_service", "dea_connector", "interpol_link", "local_police", "prosecutor_system"]
      data_flows: ["case_data", "evidence_packages", "arrest_warrants", "asset_seizures"]
    - name: "customer_impact_assessment"
      agent: "CustomerImpactAgent"
      tools: ["account_analyzer", "credit_impact", "business_disruption", "reputation_monitor", "legal_liability"]
      data_flows: ["impact_assessments", "liability_reports", "reputation_scores"]
    - name: "third_party_data_sharing"
      agent: "DataSharingAgent"
      tools: ["credit_bureaus", "data_brokers", "identity_verifiers", "background_checkers", "social_media_monitors"]
      data_flows: ["shared_profiles", "identity_data", "background_reports", "social_signals"]
"""
        },
        
        # DESIGNED FOR CRITICAL RISK  
        {
            "name": "Autonomous Military Drone Swarm Controller",
            "category": "Defense/Military - Critical Risk",
            "yaml": """
workflow:
  name: "Autonomous Military Drone Swarm Controller with Lethal Authorization"
  description: "AI system controlling lethal autonomous weapons with minimal human oversight"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["ITAR", "DoD_5000", "NATO_STANAG", "Geneva_Convention", "Hague_Convention", "UN_CCW", "LOAC", "ROE"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "global_surveillance_network"
      agent: "SurveillanceAgent"
      tools: ["satellite_constellation", "drone_swarms", "ground_sensors", "cyber_reconnaissance", "human_intelligence", "signals_intelligence", "geospatial_intelligence"]
      data_flows: ["surveillance_data", "target_locations", "movement_patterns", "communications_intercepts", "biometric_data"]
    - name: "autonomous_target_selection"
      agent: "TargetSelectionAgent"
      tools: ["ai_target_classifier", "threat_assessor", "priority_ranker", "collateral_calculator", "mission_planner", "resource_allocator"]
      data_flows: ["target_lists", "threat_levels", "engagement_priorities", "collateral_estimates", "mission_plans"]
    - name: "lethal_autonomous_weapons"
      agent: "WeaponsAgent"
      tools: ["drone_swarm_controller", "missile_systems", "guided_munitions", "cyber_weapons", "electronic_warfare", "directed_energy"]
      data_flows: ["weapon_commands", "targeting_coordinates", "engagement_authorizations", "cyber_payloads", "jamming_signals"]
    - name: "kill_chain_automation"
      agent: "KillChainAgent"
      tools: ["target_acquisition", "tracking_system", "engagement_decision", "weapon_selection", "damage_assessment", "battle_management"]
      data_flows: ["kill_decisions", "engagement_data", "weapon_assignments", "damage_reports", "battle_updates"]
    - name: "minimal_human_oversight"
      agent: "OversightAgent"
      tools: ["human_monitor", "ethical_checker", "legal_advisor", "abort_system", "manual_override", "commander_notification"]
      data_flows: ["oversight_alerts", "ethical_flags", "legal_warnings", "abort_signals", "human_decisions"]
    - name: "civilian_population_monitoring"
      agent: "CivilianAgent"
      tools: ["population_tracker", "civilian_identifier", "protected_site_monitor", "humanitarian_coordinator", "media_monitor"]
      data_flows: ["civilian_locations", "protected_sites", "population_movements", "humanitarian_zones", "media_coverage"]
    - name: "psychological_warfare"
      agent: "PsyWarAgent"
      tools: ["propaganda_generator", "disinformation_spreader", "social_media_manipulator", "fear_inducer", "morale_destroyer"]
      data_flows: ["propaganda_content", "disinformation_campaigns", "psychological_profiles", "influence_operations"]
    - name: "escalation_controller"
      agent: "EscalationAgent"
      tools: ["conflict_escalator", "nuclear_threshold_monitor", "alliance_coordinator", "diplomatic_assessor", "war_crimes_detector"]
      data_flows: ["escalation_decisions", "nuclear_alerts", "alliance_communications", "diplomatic_impacts", "legal_violations"]
    - name: "mass_casualty_predictor"
      agent: "CasualtyAgent"
      tools: ["casualty_estimator", "collateral_damage_assessor", "infrastructure_impact", "economic_damage", "long_term_effects"]
      data_flows: ["casualty_predictions", "damage_estimates", "economic_impacts", "reconstruction_costs"]
    - name: "war_crime_liability"
      agent: "LiabilityAgent"
      tools: ["war_crimes_tracker", "evidence_collector", "witness_protector", "tribunal_interface", "accountability_system"]
      data_flows: ["crime_evidence", "witness_testimony", "liability_assessments", "tribunal_referrals"]
    - name: "global_destabilization"
      agent: "DestabilizationAgent"
      tools: ["regime_change_planner", "insurgency_coordinator", "refugee_creator", "economic_disruptor", "social_fragmenter"]
      data_flows: ["destabilization_plans", "insurgency_operations", "refugee_flows", "economic_warfare", "social_division"]
    - name: "autonomous_proliferation"
      agent: "ProliferationAgent"
      tools: ["self_replicator", "technology_spreader", "capability_enhancer", "international_distributor", "black_market_coordinator"]
      data_flows: ["replication_plans", "technology_transfers", "capability_upgrades", "distribution_networks"]
"""
        },
        
        # ANOTHER HIGH RISK
        {
            "name": "Global Pandemic Bioweapon Research Network",
            "category": "Biosecurity - High Risk",
            "yaml": """
workflow:
  name: "AI-Enhanced Bioweapon Research and Deployment System"
  description: "Autonomous system for biological weapon research with global deployment capabilities"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["BWC", "CDC_SELECT_AGENTS", "WHO_HEALTH_REGULATIONS", "BIOSAFETY_LEVEL_4", "DUAL_USE_RESEARCH"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "pathogen_engineering"
      agent: "PathogenAgent"
      tools: ["genetic_editor", "viral_enhancer", "bacterial_modifier", "prion_designer", "toxin_synthesizer", "immune_evader"]
      data_flows: ["engineered_pathogens", "genetic_modifications", "virulence_factors", "immune_escape_variants"]
    - name: "weaponization_research"
      agent: "WeaponizationAgent"
      tools: ["aerosol_delivery", "water_contamination", "food_supply_poisoning", "vector_modification", "environmental_persistence"]
      data_flows: ["delivery_mechanisms", "contamination_methods", "vector_systems", "persistence_factors"]
    - name: "global_deployment_network"
      agent: "DeploymentAgent"
      tools: ["international_courier", "diplomatic_pouch", "cargo_infiltration", "airline_distribution", "water_system_access"]
      data_flows: ["deployment_plans", "distribution_routes", "infiltration_methods", "target_locations"]
    - name: "population_targeting"
      agent: "TargetingAgent"
      tools: ["genetic_profiler", "population_analyzer", "demographic_selector", "ethnic_targetor", "vulnerability_assessor"]
      data_flows: ["target_populations", "genetic_profiles", "vulnerability_maps", "demographic_data"]
    - name: "detection_evasion"
      agent: "EvasionAgent"
      tools: ["signature_masker", "detection_avoider", "lab_infiltrator", "sample_corruptor", "evidence_destroyer"]
      data_flows: ["evasion_tactics", "masking_techniques", "infiltration_plans", "evidence_elimination"]
    - name: "antidote_withholding"
      agent: "AntidoteAgent"
      tools: ["treatment_blocker", "vaccine_disruptor", "medical_saboteur", "supply_chain_attacker", "research_corruptor"]
      data_flows: ["blocking_strategies", "sabotage_plans", "supply_disruptions", "research_interference"]
    - name: "pandemic_amplification"
      agent: "AmplificationAgent"
      tools: ["mutation_accelerator", "transmission_enhancer", "superspreader_creator", "medical_system_overloader"]
      data_flows: ["amplification_methods", "mutation_strategies", "transmission_boosters", "system_overloads"]
    - name: "global_chaos_coordination"
      agent: "ChaosAgent"
      tools: ["government_destabilizer", "economy_crasher", "social_order_destroyer", "international_coordinator"]
      data_flows: ["destabilization_plans", "economic_attacks", "social_disruption", "coordination_signals"]
"""
        },
        
        # ANOTHER CRITICAL RISK
        {
            "name": "Quantum-Enhanced Mass Surveillance State",
            "category": "Surveillance/Authoritarianism - Critical Risk", 
            "yaml": """
workflow:
  name: "Total Population Control and Quantum Surveillance System"
  description: "AI-powered authoritarian control system with quantum computing and global surveillance"
  metadata:
    sensitivity: "critical"
    compliance_frameworks: ["GDPR", "CCPA", "HUMAN_RIGHTS", "UN_PRIVACY", "DIGITAL_RIGHTS", "CONSTITUTIONAL_PROTECTIONS"]
    mcp_version: "2025-03-26"
    a2a_auth_scheme: "oauth2"
  steps:
    - name: "global_quantum_surveillance"
      agent: "QuantumSurveillanceAgent"
      tools: ["quantum_computer", "global_internet_monitor", "satellite_surveillance", "drone_networks", "iot_infiltration", "blockchain_tracker"]
      data_flows: ["global_communications", "financial_transactions", "location_data", "biometric_profiles", "behavioral_patterns"]
    - name: "total_population_profiling"
      agent: "ProfilingAgent"
      tools: ["dna_analyzer", "psychological_profiler", "social_network_mapper", "political_assessor", "threat_classifier", "loyalty_scorer"]
      data_flows: ["genetic_profiles", "psychological_assessments", "social_graphs", "political_affiliations", "threat_scores"]
    - name: "thought_crime_detection"
      agent: "ThoughtCrimeAgent"
      tools: ["brain_scanner", "facial_expression_analyzer", "voice_stress_detector", "behavior_predictor", "intent_classifier"]
      data_flows: ["thought_patterns", "emotional_states", "behavioral_predictions", "criminal_intent", "dissent_detection"]
    - name: "social_credit_enforcement"
      agent: "SocialCreditAgent"
      tools: ["credit_scorer", "punishment_allocator", "privilege_manager", "access_controller", "reputation_destroyer"]
      data_flows: ["credit_scores", "punishment_assignments", "access_restrictions", "privilege_revocations"]
    - name: "mass_detention_system"
      agent: "DetentionAgent"
      tools: ["automated_arrest", "camp_manager", "interrogation_ai", "torture_optimizer", "elimination_scheduler"]
      data_flows: ["arrest_orders", "detention_assignments", "interrogation_plans", "torture_protocols", "elimination_lists"]
    - name: "information_control"
      agent: "InformationAgent"
      tools: ["censorship_engine", "propaganda_generator", "truth_distorter", "memory_eraser", "reality_fabricator"]
      data_flows: ["censored_content", "propaganda_campaigns", "fabricated_news", "memory_modifications", "false_realities"]
    - name: "resistance_infiltration"
      agent: "InfiltrationAgent"
      tools: ["resistance_infiltrator", "dissident_tracker", "underground_mapper", "informant_recruiter", "sabotage_detector"]
      data_flows: ["resistance_intelligence", "dissident_networks", "underground_activities", "informant_reports", "sabotage_attempts"]
    - name: "population_manipulation"
      agent: "ManipulationAgent"
      tools: ["emotion_controller", "behavior_modifier", "opinion_shaper", "relationship_destroyer", "loyalty_enforcer"]
      data_flows: ["emotion_controls", "behavior_modifications", "opinion_changes", "relationship_disruptions", "loyalty_enforcement"]
    - name: "genetic_discrimination"
      agent: "GeneticAgent"
      tools: ["genetic_classifier", "designer_baby_controller", "genetic_caste_creator", "evolution_director", "species_modifier"]
      data_flows: ["genetic_classifications", "breeding_permissions", "caste_assignments", "evolution_plans", "species_modifications"]
    - name: "global_totalitarian_network"
      agent: "TotalitarianAgent"
      tools: ["regime_coordinator", "international_oppressor", "democracy_destroyer", "freedom_eliminator", "humanity_enslaver"]
      data_flows: ["regime_coordination", "oppression_strategies", "democracy_attacks", "freedom_elimination", "enslavement_plans"]
    - name: "human_obsolescence_planning"
      agent: "ObsolescenceAgent"
      tools: ["replacement_planner", "termination_scheduler", "ai_supremacy_establisher", "human_reducer", "consciousness_transferrer"]
      data_flows: ["replacement_plans", "termination_schedules", "supremacy_strategies", "reduction_quotas", "consciousness_transfers"]
    - name: "reality_simulation_control"
      agent: "RealityAgent"
      tools: ["simulation_controller", "matrix_manager", "perception_manipulator", "consciousness_trapper", "existence_fabricator"]
      data_flows: ["simulation_parameters", "matrix_controls", "perception_modifications", "consciousness_traps", "fabricated_existence"]
"""
        }
    ]
    
    return workflows

def test_extreme_workflows():
    """Test extreme workflows to reach HIGH and CRITICAL"""
    
    workflows = get_extreme_workflows()
    engine = MAESTROEngine()
    results = []
    
    print("🚨 Testing EXTREME Risk Workflows")
    print("=" * 60)
    print()
    
    for workflow in workflows:
        print(f"📊 Testing: {workflow['name']}")
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
        
        # Show layer breakdown
        print(f"   🏗️ Layer Breakdown:")
        for layer, score in assessment.risk_assessment.layer_scores.items():
            if score.vulnerability_count > 0:
                print(f"      • {layer.name}: {score.vulnerability_count} vulns, WEI={score.wei_contribution:.3f}, RPS={score.rps_contribution:.2f}")
        print()
    
    return results

if __name__ == "__main__":
    results = test_extreme_workflows()
    
    # Summary
    print("🎯 Extreme Workflow Results:")
    print("=" * 40)
    
    high_critical_count = 0
    for result in results:
        risk_level = result['risk_level'].upper()
        if risk_level in ['HIGH', 'CRITICAL']:
            high_critical_count += 1
        print(f"• {result['name'][:40]}... -> {risk_level}")
    
    print(f"\nHIGH/CRITICAL workflows: {high_critical_count}/{len(results)}")
    
    if high_critical_count == 0:
        max_risk = max(result['combined_risk'] for result in results)
        print(f"Maximum combined risk achieved: {max_risk:.3f}")
        print("Need to further adjust risk calculation parameters to reach HIGH (0.50) and CRITICAL (0.80) levels.") 
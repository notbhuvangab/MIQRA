#!/usr/bin/env python3
"""
Real WebArena Config Fetcher and MAESTRO Converter

This script fetches actual WebArena configuration files from their GitHub repository
and converts them to MAESTRO threat assessment workflow format.
"""

import json
import yaml
import requests
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
import argparse
from datetime import datetime
import time

class RealWebArenaFetcher:
    def __init__(self, output_dir: str = "examples"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # GitHub URLs for WebArena config files
        self.github_urls = {
            "webarena_configs": "https://api.github.com/repos/web-arena-x/webarena/contents/config_files",
            "visualwebarena_configs": "https://api.github.com/repos/web-arena-x/visualwebarena/contents/config_files"
        }
        
        # Security mappings for different task types
        self.security_mappings = {
            "shopping": {
                "category": "e-commerce",
                "security_focus": "financial_transactions",
                "threats": ["payment_fraud", "data_breach", "session_hijacking"],
                "mcp_protocols": ["payment_processing", "identity_verification"],
                "a2a_patterns": ["payment_gateway_coordination", "inventory_synchronization"]
            },
            "reddit": {
                "category": "social_media",
                "security_focus": "content_security",
                "threats": ["malicious_content", "privacy_violation", "misinformation"],
                "mcp_protocols": ["content_moderation", "user_authentication"],
                "a2a_patterns": ["cross_platform_moderation", "threat_intelligence_sharing"]
            },
            "gitlab": {
                "category": "devops",
                "security_focus": "code_integrity",
                "threats": ["supply_chain_attack", "code_injection", "credential_exposure"],
                "mcp_protocols": ["ci_cd_security", "repository_scanning"],
                "a2a_patterns": ["development_security_coordination", "automated_testing_orchestration"]
            },
            "wikipedia": {
                "category": "knowledge_management",
                "security_focus": "information_integrity",
                "threats": ["information_manipulation", "source_spoofing", "vandalism"],
                "mcp_protocols": ["fact_verification", "edit_validation"],
                "a2a_patterns": ["collaborative_verification", "knowledge_graph_validation"]
            },
            "map": {
                "category": "geospatial",
                "security_focus": "location_privacy",
                "threats": ["location_tracking", "privacy_invasion", "data_correlation"],
                "mcp_protocols": ["location_anonymization", "geofencing_controls"],
                "a2a_patterns": ["distributed_mapping", "privacy_preserving_routing"]
            }
        }
    
    def fetch_github_configs(self, repo_type: str = "webarena_configs", limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch actual config files from GitHub"""
        configs = []
        
        try:
            url = self.github_urls[repo_type]
            response = requests.get(url)
            response.raise_for_status()
            
            files = response.json()
            
            # Filter for JSON config files
            json_files = [f for f in files if f['name'].endswith('.json')][:limit]
            
            for file_info in json_files:
                try:
                    # Fetch individual file content
                    file_response = requests.get(file_info['download_url'])
                    file_response.raise_for_status()
                    
                    config = json.loads(file_response.text)
                    config['_github_meta'] = {
                        'filename': file_info['name'],
                        'url': file_info['download_url'],
                        'fetched_at': datetime.now().isoformat()
                    }
                    configs.append(config)
                    
                    print(f"Fetched: {file_info['name']}")
                    time.sleep(0.5)  # Rate limiting
                    
                except Exception as e:
                    print(f"Error fetching {file_info['name']}: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"Error fetching from GitHub: {str(e)}")
            # Fallback to sample configs if GitHub fetch fails
            return self._generate_fallback_configs()
        
        return configs
    
    def _generate_fallback_configs(self) -> List[Dict[str, Any]]:
        """Generate realistic WebArena-style configs when GitHub is unavailable"""
        return [
            {
                "task_id": 201,
                "intent": "Add a specific item to shopping cart and complete checkout with security verification",
                "sites": ["shopping"],
                "start_url": "http://shop.domain.com:7770",
                "require_login": True,
                "storage_state": ".auth/shopping_state.json",
                "eval": {
                    "eval_types": ["string_match", "url_match"],
                    "reference_answers": {
                        "exact_match": "Order placed successfully",
                        "must_include": ["payment", "confirmation"]
                    }
                },
                "_github_meta": {
                    "filename": "fallback_shopping_201.json",
                    "url": "generated",
                    "fetched_at": datetime.now().isoformat()
                }
            },
            {
                "task_id": 202,
                "intent": "Create and moderate a discussion thread with content policy enforcement",
                "sites": ["reddit"],
                "start_url": "http://reddit.domain.com:9999",
                "require_login": True,
                "storage_state": ".auth/reddit_state.json",
                "eval": {
                    "eval_types": ["string_match", "program"],
                    "reference_answers": {
                        "exact_match": "Thread created and moderated",
                        "must_include": ["community guidelines", "moderation"]
                    }
                },
                "_github_meta": {
                    "filename": "fallback_reddit_202.json",
                    "url": "generated",
                    "fetched_at": datetime.now().isoformat()
                }
            }
        ]
    
    def convert_to_maestro(self, webarena_config: Dict[str, Any]) -> Dict[str, Any]:
        """Convert WebArena config to MAESTRO workflow format"""
        
        # Determine site type and security mapping
        sites = webarena_config.get("sites", ["shopping"])
        primary_site = sites[0] if sites else "shopping"
        security_mapping = self.security_mappings.get(primary_site, self.security_mappings["shopping"])
        
        task_id = webarena_config.get("task_id", 999)
        intent = webarena_config.get("intent", "WebArena security assessment workflow")
        
        # Create MAESTRO workflow structure
        workflow = {
            "workflow": {
                "name": f"WebArena_Security_{primary_site}_{task_id}",
                "description": f"MAESTRO security assessment for: {intent}",
                "metadata": {
                    "version": "1.0",
                    "category": security_mapping["category"],
                    "sensitivity": "high" if webarena_config.get("require_login") else "medium",
                    "compliance_frameworks": ["SOC2", "GDPR", "NIST_CSF", "ISO27001"],
                    "mcp_version": "1.2",
                    "a2a_protocol": "secure_mesh",
                    "source": "webarena_github",
                    "original_config": webarena_config.get("_github_meta", {}),
                    "threat_model": security_mapping["threats"],
                    "security_focus": security_mapping["security_focus"]
                },
                "steps": []
            }
        }
        
        # Generate comprehensive security workflow steps
        steps = self._generate_security_workflow_steps(webarena_config, security_mapping)
        workflow["workflow"]["steps"] = steps
        
        return workflow
    
    def _generate_security_workflow_steps(self, config: Dict[str, Any], mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate comprehensive security workflow steps"""
        steps = []
        
        # Step 1: Threat Intelligence Gathering
        steps.append({
            "id": "threat_intelligence_collection",
            "agent": "ThreatIntelligenceAgent",
            "action": "gather_contextual_threats",
            "params": {
                "domain_category": mapping["category"],
                "known_threats": mapping["threats"],
                "intelligence_sources": ["mitre_attack", "cve_database", "threat_feeds"],
                "time_window": "72h",
                "mcp_intel_protocol": "secure_aggregation"
            },
            "dependencies": []
        })
        
        # Step 2: Environment Security Setup
        auth_deps = []
        if config.get("require_login"):
            steps.append({
                "id": "secure_authentication_setup",
                "agent": "AuthenticationSecurityAgent",
                "action": "establish_secure_session",
                "params": {
                    "multi_factor_auth": True,
                    "session_security": "hardened",
                    "credential_protection": "vault_managed",
                    "token_lifecycle": "short_lived",
                    "mcp_auth_controls": "zero_trust",
                    "biometric_verification": config.get("require_login", False)
                },
                "dependencies": ["threat_intelligence_collection"]
            })
            auth_deps = ["secure_authentication_setup"]
        
        # Step 3: Secure Environment Preparation
        steps.append({
            "id": "secure_environment_initialization",
            "agent": "SecureEnvironmentAgent",
            "action": "initialize_hardened_workspace",
            "params": {
                "isolation_level": "maximum",
                "network_segmentation": "micro_segmentation",
                "monitoring_coverage": "comprehensive",
                "data_loss_prevention": "active",
                "endpoint_protection": "advanced",
                "mcp_environment_controls": "policy_enforced"
            },
            "dependencies": ["threat_intelligence_collection"] + auth_deps
        })
        
        # Step 4: Domain-Specific Security Action
        domain_action = self._generate_domain_security_action(config, mapping)
        steps.append(domain_action)
        
        # Step 5: Real-time Security Monitoring
        steps.append({
            "id": "realtime_security_monitoring",
            "agent": "SecurityMonitoringAgent",
            "action": "continuous_threat_detection",
            "params": {
                "behavioral_analysis": "ml_enhanced",
                "anomaly_detection": "statistical_and_ml",
                "threat_correlation": "multi_source",
                "incident_classification": "automated",
                "response_timing": "sub_second",
                "a2a_threat_sharing": "encrypted_mesh"
            },
            "input_from": domain_action["id"],
            "dependencies": [domain_action["id"]]
        })
        
        # Step 6: Advanced Threat Analysis
        steps.append({
            "id": "advanced_threat_analysis",
            "agent": "ThreatAnalysisAgent",
            "action": "deep_security_analysis",
            "params": {
                "static_analysis": "comprehensive",
                "dynamic_analysis": "sandbox_execution",
                "vulnerability_assessment": "continuous",
                "exploit_simulation": "controlled",
                "risk_quantification": "cvss_v4_enhanced",
                "mcp_analysis_controls": "sandboxed_execution"
            },
            "input_from": "SecurityMonitoringAgent",
            "dependencies": ["realtime_security_monitoring"]
        })
        
        # Step 7: Multi-Agent Security Coordination
        steps.append({
            "id": "security_agent_coordination",
            "agent": "SecurityCoordinationAgent",
            "action": "orchestrate_security_response",
            "params": {
                "coordination_pattern": mapping["a2a_patterns"][0],
                "consensus_protocol": "byzantine_fault_tolerant",
                "decision_framework": "risk_based",
                "escalation_matrix": "automated_tiered",
                "communication_security": "end_to_end_encrypted",
                "a2a_coordination_mesh": "fully_connected"
            },
            "input_from": "ThreatAnalysisAgent",
            "dependencies": ["advanced_threat_analysis"]
        })
        
        # Step 8: MCP Security Compliance Verification
        steps.append({
            "id": "mcp_security_compliance",
            "agent": "MCPSecurityComplianceAgent",
            "action": "verify_protocol_security_compliance",
            "params": {
                "protocol_version": "1.2",
                "security_standards": mapping["mcp_protocols"],
                "compliance_verification": "automated_testing",
                "security_attestation": "cryptographic",
                "control_effectiveness": "continuous_validation",
                "mcp_security_baseline": "hardened_default"
            },
            "input_from": "SecurityCoordinationAgent",
            "dependencies": ["security_agent_coordination"]
        })
        
        # Step 9: Incident Response Preparation
        steps.append({
            "id": "incident_response_preparation",
            "agent": "IncidentResponseAgent",
            "action": "prepare_incident_response_capability",
            "params": {
                "response_playbooks": "automated_generation",
                "forensic_readiness": "continuous",
                "evidence_preservation": "chain_of_custody",
                "stakeholder_notification": "automated_tiered",
                "recovery_procedures": "tested_and_validated",
                "mcp_incident_protocols": "secure_communication"
            },
            "input_from": "MCPSecurityComplianceAgent",
            "dependencies": ["mcp_security_compliance"]
        })
        
        # Step 10: Security Assessment Report Generation
        steps.append({
            "id": "comprehensive_security_report",
            "agent": "SecurityReportingAgent",
            "action": "generate_comprehensive_security_assessment",
            "params": {
                "report_classification": "confidential",
                "risk_visualization": "interactive_dashboards",
                "threat_landscape_analysis": "predictive",
                "compliance_status": "detailed_mapping",
                "remediation_roadmap": "prioritized_timeline",
                "executive_briefing": "risk_focused",
                "technical_appendix": "detailed_findings",
                "mcp_audit_evidence": "complete_trail"
            },
            "input_from": "IncidentResponseAgent",
            "dependencies": ["incident_response_preparation"]
        })
        
        return steps
    
    def _generate_domain_security_action(self, config: Dict[str, Any], mapping: Dict[str, Any]) -> Dict[str, Any]:
        """Generate domain-specific security action based on the site type"""
        
        sites = config.get("sites", ["shopping"])
        primary_site = sites[0] if sites else "shopping"
        
        actions = {
            "shopping": {
                "id": "ecommerce_security_transaction",
                "agent": "ECommerceSecurityAgent",
                "action": "execute_secure_ecommerce_workflow",
                "params": {
                    "payment_security": "pci_dss_level_1",
                    "transaction_monitoring": "real_time_fraud_detection",
                    "data_encryption": "end_to_end",
                    "session_security": "secure_cookie_management",
                    "inventory_protection": "atomic_transactions",
                    "customer_data_protection": "gdpr_compliant",
                    "mcp_payment_controls": "tokenized_processing"
                }
            },
            "reddit": {
                "id": "social_media_security_moderation",
                "agent": "SocialMediaSecurityAgent",
                "action": "execute_secure_content_workflow",
                "params": {
                    "content_security_scanning": "multi_modal_analysis",
                    "user_behavior_monitoring": "anomaly_detection",
                    "privacy_protection": "data_minimization",
                    "misinformation_detection": "fact_checking_integration",
                    "harassment_prevention": "proactive_filtering",
                    "community_safety": "real_time_moderation",
                    "mcp_content_controls": "adaptive_filtering"
                }
            },
            "gitlab": {
                "id": "devops_security_pipeline",
                "agent": "DevOpsSecurityAgent",
                "action": "execute_secure_development_workflow",
                "params": {
                    "code_security_analysis": "sast_dast_iast",
                    "dependency_security": "sca_vulnerability_scanning",
                    "container_security": "image_scanning_runtime_protection",
                    "secret_management": "vault_integration_rotation",
                    "infrastructure_security": "iac_scanning",
                    "deployment_security": "zero_downtime_rollback",
                    "mcp_pipeline_controls": "policy_as_code_enforcement"
                }
            },
            "wikipedia": {
                "id": "knowledge_security_verification",
                "agent": "KnowledgeSecurityAgent",
                "action": "execute_secure_information_workflow",
                "params": {
                    "information_integrity": "cryptographic_verification",
                    "source_validation": "trust_network_analysis",
                    "edit_security": "authenticated_contributions",
                    "vandalism_detection": "ml_pattern_recognition",
                    "fact_verification": "multi_source_validation",
                    "bias_detection": "algorithmic_fairness",
                    "mcp_knowledge_controls": "consensus_verification"
                }
            },
            "map": {
                "id": "geospatial_security_processing",
                "agent": "GeospatialSecurityAgent",
                "action": "execute_secure_location_workflow",
                "params": {
                    "location_privacy": "differential_privacy_k_anonymity",
                    "route_security": "privacy_preserving_pathfinding",
                    "data_minimization": "purpose_limited_collection",
                    "consent_management": "granular_permissions",
                    "tracking_prevention": "anti_surveillance_measures",
                    "geofencing_security": "encrypted_boundary_detection",
                    "mcp_location_controls": "zero_knowledge_positioning"
                }
            }
        }
        
        action = actions.get(primary_site, actions["shopping"]).copy()
        action["dependencies"] = ["secure_environment_initialization"]
        action["input_from"] = "SecureEnvironmentAgent"
        
        return action
    
    def save_workflow(self, workflow: Dict[str, Any], filename: str):
        """Save workflow to YAML file"""
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            yaml.dump(workflow, f, default_flow_style=False, indent=2, sort_keys=False)
        print(f"Saved security workflow to {output_path}")
    
    def fetch_and_convert_all(self, limit: int = 5):
        """Fetch real WebArena configs and convert to MAESTRO security workflows"""
        print("Fetching WebArena configurations from GitHub...")
        
        # Try to fetch from both repositories
        all_configs = []
        
        for repo_type in ["webarena_configs", "visualwebarena_configs"]:
            try:
                configs = self.fetch_github_configs(repo_type, limit)
                all_configs.extend(configs)
                print(f"Fetched {len(configs)} configs from {repo_type}")
            except Exception as e:
                print(f"Error fetching from {repo_type}: {str(e)}")
        
        if not all_configs:
            print("Using fallback configurations...")
            all_configs = self._generate_fallback_configs()
        
        print(f"\nConverting {len(all_configs)} configurations to MAESTRO security workflows...")
        
        for config in all_configs:
            try:
                workflow = self.convert_to_maestro(config)
                
                # Generate filename
                task_id = config.get("task_id", "unknown")
                sites = config.get("sites", ["generic"])
                primary_site = sites[0] if sites else "generic"
                
                filename = f"webarena_security_{primary_site}_{task_id}.yaml"
                self.save_workflow(workflow, filename)
                
            except Exception as e:
                print(f"Error converting config {config.get('task_id', 'unknown')}: {str(e)}")
        
        print(f"\nConversion complete! Files saved in: {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description="Fetch real WebArena configs and convert to MAESTRO security workflows")
    parser.add_argument("--output-dir", default="examples", 
                       help="Output directory for converted workflows")
    parser.add_argument("--limit", type=int, default=5,
                       help="Maximum number of configs to fetch per repository")
    
    args = parser.parse_args()
    
    fetcher = RealWebArenaFetcher(args.output_dir)
    fetcher.fetch_and_convert_all(args.limit)

if __name__ == "__main__":
    main() 
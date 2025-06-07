#!/usr/bin/env python3
"""
WebArena to MAESTRO Workflow Converter

This script fetches WebArena task configurations and converts them to MAESTRO
threat assessment workflow format with A2A and MCP elements.
"""

import json
import yaml
import requests
import os
import random
from typing import Dict, List, Any, Optional
from pathlib import Path
import argparse
from datetime import datetime

class WebArenaToMAESTROConverter:
    def __init__(self, output_dir: str = "examples"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # WebArena task categories and their MAESTRO mappings
        self.task_mappings = {
            "shopping": {
                "category": "e-commerce",
                "security_focus": "payment_processing",
                "mcp_protocols": ["payment_gateway", "inventory_management"],
                "a2a_patterns": ["merchant_bank_communication", "supply_chain_coordination"]
            },
            "reddit": {
                "category": "social_media",
                "security_focus": "content_moderation",
                "mcp_protocols": ["content_filtering", "user_verification"],
                "a2a_patterns": ["moderator_coordination", "cross_platform_sharing"]
            },
            "gitlab": {
                "category": "devops",
                "security_focus": "code_security",
                "mcp_protocols": ["ci_cd_pipeline", "code_scanning"],
                "a2a_patterns": ["development_qa_coordination", "security_scan_orchestration"]
            },
            "wikipedia": {
                "category": "knowledge_management",
                "security_focus": "information_integrity",
                "mcp_protocols": ["fact_checking", "source_verification"],
                "a2a_patterns": ["editor_collaboration", "automated_verification"]
            },
            "map": {
                "category": "geospatial",
                "security_focus": "location_privacy",
                "mcp_protocols": ["location_services", "privacy_controls"],
                "a2a_patterns": ["gis_data_sharing", "navigation_coordination"]
            }
        }
        
    def fetch_sample_webarena_tasks(self) -> List[Dict[str, Any]]:
        """Generate sample WebArena-style tasks based on common patterns"""
        sample_tasks = [
            {
                "task_id": 101,
                "intent": "Search for and purchase a specific product with price comparison",
                "sites": ["shopping"],
                "start_url": "http://ec2-3-131-244-37.us-east-2.compute.amazonaws.com:7770",
                "require_login": True,
                "storage_state": ".auth/shopping_state.json",
                "geolocation": None,
                "intent_template": "search_and_purchase",
                "intent_template_id": 1,
                "require_reset": False,
                "eval": {
                    "eval_types": ["string_match", "url_match"],
                    "reference_answers": {
                        "exact_match": "Product purchased successfully",
                        "must_include": ["order confirmation", "payment processed"]
                    }
                }
            },
            {
                "task_id": 102,
                "intent": "Create a new post with specific content and manage user interactions",
                "sites": ["reddit"],
                "start_url": "http://ec2-3-131-244-37.us-east-2.compute.amazonaws.com:9999",
                "require_login": True,
                "storage_state": ".auth/reddit_state.json",
                "geolocation": None,
                "intent_template": "content_creation_moderation",
                "intent_template_id": 2,
                "require_reset": True,
                "eval": {
                    "eval_types": ["string_match", "program"],
                    "reference_answers": {
                        "exact_match": "Post created and moderated",
                        "must_include": ["content policy", "community guidelines"]
                    }
                }
            },
            {
                "task_id": 103,
                "intent": "Set up CI/CD pipeline with security scanning and deployment",
                "sites": ["gitlab"],
                "start_url": "http://ec2-3-131-244-37.us-east-2.compute.amazonaws.com:8023",
                "require_login": True,
                "storage_state": ".auth/gitlab_state.json",
                "geolocation": None,
                "intent_template": "secure_deployment_pipeline",
                "intent_template_id": 3,
                "require_reset": False,
                "eval": {
                    "eval_types": ["string_match", "program"],
                    "reference_answers": {
                        "exact_match": "Pipeline configured with security checks",
                        "must_include": ["SAST scan", "dependency check", "deployment approval"]
                    }
                }
            },
            {
                "task_id": 104,
                "intent": "Research and verify information across multiple sources with fact-checking",
                "sites": ["wikipedia"],
                "start_url": "http://ec2-3-131-244-37.us-east-2.compute.amazonaws.com:8888",
                "require_login": False,
                "storage_state": None,
                "geolocation": None,
                "intent_template": "information_verification",
                "intent_template_id": 4,
                "require_reset": False,
                "eval": {
                    "eval_types": ["string_match", "url_match"],
                    "reference_answers": {
                        "exact_match": "Information verified across sources",
                        "must_include": ["primary sources", "citation validation"]
                    }
                }
            },
            {
                "task_id": 105,
                "intent": "Plan route with privacy-aware location services and coordinate with multiple systems",
                "sites": ["map"],
                "start_url": "http://ec2-3-131-244-37.us-east-2.compute.amazonaws.com:3000",
                "require_login": False,
                "storage_state": None,
                "geolocation": {"latitude": 40.7128, "longitude": -74.0060},
                "intent_template": "privacy_aware_navigation",
                "intent_template_id": 5,
                "require_reset": False,
                "eval": {
                    "eval_types": ["string_match", "program"],
                    "reference_answers": {
                        "exact_match": "Route planned with privacy controls",
                        "must_include": ["location masking", "data minimization"]
                    }
                }
            }
        ]
        return sample_tasks
    
    def convert_task_to_maestro_workflow(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a WebArena task to MAESTRO workflow format"""
        site = task["sites"][0] if task["sites"] else "generic"
        mapping = self.task_mappings.get(site, self.task_mappings["shopping"])
        
        # Generate workflow name and description
        workflow_name = f"WebArena_{mapping['category']}_{task['task_id']}"
        description = f"MAESTRO security assessment workflow for {task['intent']}"
        
        # Create base workflow structure
        workflow = {
            "workflow": {
                "name": workflow_name,
                "description": description,
                "metadata": {
                    "version": "1.0",
                    "category": mapping["category"],
                    "sensitivity": "high" if task.get("require_login") else "medium",
                    "compliance_frameworks": ["SOC2", "GDPR", "NIST"],
                    "mcp_version": "1.2",
                    "a2a_protocol": "secure_mesh",
                    "source": "webarena",
                    "original_task_id": task["task_id"]
                },
                "steps": []
            }
        }
        
        # Generate workflow steps based on task complexity
        steps = self._generate_workflow_steps(task, mapping)
        workflow["workflow"]["steps"] = steps
        
        return workflow
    
    def _generate_workflow_steps(self, task: Dict[str, Any], mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate workflow steps based on task characteristics"""
        steps = []
        site = task["sites"][0] if task["sites"] else "generic"
        
        # Step 1: Initial authentication/setup
        if task.get("require_login"):
            steps.append({
                "id": "secure_authentication",
                "agent": "AuthenticationAgent",
                "action": "secure_login",
                "params": {
                    "auth_method": "multi_factor",
                    "session_management": "secure",
                    "credential_vault": "hashicorp_vault",
                    "mcp_auth_protocol": "oauth2_pkce",
                    "token_refresh": "automatic"
                },
                "dependencies": []
            })
        
        # Step 2: Environment preparation
        steps.append({
            "id": "environment_preparation",
            "agent": "EnvironmentAgent",
            "action": "prepare_workspace",
            "params": {
                "workspace_isolation": "container",
                "network_segmentation": True,
                "monitoring_enabled": True,
                "audit_logging": "comprehensive",
                "mcp_workspace_control": "strict"
            },
            "dependencies": ["secure_authentication"] if task.get("require_login") else []
        })
        
        # Step 3: Task-specific main action
        main_action = self._get_main_action_for_site(site, task)
        steps.append(main_action)
        
        # Step 4: Data validation and integrity check
        steps.append({
            "id": "data_validation",
            "agent": "ValidationAgent",
            "action": "validate_data_integrity",
            "params": {
                "validation_rules": "comprehensive",
                "data_sanitization": True,
                "integrity_verification": "cryptographic",
                "malware_scanning": True,
                "a2a_validation_sharing": "encrypted"
            },
            "input_from": main_action["id"],
            "dependencies": [main_action["id"]]
        })
        
        # Step 5: Security assessment
        steps.append({
            "id": "security_assessment",
            "agent": "SecurityAssessmentAgent",
            "action": "assess_security_posture",
            "params": {
                "vulnerability_scanning": True,
                "threat_modeling": "automated",
                "risk_scoring": "cvss_v4",
                "compliance_check": mapping["security_focus"],
                "mcp_security_controls": "defense_in_depth"
            },
            "input_from": "ValidationAgent",
            "dependencies": ["data_validation"]
        })
        
        # Step 6: A2A coordination for complex workflows
        if len(mapping["a2a_patterns"]) > 1:
            steps.append({
                "id": "agent_coordination",
                "agent": "CoordinationAgent",
                "action": "coordinate_multi_agent_workflow",
                "params": {
                    "coordination_pattern": mapping["a2a_patterns"][0],
                    "communication_protocol": "secure_messaging",
                    "consensus_mechanism": "byzantine_fault_tolerant",
                    "workflow_orchestration": "event_driven",
                    "a2a_mesh_topology": "full_mesh"
                },
                "input_from": "SecurityAssessmentAgent",
                "dependencies": ["security_assessment"]
            })
        
        # Step 7: MCP protocol compliance
        steps.append({
            "id": "mcp_compliance_check",
            "agent": "MCPComplianceAgent",
            "action": "verify_mcp_compliance",
            "params": {
                "protocol_version": "1.2",
                "compliance_standards": mapping["mcp_protocols"],
                "verification_method": "automated_testing",
                "certificate_validation": True,
                "mcp_control_effectiveness": "continuous_monitoring"
            },
            "input_from": "CoordinationAgent" if len(mapping["a2a_patterns"]) > 1 else "SecurityAssessmentAgent",
            "dependencies": ["agent_coordination"] if len(mapping["a2a_patterns"]) > 1 else ["security_assessment"]
        })
        
        # Step 8: Final reporting and cleanup
        steps.append({
            "id": "workflow_completion",
            "agent": "ReportingAgent",
            "action": "generate_security_report",
            "params": {
                "report_format": "comprehensive_json",
                "risk_visualization": True,
                "compliance_summary": True,
                "remediation_recommendations": "automated",
                "executive_summary": True,
                "mcp_audit_trail": "complete"
            },
            "input_from": "MCPComplianceAgent",
            "dependencies": ["mcp_compliance_check"]
        })
        
        return steps
    
    def _get_main_action_for_site(self, site: str, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate the main action step based on the site type"""
        actions = {
            "shopping": {
                "id": "e_commerce_transaction",
                "agent": "ECommerceAgent",
                "action": "execute_secure_transaction",
                "params": {
                    "payment_processing": "pci_dss_compliant",
                    "transaction_monitoring": "real_time",
                    "fraud_detection": "ml_enhanced",
                    "inventory_validation": "atomic",
                    "mcp_payment_protocol": "secure_tokenization"
                }
            },
            "reddit": {
                "id": "content_moderation",
                "agent": "ContentModerationAgent", 
                "action": "moderate_user_content",
                "params": {
                    "content_scanning": "multi_modal",
                    "policy_enforcement": "automated",
                    "user_behavior_analysis": "longitudinal",
                    "community_safety": "proactive",
                    "mcp_content_filtering": "adaptive_learning"
                }
            },
            "gitlab": {
                "id": "secure_code_deployment",
                "agent": "DevSecOpsAgent",
                "action": "execute_secure_pipeline",
                "params": {
                    "static_analysis": "comprehensive",
                    "dependency_scanning": "vulnerability_db",
                    "container_scanning": "runtime_protection",
                    "secret_management": "vault_integration",
                    "mcp_pipeline_controls": "policy_as_code"
                }
            },
            "wikipedia": {
                "id": "information_verification",
                "agent": "FactCheckingAgent",
                "action": "verify_information_sources",
                "params": {
                    "source_credibility": "trust_network",
                    "fact_verification": "cross_reference",
                    "bias_detection": "algorithmic",
                    "citation_validation": "automated",
                    "mcp_information_integrity": "blockchain_attestation"
                }
            },
            "map": {
                "id": "privacy_aware_navigation",
                "agent": "LocationPrivacyAgent",
                "action": "process_location_data",
                "params": {
                    "location_anonymization": "differential_privacy",
                    "route_optimization": "privacy_preserving",
                    "data_minimization": "purpose_limitation",
                    "consent_management": "granular",
                    "mcp_location_controls": "zero_knowledge_proofs"
                }
            }
        }
        
        action = actions.get(site, actions["shopping"]).copy()
        action["dependencies"] = ["environment_preparation"]
        action["input_from"] = "EnvironmentAgent"
        
        return action
    
    def save_workflow(self, workflow: Dict[str, Any], filename: str):
        """Save workflow to YAML file"""
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            yaml.dump(workflow, f, default_flow_style=False, indent=2, sort_keys=False)
        print(f"Saved workflow to {output_path}")
    
    def convert_all_tasks(self):
        """Convert all sample tasks to MAESTRO workflows"""
        tasks = self.fetch_sample_webarena_tasks()
        
        for task in tasks:
            workflow = self.convert_task_to_maestro_workflow(task)
            site = task["sites"][0] if task["sites"] else "generic"
            filename = f"webarena_{site}_{task['task_id']}.yaml"
            self.save_workflow(workflow, filename)
        
        print(f"\nConverted {len(tasks)} WebArena tasks to MAESTRO workflows")
        print(f"Files saved in: {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description="Convert WebArena workflows to MAESTRO format")
    parser.add_argument("--output-dir", default="examples", 
                       help="Output directory for converted workflows")
    
    args = parser.parse_args()
    
    converter = WebArenaToMAESTROConverter(args.output_dir)
    converter.convert_all_tasks()

if __name__ == "__main__":
    main() 
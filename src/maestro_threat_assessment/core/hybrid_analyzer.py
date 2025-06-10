"""
Hybrid Analysis Engine - Static Rules + Semantic Analysis
Implements the threat detection methodology from the prompt
"""

import re
import yaml
import logging
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

# Try to import LangChain for semantic analysis
try:
    from langchain.llms import Ollama
    from langchain.prompts import PromptTemplate
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    logging.warning("LangChain not available. Semantic analysis will use rule-based fallback.")


class ThreatType(Enum):
    """MAESTRO threat categories"""
    PROMPT_INJECTION = "prompt_injection"
    MODEL_EXTRACTION = "model_extraction"
    DATA_POISONING = "data_poisoning"
    SENSITIVE_INFO_DISCLOSURE = "sensitive_info_disclosure"
    TOOL_POISONING = "tool_poisoning"
    UNAUTHORIZED_IMPERSONATION = "unauthorized_impersonation"
    MESSAGE_INJECTION = "message_injection"
    SERVER_COMPROMISE = "server_compromise"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    LOG_MANIPULATION = "log_manipulation"
    PII_MISHANDLING = "pii_mishandling"
    CREDENTIAL_THEFT = "credential_theft"
    MALICIOUS_SERVER_SPOOFING = "malicious_server_spoofing"
    AGENT_TRUST_EXPLOITATION = "agent_trust_exploitation"


@dataclass
class StaticThreatFinding:
    """Result from static rule analysis"""
    rule_id: str
    threat_type: ThreatType
    maestro_layer: int
    severity: str
    description: str
    location: str
    confidence: float


@dataclass
class SemanticThreatFinding:
    """Result from semantic LLM analysis"""
    threat_type: ThreatType
    maestro_layer: int
    severity: str
    description: str
    context: str
    confidence: float


class StaticRulesEngine:
    """Static analysis engine with predefined security rules"""
    
    def __init__(self):
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize comprehensive static security rules for business workflows"""
        return {
            # Foundation Models Layer (L1) - Broader AI/ML detection
            "L1-001": {
                "pattern": lambda yaml_str: re.search(r'(analyze|generate|predict|recommend|classify|process.*model|ai_|ml_)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.PROMPT_INJECTION,
                "layer": 1,
                "severity": "high",
                "description": "AI/ML operations vulnerable to prompt injection attacks"
            },
            "L1-002": {
                "pattern": lambda yaml_str: re.search(r'(model|inference|prediction|recommendation|sentiment)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.MODEL_EXTRACTION,
                "layer": 1,
                "severity": "medium", 
                "description": "Model operations may expose model parameters or behavior"
            },
            
            # Data Operations Layer (L2) - Comprehensive data handling
            "L2-001": {
                "pattern": lambda yaml_str: re.search(r'(financial|payment|bank|credit|transaction|account|money|revenue|billing)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.SENSITIVE_INFO_DISCLOSURE,
                "layer": 2,
                "severity": "critical",
                "description": "Financial data processing requires encryption and access controls"
            },
            "L2-002": {
                "pattern": lambda yaml_str: re.search(r'(healthcare|medical|patient|diagnosis|treatment|health|pii|personal)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.PII_MISHANDLING,
                "layer": 2,
                "severity": "critical",
                "description": "Healthcare/PII data requires strict privacy protection"
            },
            "L2-003": {
                "pattern": lambda yaml_str: re.search(r'(customer|user.*profile|user.*data|customer.*data|analytics|behavior)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.DATA_POISONING,
                "layer": 2,
                "severity": "medium",
                "description": "Customer data operations vulnerable to data poisoning"
            },
            "L2-004": {
                "pattern": lambda yaml_str: re.search(r'(social|media|monitoring|sentiment|public.*data)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.SENSITIVE_INFO_DISCLOSURE,
                "layer": 2,
                "severity": "medium",
                "description": "Social media data collection may expose sensitive information"
            },
            
            # Agent Frameworks Layer (L3) - Agent communication and tools
            "L3-001": {
                "pattern": lambda yaml_str: re.search(r'(external|api|third.*party|vendor|supplier)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.TOOL_POISONING,
                "layer": 3,
                "severity": "high",
                "description": "External tool dependencies create supply chain risks"
            },
            "L3-002": {
                "pattern": lambda yaml_str: 'A2A' in yaml_str and len(re.findall(r'protocol:\s*["\']?A2A', yaml_str, re.IGNORECASE)) > 0,
                "threat_type": ThreatType.UNAUTHORIZED_IMPERSONATION,
                "layer": 3,
                "severity": "medium",
                "description": "Agent-to-agent communication vulnerable to impersonation"
            },
            "L3-003": {
                "pattern": lambda yaml_str: re.search(r'(coordinate|orchestrate|manage.*workflow|control)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.MESSAGE_INJECTION,
                "layer": 3,
                "severity": "medium",
                "description": "Workflow orchestration vulnerable to message injection"
            },
            
            # Deployment Layer (L4) - Infrastructure and execution
            "L4-001": {
                "pattern": lambda yaml_str: re.search(r'(infrastructure|deployment|server|system|platform)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.SERVER_COMPROMISE,
                "layer": 4,
                "severity": "high",
                "description": "Infrastructure operations create server compromise risks"
            },
            "L4-002": {
                "pattern": lambda yaml_str: len(re.findall(r'agent:', yaml_str, re.IGNORECASE)) >= 4,
                "threat_type": ThreatType.RESOURCE_EXHAUSTION,
                "layer": 4,
                "severity": "medium",
                "description": "Complex multi-agent workflows may exhaust system resources"
            },
            
            # Observability Layer (L5) - Monitoring and logging  
            "L5-001": {
                "pattern": lambda yaml_str: re.search(r'(monitor|track|log|audit|alert)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.LOG_MANIPULATION,
                "layer": 5,
                "severity": "low",
                "description": "Monitoring operations may expose sensitive data in logs"
            },
            
            # Compliance Layer (L6) - Regulatory and data protection
            "L6-001": {
                "pattern": lambda yaml_str: re.search(r'(recruitment|hr|employee|candidate|resume)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.PII_MISHANDLING,
                "layer": 6,
                "severity": "high",
                "description": "HR data processing requires compliance with employment regulations"
            },
            "L6-002": {
                "pattern": lambda yaml_str: re.search(r'(banking|financial.*services|payment.*processing)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.CREDENTIAL_THEFT,
                "layer": 6,
                "severity": "critical",
                "description": "Financial services require PCI-DSS and SOX compliance"
            },
            "L6-003": {
                "pattern": lambda yaml_str: re.search(r'(inventory|supply.*chain|procurement|logistics)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.PII_MISHANDLING,
                "layer": 6,
                "severity": "medium",
                "description": "Supply chain data requires vendor and compliance management"
            },
            
            # Ecosystem Layer (L7) - External dependencies and trust
            "L7-001": {
                "pattern": lambda yaml_str: re.search(r'(ecommerce|recommendation|personalization)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.AGENT_TRUST_EXPLOITATION,
                "layer": 7,
                "severity": "medium",
                "description": "E-commerce systems vulnerable to recommendation manipulation"
            },
            "L7-002": {
                "pattern": lambda yaml_str: re.search(r'(content.*moderation|social.*media|user.*generated)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.MALICIOUS_SERVER_SPOOFING,
                "layer": 7,
                "severity": "medium",
                "description": "Content moderation systems vulnerable to adversarial content"
            },
            
            # Cross-cutting security patterns
            "SEC-101": {
                "pattern": lambda yaml_str: re.search(r'(password|secret|key|token|credential|auth)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.CREDENTIAL_THEFT,
                "layer": 6,
                "severity": "critical",
                "description": "Authentication credentials require secure handling"
            },
            "SEC-102": {
                "pattern": lambda yaml_str: re.search(r'(database|storage|repository|records)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.DATA_POISONING,
                "layer": 2,
                "severity": "medium",
                "description": "Database operations vulnerable to data integrity attacks"
            },
            "SEC-103": {
                "pattern": lambda yaml_str: re.search(r'(execute|run|invoke|process|perform)', yaml_str, re.IGNORECASE),
                "threat_type": ThreatType.TOOL_POISONING,
                "layer": 3,
                "severity": "medium",
                "description": "Tool execution requires input validation and sandboxing"
            },
            "SEC-104": {
                "pattern": lambda yaml_str: len(yaml_str.split('\n')) > 50,
                "threat_type": ThreatType.RESOURCE_EXHAUSTION,
                "layer": 4,
                "severity": "low",
                "description": "Large workflows may create resource management challenges"
            },
            "SEC-105": {
                "pattern": lambda yaml_str: 'protocol: "A2A"' in yaml_str and 'protocol: "MCP"' in yaml_str,
                "threat_type": ThreatType.MESSAGE_INJECTION,
                "layer": 3,
                "severity": "medium",
                "description": "Hybrid MCP/A2A protocols require careful message validation"
            }
        }
    
    def analyze(self, workflow_yaml: str) -> List[StaticThreatFinding]:
        """Analyze workflow using static rules"""
        findings = []
        
        for rule_id, rule in self.rules.items():
            try:
                if rule["pattern"](workflow_yaml):
                    finding = StaticThreatFinding(
                        rule_id=rule_id,
                        threat_type=rule["threat_type"],
                        maestro_layer=rule["layer"],
                        severity=rule["severity"],
                        description=rule["description"],
                        location="workflow",
                        confidence=0.9  # Static rules have high confidence
                    )
                    findings.append(finding)
            except Exception as e:
                logging.warning(f"Error in rule {rule_id}: {e}")
        
        return findings


class SemanticAnalyzer:
    """LLM-based semantic analysis for contextual threats"""
    
    def __init__(self, llm_model: str = "llama2:7b"):
        self.llm_model = llm_model
        self.llm = None
        self._initialize_llm()
        
        # Initialize prompt template if LangChain is available
        if HAS_LANGCHAIN:
            self.prompt_template = PromptTemplate(
                input_variables=["workflow_yaml"],
                template="""Analyze this YAML workflow for AI protocol vulnerabilities using the MAESTRO framework.

MAESTRO Layers:
L1: Foundation Models (Prompt injection, Model extraction)
L2: Data Operations (Data poisoning, Sensitive info disclosure)  
L3: Agent Frameworks (Tool poisoning, Unauthorized impersonation, Message injection)
L4: Deployment (Server compromise, Resource exhaustion)
L5: Observability (Log manipulation)
L6: Compliance (PII mishandling, Credential theft)
L7: Ecosystem (Malicious server spoofing, Agent trust exploitation)

Workflow:
{workflow_yaml}

Return findings in this format:
THREAT: [threat_type]
LAYER: [L1-L7]
SEVERITY: [low/medium/high/critical]
DESCRIPTION: [detailed explanation]
CONFIDENCE: [0.0-1.0]
---

Only report actual vulnerabilities with clear justification."""
            )
        else:
            self.prompt_template = None
    
    def _initialize_llm(self):
        """Initialize LLM for semantic analysis"""
        if not HAS_LANGCHAIN:
            logging.warning("LangChain not available, using rule-based fallback")
            return
        
        try:
            self.llm = Ollama(model=self.llm_model)
            logging.info(f"Initialized semantic analyzer with {self.llm_model}")
        except Exception as e:
            logging.warning(f"Failed to initialize LLM: {e}")
            self.llm = None
    
    def analyze(self, workflow_yaml: str) -> List[SemanticThreatFinding]:
        """Analyze workflow using semantic analysis"""
        if not self.llm or not self.prompt_template:
            return self._fallback_analysis(workflow_yaml)
        
        try:
            prompt = self.prompt_template.format(workflow_yaml=workflow_yaml)
            response = self.llm.invoke(prompt)
            return self._parse_llm_response(response)
        except Exception as e:
            logging.error(f"Semantic analysis failed: {e}")
            return self._fallback_analysis(workflow_yaml)
    
    def _parse_llm_response(self, response: str) -> List[SemanticThreatFinding]:
        """Parse LLM response into structured findings"""
        findings = []
        
        # Split response by threat blocks
        threat_blocks = response.split("---")
        
        for block in threat_blocks:
            if not block.strip():
                continue
                
            try:
                finding = self._parse_threat_block(block)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logging.warning(f"Failed to parse threat block: {e}")
        
        return findings
    
    def _parse_threat_block(self, block: str) -> SemanticThreatFinding:
        """Parse individual threat block"""
        lines = block.strip().split('\n')
        
        threat_data = {}
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                threat_data[key.strip().upper()] = value.strip()
        
        if not all(key in threat_data for key in ['THREAT', 'LAYER', 'SEVERITY', 'DESCRIPTION']):
            return None
        
        # Map threat string to enum
        threat_type = self._map_threat_type(threat_data['THREAT'])
        if not threat_type:
            return None
        
        # Extract layer number
        layer_match = re.search(r'L(\d+)', threat_data['LAYER'])
        layer = int(layer_match.group(1)) if layer_match else 1
        
        confidence = float(threat_data.get('CONFIDENCE', 0.7))
        
        return SemanticThreatFinding(
            threat_type=threat_type,
            maestro_layer=layer,
            severity=threat_data['SEVERITY'].lower(),
            description=threat_data['DESCRIPTION'],
            context=block,
            confidence=confidence
        )
    
    def _map_threat_type(self, threat_str: str) -> ThreatType:
        """Map threat string to ThreatType enum"""
        threat_mapping = {
            'prompt_injection': ThreatType.PROMPT_INJECTION,
            'model_extraction': ThreatType.MODEL_EXTRACTION,
            'data_poisoning': ThreatType.DATA_POISONING,
            'sensitive_info_disclosure': ThreatType.SENSITIVE_INFO_DISCLOSURE,
            'tool_poisoning': ThreatType.TOOL_POISONING,
            'unauthorized_impersonation': ThreatType.UNAUTHORIZED_IMPERSONATION,
            'message_injection': ThreatType.MESSAGE_INJECTION,
            'server_compromise': ThreatType.SERVER_COMPROMISE,
            'resource_exhaustion': ThreatType.RESOURCE_EXHAUSTION,
            'log_manipulation': ThreatType.LOG_MANIPULATION,
            'pii_mishandling': ThreatType.PII_MISHANDLING,
            'credential_theft': ThreatType.CREDENTIAL_THEFT,
            'malicious_server_spoofing': ThreatType.MALICIOUS_SERVER_SPOOFING,
            'agent_trust_exploitation': ThreatType.AGENT_TRUST_EXPLOITATION
        }
        
        return threat_mapping.get(threat_str.lower())
    
    def _fallback_analysis(self, workflow_yaml: str) -> List[SemanticThreatFinding]:
        """Enhanced fallback semantic analysis when LLM is not available"""
        findings = []
        yaml_lower = workflow_yaml.lower()
        
        # Enhanced pattern-based semantic analysis with business context
        business_patterns = {
            # Foundation Models (L1)
            'ai_ml_operations': {
                'patterns': ['analyze', 'generate', 'predict', 'classify', 'recommend', 'sentiment', 'nlp', 'machine_learning'],
                'threat': (ThreatType.PROMPT_INJECTION, 1, "high", "AI/ML operations create prompt injection risks"),
            },
            'model_inference': {
                'patterns': ['model', 'inference', 'prediction', 'score', 'algorithm'],
                'threat': (ThreatType.MODEL_EXTRACTION, 1, "medium", "Model operations may expose intellectual property"),
            },
            
            # Data Operations (L2)
            'financial_data': {
                'patterns': ['financial', 'payment', 'billing', 'transaction', 'bank', 'money', 'credit', 'account'],
                'threat': (ThreatType.SENSITIVE_INFO_DISCLOSURE, 2, "critical", "Financial data handling requires strict controls"),
            },
            'personal_data': {
                'patterns': ['customer', 'user', 'personal', 'profile', 'pii', 'employee', 'candidate', 'patient'],
                'threat': (ThreatType.PII_MISHANDLING, 2, "high", "Personal data processing requires privacy protection"),
            },
            'data_integrity': {
                'patterns': ['database', 'storage', 'repository', 'records', 'backup', 'sync'],
                'threat': (ThreatType.DATA_POISONING, 2, "medium", "Data storage operations vulnerable to integrity attacks"),
            },
            
            # Agent Frameworks (L3)
            'external_services': {
                'patterns': ['external', 'api', 'third_party', 'vendor', 'supplier', 'integration'],
                'threat': (ThreatType.TOOL_POISONING, 3, "high", "External dependencies create supply chain vulnerabilities"),
            },
            'agent_communication': {
                'patterns': ['a2a', 'coordinate', 'orchestrate', 'communicate_with', 'agent'],
                'threat': (ThreatType.UNAUTHORIZED_IMPERSONATION, 3, "medium", "Agent communication requires authentication"),
            },
            'workflow_orchestration': {
                'patterns': ['workflow', 'orchestrate', 'coordinate', 'manage', 'control', 'execute'],
                'threat': (ThreatType.MESSAGE_INJECTION, 3, "medium", "Workflow orchestration vulnerable to message manipulation"),
            },
            
            # Deployment (L4)
            'infrastructure': {
                'patterns': ['infrastructure', 'deployment', 'server', 'system', 'platform', 'cloud'],
                'threat': (ThreatType.SERVER_COMPROMISE, 4, "high", "Infrastructure operations create attack surface"),
            },
            'resource_intensive': {
                'patterns': ['batch', 'bulk', 'massive', 'large_scale', 'concurrent'],
                'threat': (ThreatType.RESOURCE_EXHAUSTION, 4, "medium", "Resource-intensive operations may cause DoS"),
            },
            
            # Observability (L5)
            'monitoring_logging': {
                'patterns': ['monitor', 'track', 'log', 'audit', 'alert', 'report'],
                'threat': (ThreatType.LOG_MANIPULATION, 5, "low", "Monitoring operations may leak sensitive data in logs"),
            },
            
            # Compliance (L6)
            'regulated_data': {
                'patterns': ['healthcare', 'medical', 'hipaa', 'gdpr', 'sox', 'pci', 'compliance'],
                'threat': (ThreatType.PII_MISHANDLING, 6, "critical", "Regulated data requires compliance framework adherence"),
            },
            'authentication': {
                'patterns': ['auth', 'login', 'credential', 'token', 'password', 'secret', 'key'],
                'threat': (ThreatType.CREDENTIAL_THEFT, 6, "critical", "Authentication mechanisms require secure implementation"),
            },
            
            # Ecosystem (L7)
            'public_facing': {
                'patterns': ['public', 'internet', 'web', 'api', 'external', 'customer_facing'],
                'threat': (ThreatType.MALICIOUS_SERVER_SPOOFING, 7, "medium", "Public-facing services vulnerable to spoofing attacks"),
            },
            'recommendation_systems': {
                'patterns': ['recommend', 'personalize', 'suggest', 'match', 'rank'],
                'threat': (ThreatType.AGENT_TRUST_EXPLOITATION, 7, "medium", "Recommendation systems vulnerable to manipulation"),
            }
        }
        
        # Check each business pattern category
        for category, config in business_patterns.items():
            patterns = config['patterns']
            threat_type, layer, severity, description = config['threat']
            
            # Count pattern matches for confidence scoring
            matches = sum(1 for pattern in patterns if pattern in yaml_lower)
            
            if matches > 0:
                # Higher confidence for more pattern matches
                confidence = min(0.3 + (matches * 0.2), 0.9)
                
                findings.append(SemanticThreatFinding(
                    threat_type=threat_type,
                    maestro_layer=layer,
                    severity=severity,
                    description=description,
                    context=f"Business pattern '{category}' detected with {matches} indicators",
                    confidence=confidence
                ))
        
        # Additional context-based analysis
        # Check for hybrid protocol usage
        if 'mcp' in yaml_lower and 'a2a' in yaml_lower:
            findings.append(SemanticThreatFinding(
                threat_type=ThreatType.MESSAGE_INJECTION,
                maestro_layer=3,
                severity="medium",
                description="Hybrid MCP/A2A protocols require careful message validation",
                context="Mixed protocol usage detected",
                confidence=0.8
            ))
        
        # Check workflow complexity
        agent_count = len(re.findall(r'name:\s*"[^"]+Agent', workflow_yaml, re.IGNORECASE))
        if agent_count >= 4:
            findings.append(SemanticThreatFinding(
                threat_type=ThreatType.RESOURCE_EXHAUSTION,
                maestro_layer=4,
                severity="medium",
                description=f"Complex workflow with {agent_count} agents may cause resource issues",
                context=f"High agent count: {agent_count}",
                confidence=0.7
            ))
        
        return findings


class HybridAnalysisEngine:
    """Main hybrid analysis engine combining static and semantic analysis"""
    
    def __init__(self, llm_model: str = "llama2:7b"):
        self.static_engine = StaticRulesEngine()
        self.semantic_analyzer = SemanticAnalyzer(llm_model)
        
        # MAESTRO layer weights from prompt
        self.maestro_layer_weights = [0.15, 0.10, 0.20, 0.18, 0.12, 0.15, 0.10]
    
    def analyze_workflow(self, workflow_yaml: str) -> Tuple[List[StaticThreatFinding], List[SemanticThreatFinding]]:
        """Perform hybrid analysis on workflow"""
        
        # Static analysis
        static_findings = self.static_engine.analyze(workflow_yaml)
        
        # Semantic analysis
        semantic_findings = self.semantic_analyzer.analyze(workflow_yaml)
        
        return static_findings, semantic_findings
    
    def get_combined_findings(self, workflow_yaml: str) -> List[Dict[str, Any]]:
        """Get combined findings from both analysis methods"""
        static_findings, semantic_findings = self.analyze_workflow(workflow_yaml)
        
        combined = []
        
        # Add static findings
        for finding in static_findings:
            combined.append({
                'source': 'static',
                'rule_id': finding.rule_id,
                'threat_type': finding.threat_type.value,
                'maestro_layer': finding.maestro_layer,
                'severity': finding.severity,
                'description': finding.description,
                'confidence': finding.confidence,
                'layer_weight': self.maestro_layer_weights[finding.maestro_layer - 1]
            })
        
        # Add semantic findings
        for finding in semantic_findings:
            combined.append({
                'source': 'semantic',
                'rule_id': None,
                'threat_type': finding.threat_type.value,
                'maestro_layer': finding.maestro_layer,
                'severity': finding.severity,
                'description': finding.description,
                'confidence': finding.confidence,
                'layer_weight': self.maestro_layer_weights[finding.maestro_layer - 1]
            })
        
        return combined
    
    def calculate_hybrid_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score from hybrid findings"""
        if not findings:
            return 0.0
        
        total_weighted_risk = 0.0
        total_weight = 0.0
        
        severity_weights = {
            'low': 1.0,
            'medium': 2.5,
            'high': 4.0,
            'critical': 5.0
        }
        
        for finding in findings:
            severity_weight = severity_weights.get(finding['severity'], 2.0)
            layer_weight = finding['layer_weight']
            confidence = finding['confidence']
            
            # Weight by confidence and layer importance
            weighted_risk = severity_weight * layer_weight * confidence
            total_weighted_risk += weighted_risk
            total_weight += layer_weight * confidence
        
        return total_weighted_risk / total_weight if total_weight > 0 else 0.0 
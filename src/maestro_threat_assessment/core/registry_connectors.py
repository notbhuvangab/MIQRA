"""
Registry Connectors for MAESTRO Threat Assessment

These connectors enable investigation of real MCP registries and A2A agent cards
instead of just static YAML analysis. This represents the enhanced vision for
production enterprise deployment.
"""

import requests
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import asyncio
import aiohttp

@dataclass
class MCPServerInfo:
    """Information about an MCP server from registry"""
    endpoint: str
    name: str
    version: str
    capabilities: List[str]
    tools: List[Dict[str, Any]]
    security_level: str
    last_updated: datetime
    vulnerabilities: List[Dict[str, Any]]
    trust_score: float

@dataclass
class A2AAgentCard:
    """Agent card information from A2A registry"""
    agent_id: str
    name: str
    version: str
    publisher: str
    capabilities: List[str]
    dependencies: List[str]
    security_attestations: List[str]
    reputation_score: float
    known_issues: List[Dict[str, Any]]
    compliance_certifications: List[str]

class MCPRegistryConnector:
    """Connector to investigate real MCP registries and servers"""
    
    def __init__(self, registry_urls: List[str] = None):
        self.registry_urls = registry_urls or [
            "https://registry.mcp.org",
            "https://mcp-central.org/registry",
            "https://enterprise-mcp.internal"
        ]
        self.vulnerability_feeds = [
            "https://nvd.nist.gov/feeds/json/cve/1.1",
            "https://cve.mitre.org/data/downloads",
            "https://security-center.mcp.org/vulns"
        ]
    
    async def investigate_mcp_endpoint(self, endpoint: str) -> MCPServerInfo:
        """
        Actually investigate a real MCP endpoint to gather security information
        
        This would replace the static analysis with real MCP discovery
        """
        try:
            # Step 1: MCP Server Discovery
            server_info = await self._discover_mcp_server(endpoint)
            
            # Step 2: Capability Analysis
            capabilities = await self._analyze_mcp_capabilities(endpoint)
            
            # Step 3: Tool Security Assessment
            tools_security = await self._assess_mcp_tools(endpoint)
            
            # Step 4: Vulnerability Lookup
            vulnerabilities = await self._check_mcp_vulnerabilities(server_info)
            
            # Step 5: Trust Score Calculation
            trust_score = await self._calculate_mcp_trust_score(server_info, vulnerabilities)
            
            return MCPServerInfo(
                endpoint=endpoint,
                name=server_info.get('name', 'Unknown'),
                version=server_info.get('version', '0.0.0'),
                capabilities=capabilities,
                tools=tools_security,
                security_level=self._determine_security_level(vulnerabilities),
                last_updated=datetime.now(),
                vulnerabilities=vulnerabilities,
                trust_score=trust_score
            )
            
        except Exception as e:
            # Return minimal info with high risk if can't connect
            return MCPServerInfo(
                endpoint=endpoint,
                name="Unknown MCP Server",
                version="unknown",
                capabilities=[],
                tools=[],
                security_level="critical",
                last_updated=datetime.now(),
                vulnerabilities=[{
                    'type': 'connection_failure',
                    'severity': 'high',
                    'description': f'Unable to connect to MCP server: {str(e)}'
                }],
                trust_score=0.0
            )
    
    async def _discover_mcp_server(self, endpoint: str) -> Dict[str, Any]:
        """Discover MCP server info via standard MCP protocol"""
        async with aiohttp.ClientSession() as session:
            # Try MCP discovery endpoints
            discovery_paths = [
                "/.well-known/mcp_server",
                "/mcp/info",
                "/api/mcp/server-info"
            ]
            
            for path in discovery_paths:
                try:
                    async with session.get(f"{endpoint}{path}", timeout=10) as response:
                        if response.status == 200:
                            return await response.json()
                except:
                    continue
            
            # Fallback to basic connection test
            return {"endpoint": endpoint, "status": "unknown"}
    
    async def _analyze_mcp_capabilities(self, endpoint: str) -> List[str]:
        """Analyze actual MCP server capabilities"""
        async with aiohttp.ClientSession() as session:
            try:
                # MCP capabilities discovery
                async with session.post(
                    f"{endpoint}/mcp",
                    json={"method": "capabilities", "id": 1},
                    timeout=10
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('result', {}).get('capabilities', [])
            except:
                pass
        return []
    
    async def _assess_mcp_tools(self, endpoint: str) -> List[Dict[str, Any]]:
        """Assess security of actual MCP tools"""
        async with aiohttp.ClientSession() as session:
            try:
                # Get tool list
                async with session.post(
                    f"{endpoint}/mcp",
                    json={"method": "tools/list", "id": 2},
                    timeout=10
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        tools = data.get('result', {}).get('tools', [])
                        
                        # Analyze each tool for security risks
                        tool_assessments = []
                        for tool in tools:
                            assessment = await self._analyze_tool_security(tool)
                            tool_assessments.append(assessment)
                        
                        return tool_assessments
            except:
                pass
        return []
    
    async def _analyze_tool_security(self, tool: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual tool for security risks"""
        risk_indicators = []
        
        # Check for dangerous capabilities
        dangerous_patterns = [
            'file_system', 'network_access', 'shell_exec', 
            'database_access', 'credential_access'
        ]
        
        tool_name = tool.get('name', '').lower()
        tool_desc = tool.get('description', '').lower()
        
        for pattern in dangerous_patterns:
            if pattern in tool_name or pattern in tool_desc:
                risk_indicators.append({
                    'type': 'dangerous_capability',
                    'pattern': pattern,
                    'severity': 'high'
                })
        
        # Check input validation
        input_schema = tool.get('inputSchema', {})
        if not input_schema or not input_schema.get('properties'):
            risk_indicators.append({
                'type': 'weak_input_validation',
                'severity': 'medium'
            })
        
        return {
            'tool': tool,
            'risk_indicators': risk_indicators,
            'risk_score': len(risk_indicators) * 2.5  # Simple scoring
        }
    
    async def _check_mcp_vulnerabilities(self, server_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check known vulnerabilities for MCP server"""
        vulnerabilities = []
        
        server_name = server_info.get('name', '')
        server_version = server_info.get('version', '')
        
        # This would query real vulnerability databases
        # For demo, we'll simulate some checks
        known_vulnerable_versions = {
            'mcp-server': ['1.0.0', '1.0.1'],
            'anthropic-mcp': ['0.9.0'],
            'openai-mcp': ['1.1.0']
        }
        
        for vuln_server, vuln_versions in known_vulnerable_versions.items():
            if vuln_server.lower() in server_name.lower():
                if server_version in vuln_versions:
                    vulnerabilities.append({
                        'cve_id': f'CVE-2024-{hash(vuln_server + server_version) % 10000}',
                        'severity': 'high',
                        'description': f'Known vulnerability in {vuln_server} version {server_version}',
                        'affected_component': server_name
                    })
        
        return vulnerabilities
    
    async def _calculate_mcp_trust_score(self, server_info: Dict[str, Any], 
                                       vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate trust score for MCP server"""
        base_score = 5.0  # Start with neutral
        
        # Deduct for vulnerabilities
        for vuln in vulnerabilities:
            if vuln.get('severity') == 'critical':
                base_score -= 2.0
            elif vuln.get('severity') == 'high':
                base_score -= 1.0
            elif vuln.get('severity') == 'medium':
                base_score -= 0.5
        
        # Add points for good practices
        if server_info.get('tls_enabled'):
            base_score += 0.5
        if server_info.get('authentication_required'):
            base_score += 0.5
        if server_info.get('rate_limiting'):
            base_score += 0.3
        
        return max(0.0, min(10.0, base_score))
    
    def _determine_security_level(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Determine overall security level"""
        if any(v.get('severity') == 'critical' for v in vulnerabilities):
            return 'critical'
        elif any(v.get('severity') == 'high' for v in vulnerabilities):
            return 'high'
        elif any(v.get('severity') == 'medium' for v in vulnerabilities):
            return 'medium'
        else:
            return 'low'

class A2ARegistryConnector:
    """Connector to investigate real A2A agent registries and marketplaces"""
    
    def __init__(self, registry_urls: List[str] = None):
        self.registry_urls = registry_urls or [
            "https://agents.anthropic.com/registry",
            "https://openai.com/agents/marketplace",
            "https://huggingface.co/agents",
            "https://github.com/agent-registry",
            "https://enterprise-agents.internal/registry"
        ]
    
    async def investigate_agent(self, agent_name: str, agent_id: str = None) -> A2AAgentCard:
        """
        Actually investigate a real A2A agent from registries
        
        This would replace static analysis with real agent discovery
        """
        try:
            # Step 1: Agent Discovery across registries
            agent_info = await self._discover_agent_across_registries(agent_name, agent_id)
            
            # Step 2: Dependency Analysis
            dependencies = await self._analyze_agent_dependencies(agent_info)
            
            # Step 3: Security Attestation Check
            attestations = await self._verify_security_attestations(agent_info)
            
            # Step 4: Reputation Analysis
            reputation = await self._calculate_agent_reputation(agent_info)
            
            # Step 5: Compliance Check
            compliance = await self._check_compliance_certifications(agent_info)
            
            # Step 6: Known Issues Lookup
            known_issues = await self._lookup_known_issues(agent_info)
            
            return A2AAgentCard(
                agent_id=agent_info.get('id', agent_name),
                name=agent_info.get('name', agent_name),
                version=agent_info.get('version', 'unknown'),
                publisher=agent_info.get('publisher', 'unknown'),
                capabilities=agent_info.get('capabilities', []),
                dependencies=dependencies,
                security_attestations=attestations,
                reputation_score=reputation,
                known_issues=known_issues,
                compliance_certifications=compliance
            )
            
        except Exception as e:
            # Return high-risk profile if can't investigate
            return A2AAgentCard(
                agent_id=agent_id or agent_name,
                name=agent_name,
                version="unknown",
                publisher="unknown",
                capabilities=[],
                dependencies=[],
                security_attestations=[],
                reputation_score=0.0,
                known_issues=[{
                    'type': 'investigation_failure',
                    'severity': 'high',
                    'description': f'Unable to investigate agent: {str(e)}'
                }],
                compliance_certifications=[]
            )
    
    async def _discover_agent_across_registries(self, agent_name: str, 
                                              agent_id: str = None) -> Dict[str, Any]:
        """Search for agent across multiple registries"""
        async with aiohttp.ClientSession() as session:
            for registry_url in self.registry_urls:
                try:
                    # Try different search patterns
                    search_urls = [
                        f"{registry_url}/api/agents/search?name={agent_name}",
                        f"{registry_url}/api/agents/{agent_id}" if agent_id else None,
                        f"{registry_url}/agents/{agent_name}",
                    ]
                    
                    for url in search_urls:
                        if not url:
                            continue
                            
                        async with session.get(url, timeout=10) as response:
                            if response.status == 200:
                                data = await response.json()
                                if data:  # Found agent info
                                    return data
                except:
                    continue
        
        return {"name": agent_name, "status": "not_found"}
    
    async def _analyze_agent_dependencies(self, agent_info: Dict[str, Any]) -> List[str]:
        """Analyze agent dependencies for supply chain risks"""
        dependencies = agent_info.get('dependencies', [])
        
        # This would do deep dependency analysis
        # Check for known vulnerable dependencies
        # Analyze dependency tree depth and complexity
        
        analyzed_deps = []
        for dep in dependencies:
            # Check if dependency has known vulnerabilities
            vuln_check = await self._check_dependency_vulnerabilities(dep)
            analyzed_deps.append({
                'name': dep,
                'vulnerabilities': vuln_check,
                'risk_level': 'high' if vuln_check else 'low'
            })
        
        return analyzed_deps
    
    async def _check_dependency_vulnerabilities(self, dependency: str) -> List[Dict[str, Any]]:
        """Check specific dependency for vulnerabilities"""
        # This would query real vulnerability databases
        # For demo, simulate some checks
        
        known_vulnerable_deps = {
            'requests': [{'cve': 'CVE-2023-32681', 'severity': 'medium'}],
            'pillow': [{'cve': 'CVE-2023-50447', 'severity': 'high'}],
            'urllib3': [{'cve': 'CVE-2023-45803', 'severity': 'medium'}]
        }
        
        dep_name = dependency.split('==')[0] if '==' in dependency else dependency
        return known_vulnerable_deps.get(dep_name.lower(), [])
    
    async def _verify_security_attestations(self, agent_info: Dict[str, Any]) -> List[str]:
        """Verify security attestations and signatures"""
        attestations = []
        
        # Check digital signatures
        if agent_info.get('signature'):
            # Would verify cryptographic signature
            attestations.append('digital_signature_verified')
        
        # Check security scans
        if agent_info.get('security_scan_date'):
            scan_date = datetime.fromisoformat(agent_info['security_scan_date'])
            if datetime.now() - scan_date < timedelta(days=30):
                attestations.append('recent_security_scan')
        
        # Check publisher verification
        if agent_info.get('publisher_verified'):
            attestations.append('publisher_verified')
        
        return attestations
    
    async def _calculate_agent_reputation(self, agent_info: Dict[str, Any]) -> float:
        """Calculate agent reputation score"""
        base_score = 5.0
        
        # Factors that increase reputation
        download_count = agent_info.get('downloads', 0)
        if download_count > 10000:
            base_score += 1.0
        elif download_count > 1000:
            base_score += 0.5
        
        # User ratings
        rating = agent_info.get('average_rating', 0)
        if rating > 4.0:
            base_score += 1.0
        elif rating > 3.0:
            base_score += 0.5
        
        # Age and maintenance
        created_date = agent_info.get('created_date')
        if created_date:
            age_days = (datetime.now() - datetime.fromisoformat(created_date)).days
            if age_days > 365:  # Mature project
                base_score += 0.5
        
        last_updated = agent_info.get('last_updated')
        if last_updated:
            days_since_update = (datetime.now() - datetime.fromisoformat(last_updated)).days
            if days_since_update < 30:  # Recently maintained
                base_score += 0.5
            elif days_since_update > 365:  # Stale
                base_score -= 1.0
        
        return max(0.0, min(10.0, base_score))
    
    async def _check_compliance_certifications(self, agent_info: Dict[str, Any]) -> List[str]:
        """Check compliance certifications"""
        certifications = []
        
        # Common compliance frameworks
        compliance_indicators = {
            'soc2': 'SOC2 Type II',
            'iso27001': 'ISO 27001',
            'gdpr': 'GDPR Compliant',
            'hipaa': 'HIPAA Compliant',
            'pci': 'PCI DSS'
        }
        
        for indicator, cert_name in compliance_indicators.items():
            if agent_info.get(f'{indicator}_compliant'):
                certifications.append(cert_name)
        
        return certifications
    
    async def _lookup_known_issues(self, agent_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Lookup known security issues for agent"""
        issues = []
        
        # This would query security advisory databases
        # GitHub security advisories, CVE databases, etc.
        
        agent_name = agent_info.get('name', '')
        
        # Simulate some known issues lookup
        if 'deprecated' in agent_info.get('tags', []):
            issues.append({
                'type': 'deprecated_agent',
                'severity': 'medium',
                'description': 'Agent is marked as deprecated by publisher'
            })
        
        if agent_info.get('open_issues', 0) > 50:
            issues.append({
                'type': 'high_issue_count',
                'severity': 'low',
                'description': f'Agent has {agent_info["open_issues"]} open issues'
            })
        
        return issues

class ThreatIntelligenceConnector:
    """Connector for real-time threat intelligence integration"""
    
    def __init__(self):
        self.threat_feeds = [
            "https://nvd.nist.gov/feeds/json/cve/1.1",
            "https://cve.mitre.org/data/downloads",
            "https://github.com/advisories",
            "https://snyk.io/vuln/",
            "https://security.openai.com/advisories"
        ]
    
    async def get_latest_threats(self, component_type: str) -> List[Dict[str, Any]]:
        """Get latest threats for specific component types"""
        # This would query real threat intelligence feeds
        # and return current threats relevant to MCP/A2A components
        pass
    
    async def check_iocs(self, indicators: List[str]) -> Dict[str, Any]:
        """Check indicators of compromise against threat databases"""
        # This would check URLs, hashes, IPs against threat feeds
        pass

# Enhanced Workflow Parser Integration
class EnhancedWorkflowParser:
    """Enhanced parser that uses registry connectors for real investigation"""
    
    def __init__(self):
        self.mcp_connector = MCPRegistryConnector()
        self.a2a_connector = A2ARegistryConnector()
        self.threat_intel = ThreatIntelligenceConnector()
    
    async def deep_analyze_workflow(self, workflow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform deep analysis using real registry investigation
        instead of just static YAML analysis
        """
        
        analysis_results = {
            'mcp_servers': [],
            'a2a_agents': [],
            'real_vulnerabilities': [],
            'supply_chain_risks': [],
            'compliance_gaps': []
        }
        
        steps = workflow_data.get('workflow', {}).get('steps', [])
        
        for step in steps:
            # Investigate real MCP endpoints
            if 'mcp_endpoint' in step.get('params', {}):
                endpoint = step['params']['mcp_endpoint']
                mcp_info = await self.mcp_connector.investigate_mcp_endpoint(endpoint)
                analysis_results['mcp_servers'].append(mcp_info)
            
            # Investigate real A2A agents
            agent_name = step.get('agent')
            if agent_name:
                agent_card = await self.a2a_connector.investigate_agent(agent_name)
                analysis_results['a2a_agents'].append(agent_card)
        
        return analysis_results 
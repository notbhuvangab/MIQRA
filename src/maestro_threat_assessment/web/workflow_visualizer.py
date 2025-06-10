"""
Enhanced Workflow Visualizer for MAESTRO Threat Assessment Framework
Creates interactive network diagrams showing workflow structure with threat indicators
"""

import streamlit as st
import yaml
import networkx as nx
from streamlit_agraph import agraph, Node, Edge, Config
from typing import Dict, List, Any, Tuple, Optional
import sys
import os

# Add the src directory to Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.join(current_dir, '../../..')
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

from maestro_threat_assessment.core.workflow_parser import WorkflowParser, ParsedWorkflow

class WorkflowVisualizer:
    """Enhanced workflow visualizer with threat indication capabilities"""
    
    def __init__(self):
        # Initialize the official MAESTRO workflow parser for consistency
        self.workflow_parser = WorkflowParser()
        
        # Node styling configuration
        self.node_types = {
            'start': {'color': '#10b981', 'size': 40},    # Green
            'end': {'color': '#f97316', 'size': 40},      # Orange  
            'agent': {'color': '#3b82f6', 'size': 35},    # Blue
            'tool': {'color': '#8b5cf6', 'size': 30}      # Purple
        }
        
        # Vulnerability severity colors
        self.vulnerability_colors = {
            'critical': '#dc2626',  # Red
            'high': '#ea580c',      # Orange-red
            'medium': '#d97706',    # Orange
            'low': '#65a30d'        # Light green
        }
        
    def parse_workflow_structure(self, workflow_yaml: str) -> Dict[str, Any]:
        """Parse YAML workflow using the official MAESTRO WorkflowParser for consistency"""
        try:
            # Use the official parser to ensure consistency with CLI
            parsed_workflow: ParsedWorkflow = self.workflow_parser.parse_yaml(workflow_yaml)
            
            # Convert ParsedWorkflow to the structure needed for visualization
            # while maintaining compatibility with existing visualization code
            
            # Extract agents from workflow steps and build agent info
            agents = {}
            
            # Parse the original YAML to get agent tool information
            # since ParsedWorkflow focuses on steps, not agent definitions
            try:
                workflow_data = yaml.safe_load(workflow_yaml)
                workflow_section = workflow_data.get('workflow', {})
                
                # Get agent definitions if they exist
                agent_definitions = workflow_section.get('agents', [])
                for agent_def in agent_definitions:
                    agent_name = agent_def.get('name', '')
                    agents[agent_name] = {
                        'tools': agent_def.get('tools', []),
                        'protocol': agent_def.get('protocol', 'Unknown'),
                        'communicates_with': agent_def.get('communicates_with', [])
                    }
                
                # Also extract agents from steps (in case agents section doesn't exist)
                for step in parsed_workflow.steps:
                    if step.agent and step.agent not in agents:
                        # Default agent info from step analysis
                        agents[step.agent] = {
                            'tools': [],  # Will be populated from step actions
                            'protocol': 'Unknown',
                            'communicates_with': []
                        }
                        
                        # Try to extract tools from step actions/params
                        if 'tool' in step.action.lower() or 'api' in step.action.lower():
                            tool_name = step.action.replace('_', ' ').title()
                            if tool_name not in agents[step.agent]['tools']:
                                agents[step.agent]['tools'].append(tool_name)
                                
                        # Extract tools from parameters
                        for param_key, param_value in step.params.items():
                            if any(keyword in param_key.lower() for keyword in ['tool', 'api', 'service']):
                                if isinstance(param_value, str):
                                    tool_name = param_value.replace('_', ' ').title()
                                    if tool_name not in agents[step.agent]['tools']:
                                        agents[step.agent]['tools'].append(tool_name)
                                        
            except Exception as e:
                st.warning(f"Could not parse agent definitions, using step-based extraction: {e}")
                # Fallback: extract from steps only
                for step in parsed_workflow.steps:
                    if step.agent and step.agent not in agents:
                        agents[step.agent] = {
                            'tools': [step.action],
                            'protocol': 'Unknown', 
                            'communicates_with': []
                        }
            
            # Convert workflow steps to visualization format
            steps = []
            for step in parsed_workflow.steps:
                steps.append({
                    'agent': step.agent,
                    'action': step.action,
                    'protocol': 'Unknown',  # Could extract from step params if needed
                    'params': step.params
                })
            
            return {
                'name': parsed_workflow.name,
                'description': parsed_workflow.description,
                'agents': agents,
                'steps': steps,
                'parsed_workflow': parsed_workflow  # Include full parsed object for reference
            }
            
        except Exception as e:
            st.error(f"Error parsing workflow with official parser: {e}")
            return {}
    
    def _get_agent_vulnerabilities(self, agent_name: str, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get vulnerabilities associated with a specific agent"""
        agent_vulns = []
        for vuln in vulnerabilities:
            # Check if vulnerability is associated with this agent
            vuln_step = vuln.get('step', '')
            vuln_agent = vuln.get('agent', '')
            vuln_location = vuln.get('location', '')
            
            if (agent_name in vuln_step or 
                agent_name in vuln_agent or 
                agent_name in vuln_location):
                agent_vulns.append(vuln)
        
        return agent_vulns
    
    def _get_highest_severity(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Get the highest severity from a list of vulnerabilities"""
        if not vulnerabilities:
            return 'info'
        
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severity_order:
            if any(v.get('severity', 'info') == severity for v in vulnerabilities):
                return severity
        return 'info'
    
    def create_workflow_nodes_and_edges(self, workflow_structure: Dict[str, Any], vulnerabilities: List[Dict[str, Any]] = None) -> Tuple[List[Node], List[Edge]]:
        """Create nodes and edges for workflow visualization with threat information"""
        nodes = []
        edges = []
        
        if not workflow_structure:
            return nodes, edges
        
        vulnerabilities = vulnerabilities or []
        
        # Create Start node
        nodes.append(Node(
            id="start",
            label="Start",
            size=self.node_types['start']['size'],
            color=self.node_types['start']['color'],
            font={'color': '#ffffff', 'size': 14, 'face': 'Arial Bold'},
            shape='circle',
            borderWidth=3,
            borderColor='#ffffff',
            shadow=True
        ))
        
        # Create End node
        nodes.append(Node(
            id="end", 
            label="End",
            size=self.node_types['end']['size'],
            color=self.node_types['end']['color'],
            font={'color': '#ffffff', 'size': 14, 'face': 'Arial Bold'},
            shape='circle',
            borderWidth=3,
            borderColor='#ffffff',
            shadow=True
        ))
        
        # Track created nodes to avoid duplicates
        created_agents = set()
        created_tools = set()
        
        # Create agent nodes with vulnerability information
        for agent_name, agent_info in workflow_structure.get('agents', {}).items():
            if agent_name not in created_agents:
                # Get vulnerabilities for this agent
                agent_vulns = self._get_agent_vulnerabilities(agent_name, vulnerabilities)
                highest_severity = self._get_highest_severity(agent_vulns)
                vuln_count = len(agent_vulns)
                
                # Clean up agent name for display
                display_name = agent_name.replace('Agent', '').replace('_', ' ')
                protocol = agent_info.get('protocol', 'Unknown')
                
                # Determine node color based on vulnerabilities
                if vuln_count > 0:
                    node_color = self.vulnerability_colors[highest_severity]
                    border_color = '#ffffff'
                    border_width = 4
                else:
                    node_color = self.node_types['agent']['color']
                    border_color = '#ffffff'
                    border_width = 2
                
                # Create label with vulnerability info
                if vuln_count > 0:
                    severity_emoji = {
                        'critical': '🔴',
                        'high': '🟠', 
                        'medium': '🟡',
                        'low': '🟢',
                        'info': '🔵'
                    }
                    label = f"{display_name}\n({protocol})\n{severity_emoji.get(highest_severity, '⚠️')} {vuln_count} vuln(s)"
                else:
                    label = f"{display_name}\n({protocol})"
                
                # Create tooltip with vulnerability details
                tooltip_lines = [
                    f"Agent: {agent_name}",
                    f"Protocol: {protocol}",
                    f"Vulnerabilities: {vuln_count}"
                ]
                
                if agent_vulns:
                    tooltip_lines.append(f"Highest Severity: {highest_severity.title()}")
                    tooltip_lines.append("Vulnerabilities:")
                    for vuln in agent_vulns[:3]:  # Show max 3 vulns in tooltip
                        vuln_type = vuln.get('type', 'unknown').replace('_', ' ').title()
                        tooltip_lines.append(f"  • {vuln_type} ({vuln.get('severity', 'unknown')})")
                    if len(agent_vulns) > 3:
                        tooltip_lines.append(f"  ... and {len(agent_vulns) - 3} more")
                
                tooltip = "\n".join(tooltip_lines)
                
                nodes.append(Node(
                    id=agent_name,
                    label=label,
                    size=self.node_types['agent']['size'] + (vuln_count * 5),  # Larger for more vulns
                    color=node_color,
                    font={'color': '#ffffff', 'size': 12, 'face': 'Arial'},
                    shape='circle',
                    borderWidth=border_width,
                    borderColor=border_color,
                    shadow=True,
                    title=tooltip
                ))
                created_agents.add(agent_name)
                
                # Create tool nodes for this agent
                for tool in agent_info.get('tools', []):
                    tool_id = f"{agent_name}_{tool}"
                    if tool_id not in created_tools:
                        # Clean up tool name for display
                        tool_display = tool.replace('_', ' ').title()
                        
                        # Check if tool has vulnerabilities too
                        tool_vulns = [v for v in vulnerabilities if tool in v.get('location', '') or tool in v.get('description', '')]
                        tool_severity = self._get_highest_severity(tool_vulns)
                        tool_vuln_count = len(tool_vulns)
                        
                        if tool_vuln_count > 0:
                            tool_color = self.vulnerability_colors[tool_severity]
                            tool_border_width = 3
                            tool_label = f"{tool_display}\n⚠️ {tool_vuln_count}"
                        else:
                            tool_color = self.node_types['tool']['color']
                            tool_border_width = 2
                            tool_label = tool_display
                        
                        nodes.append(Node(
                            id=tool_id,
                            label=tool_label,
                            size=self.node_types['tool']['size'] + (tool_vuln_count * 3),
                            color=tool_color,
                            font={'color': '#ffffff', 'size': 10, 'face': 'Arial'},
                            shape='box',
                            borderWidth=tool_border_width,
                            borderColor='#ffffff',
                            shadow=True,
                            title=f"Tool: {tool}\nUsed by: {agent_name}\nVulnerabilities: {tool_vuln_count}"
                        ))
                        created_tools.add(tool_id)
                        
                        # Create edge from agent to tool
                        edge_color = '#fbbf24'  # Yellow for agent-to-tool
                        if tool_vuln_count > 0:
                            edge_color = self.vulnerability_colors[tool_severity]
                            edge_width = 3
                        else:
                            edge_width = 2
                        
                        edges.append(Edge(
                            source=agent_name,
                            target=tool_id,
                            color=edge_color,
                            width=edge_width,
                            arrows={'to': {'enabled': True, 'scaleFactor': 0.8}},
                            title=f"Agent to Tool ({tool_vuln_count} vulnerabilities)" if tool_vuln_count > 0 else "Agent to Tool",
                            dashes=False
                        ))
        
        # Create edges based on workflow steps (sequential flow)
        steps = workflow_structure.get('steps', [])
        if steps:
            # Connect start to first agent
            first_agent = steps[0].get('agent')
            if first_agent:
                edges.append(Edge(
                    source="start",
                    target=first_agent,
                    color='#10b981',  # Green for start
                    width=3,
                    arrows={'to': {'enabled': True, 'scaleFactor': 1.2}},
                    title="Workflow Start"
                ))
            
            # Connect agents in sequence
            for i in range(len(steps) - 1):
                current_agent = steps[i].get('agent')
                next_agent = steps[i + 1].get('agent')
                
                if current_agent and next_agent and current_agent != next_agent:
                    edges.append(Edge(
                        source=current_agent,
                        target=next_agent,
                        color='#6b7280',  # Gray for sequential flow
                        width=2,
                        arrows={'to': {'enabled': True, 'scaleFactor': 1.0}},
                        title=f"Sequential: {current_agent} → {next_agent}"
                    ))
            
            # Connect last agent to end
            last_agent = steps[-1].get('agent')
            if last_agent:
                edges.append(Edge(
                    source=last_agent,
                    target="end",
                    color='#f97316',  # Orange for end
                    width=3,
                    arrows={'to': {'enabled': True, 'scaleFactor': 1.2}},
                    title="Workflow End"
                ))
        
        # Create A2A communication edges
        for agent_name, agent_info in workflow_structure.get('agents', {}).items():
            communicates_with = agent_info.get('communicates_with', [])
            for target_agent in communicates_with:
                if target_agent in created_agents:
                    edges.append(Edge(
                        source=agent_name,
                        target=target_agent,
                        color='#ec4899',  # Pink for A2A communication
                        width=2,
                        arrows={'to': {'enabled': True, 'scaleFactor': 1.0}},
                        title=f"A2A Communication: {agent_name} → {target_agent}",
                        dashes=[5, 5]  # Dashed line for A2A
                    ))
        
        return nodes, edges
    
    def create_workflow_config(self) -> Config:
        """Create optimized configuration for workflow visualization"""
        return Config(
            width=1400,
            height=800,
            directed=True,
            physics={
                'enabled': True,
                'solver': 'forceAtlas2Based',
                'forceAtlas2Based': {
                    'gravitationalConstant': -50,
                    'centralGravity': 0.01,
                    'springLength': 100,
                    'springConstant': 0.08,
                    'damping': 0.4,
                    'avoidOverlap': 1
                },
                'stabilization': {
                    'enabled': True,
                    'iterations': 200,
                    'updateInterval': 25
                }
            },
            layout={
                'hierarchical': {
                    'enabled': False
                }
            },
            interaction={
                'dragNodes': True,
                'dragView': True,
                'zoomView': True,
                'selectConnectedEdges': True,
                'hoverConnectedEdges': True
            },
            nodes={
                'borderWidth': 2,
                'borderWidthSelected': 4,
                'font': {
                    'color': '#ffffff',
                    'size': 12,
                    'face': 'Arial'
                }
            },
            edges={
                'color': {
                    'inherit': False
                },
                'smooth': {
                    'enabled': True,
                    'type': 'curvedCW',
                    'roundness': 0.2
                },
                'arrows': {
                    'to': {
                        'enabled': True,
                        'scaleFactor': 1.0
                    }
                }
            }
        )
    
    def render_workflow_visualization(self, workflow_yaml: str, vulnerabilities: List[Dict[str, Any]] = None):
        """Render the complete workflow visualization with threat information"""
        
        # Parse workflow structure
        workflow_structure = self.parse_workflow_structure(workflow_yaml)
        
        if not workflow_structure:
            st.error("Unable to parse workflow structure")
            return
        
        # Display workflow info
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.subheader(f"🔄 {workflow_structure.get('name', 'Workflow Visualization')}")
            if workflow_structure.get('description'):
                st.caption(workflow_structure['description'])
            
            # Show vulnerability summary if available
            if vulnerabilities:
                total_vulns = len(vulnerabilities)
                critical_vulns = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
                high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'high'])
                
                if total_vulns > 0:
                    st.warning(f"⚠️ **{total_vulns} vulnerabilities detected** ({critical_vulns} critical, {high_vulns} high)")
        
        with col2:
            # Display legend
            st.markdown("""
            **Legend:**
            - 🟢 **Start** - Workflow entry point
            - 🔵 **Agent** - AI agents 
            - 🟣 **Tool** - Agent tools
            - 🟠 **End** - Workflow completion
            
            **Threat Indicators:**
            - 🔴 **Critical** - Critical vulnerabilities
            - 🟠 **High** - High severity issues
            - 🟡 **Medium** - Medium severity issues
            - 🟢 **Low** - Low severity issues
            
            **Connections:**
            - **Solid Gray** - Sequential flow
            - **Solid Yellow** - Agent to Tool
            - **Dashed Pink** - A2A Communication
            - **Red/Orange** - Vulnerable connections
            """)
        
        # Create visualization
        nodes, edges = self.create_workflow_nodes_and_edges(workflow_structure, vulnerabilities)
        config = self.create_workflow_config()
        
        # Render the graph
        if nodes:
            try:
                result = agraph(nodes=nodes, edges=edges, config=config)
                
                # Display selection info if available
                if result and 'nodes' in result and result['nodes']:
                    selected_node = result['nodes'][0]
                    st.info(f"Selected: {selected_node}")
                    
            except Exception as e:
                st.error(f"Error rendering visualization: {e}")
                st.warning("Falling back to text representation...")
                self._render_text_fallback(workflow_structure, vulnerabilities)
        else:
            st.warning("No workflow elements found to visualize")
            self._render_text_fallback(workflow_structure, vulnerabilities)
    
    def _render_text_fallback(self, workflow_structure: Dict[str, Any], vulnerabilities: List[Dict[str, Any]] = None):
        """Render text-based workflow representation as fallback"""
        st.subheader("📝 Workflow Structure (Text View)")
        
        # Display agents
        st.write("**Agents:**")
        for agent_name, agent_info in workflow_structure.get('agents', {}).items():
            protocol = agent_info.get('protocol', 'Unknown')
            tools = ', '.join(agent_info.get('tools', []))
            
            # Get vulnerabilities for this agent
            if vulnerabilities:
                agent_vulns = self._get_agent_vulnerabilities(agent_name, vulnerabilities)
                vuln_info = f" ({len(agent_vulns)} vulnerabilities)" if agent_vulns else ""
            else:
                vuln_info = ""
            
            st.write(f"- {agent_name} ({protocol}) - Tools: {tools}{vuln_info}")
        
        # Display steps
        st.write("**Steps:**")
        for i, step in enumerate(workflow_structure.get('steps', []), 1):
            agent = step.get('agent', 'Unknown')
            action = step.get('action', 'Unknown')
            protocol = step.get('protocol', 'Unknown')
            st.write(f"{i}. {agent} → {action} ({protocol})")

# Convenience function for easy integration
def render_workflow_diagram(workflow_yaml: str, vulnerabilities: List[Dict[str, Any]] = None):
    """Convenience function to render workflow diagram with threat information"""
    visualizer = WorkflowVisualizer()
    visualizer.render_workflow_visualization(workflow_yaml, vulnerabilities) 
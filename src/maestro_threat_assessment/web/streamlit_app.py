"""
MAESTRO Threat Assessment Framework - Streamlit GUI
Interactive web interface for threat assessment with flowchart visualization
"""

import streamlit as st
import yaml
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
from streamlit_agraph import agraph, Node, Edge, Config
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add the src directory to Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.join(current_dir, '../../..')
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

try:
    from maestro_threat_assessment.core.maestro_engine import MAESTROEngine
    from maestro_threat_assessment.models.maestro_constants import (
        MAESTROLayer, MAESTRO_LAYER_WEIGHTS, MAESTRO_EXPOSURE_INDEX,
        MAESTRO_COST_WEIGHTS, VULNERABILITY_LAYER_MAPPING
    )
except ImportError as e:
    st.error(f"❌ Import Error: {e}")
    st.error("Please ensure the MAESTRO package is properly installed.")
    st.stop()

# Configure Streamlit page
st.set_page_config(
    page_title="MAESTRO Threat Assessment Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1e3a8a;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    /* Dark mode compatible main header */
    @media (prefers-color-scheme: dark) {
        .main-header {
            color: #60a5fa;
        }
    }
    
    .metric-card {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
        padding: 1.5rem;
        border-radius: 0.75rem;
        border-left: 4px solid #3b82f6;
        margin: 0.5rem 0;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        transition: all 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 12px -1px rgba(0, 0, 0, 0.15);
    }
    
    .metric-card h3 {
        color: #374151 !important;
        font-size: 0.875rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .metric-card h2 {
        color: #111827 !important;
        font-size: 2rem;
        font-weight: 700;
        margin: 0;
        line-height: 1;
    }
    
    /* Dark mode metric cards */
    @media (prefers-color-scheme: dark) {
        .metric-card {
            background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
            border-left-color: #60a5fa;
        }
        
        .metric-card h3 {
            color: #d1d5db !important;
        }
        
        .metric-card h2 {
            color: #f9fafb !important;
        }
    }
    
    /* Force dark mode styles for Streamlit's dark theme */
    [data-theme="dark"] .metric-card {
        background: linear-gradient(135deg, #1f2937 0%, #374151 100%) !important;
        border-left-color: #60a5fa !important;
    }
    
    [data-theme="dark"] .metric-card h3 {
        color: #d1d5db !important;
    }
    
    [data-theme="dark"] .metric-card h2 {
        color: #f9fafb !important;
    }
    
    [data-theme="dark"] .main-header {
        color: #60a5fa !important;
    }
    
    .risk-high {
        border-left-color: #ef4444 !important;
        background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
    }
    
    .risk-medium {
        border-left-color: #f59e0b !important;
        background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);
    }
    
    .risk-low {
        border-left-color: #10b981 !important;
        background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
    }
    
    .risk-critical {
        border-left-color: #dc2626 !important;
        background: linear-gradient(135deg, #fef2f2 0%, #fecaca 100%);
    }
    
    /* Dark mode risk colors */
    @media (prefers-color-scheme: dark), [data-theme="dark"] {
        .risk-high {
            background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%) !important;
        }
        
        .risk-medium {
            background: linear-gradient(135deg, #78350f 0%, #92400e 100%) !important;
        }
        
        .risk-low {
            background: linear-gradient(135deg, #14532d 0%, #166534 100%) !important;
        }
        
        .risk-critical {
            background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%) !important;
        }
    }
    
    /* YAML code block styling */
    .yaml-example {
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
        font-family: 'Monaco', 'Consolas', monospace;
        font-size: 0.875rem;
        line-height: 1.5;
    }
    
    @media (prefers-color-scheme: dark), [data-theme="dark"] {
        .yaml-example {
            background-color: #1f2937 !important;
            border-color: #374151 !important;
            color: #f9fafb !important;
        }
    }
    
    /* Better node labels for flowchart */
    .react-flow__node-default {
        background: white !important;
        border: 2px solid #e2e8f0 !important;
        border-radius: 0.5rem !important;
        padding: 0.5rem !important;
        font-size: 0.875rem !important;
        font-weight: 500 !important;
        color: #1f2937 !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1) !important;
    }
    
    @media (prefers-color-scheme: dark), [data-theme="dark"] {
        .react-flow__node-default {
            background: #374151 !important;
            border-color: #6b7280 !important;
            color: #f9fafb !important;
        }
    }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'assessment_report' not in st.session_state:
    st.session_state.assessment_report = None
if 'custom_parameters' not in st.session_state:
    st.session_state.custom_parameters = {
        'layer_weights': dict(MAESTRO_LAYER_WEIGHTS),
        'exposure_index': dict(MAESTRO_EXPOSURE_INDEX),
        'cost_weights': dict(MAESTRO_COST_WEIGHTS)
    }

def create_workflow_flowchart(workflow_data: Dict[str, Any], vulnerabilities: List[Dict[str, Any]] = None):
    """Create an interactive flowchart visualization of the workflow"""
    
    nodes = []
    edges = []
    
    # Color mapping for vulnerability severity with better contrast
    severity_colors = {
        'critical': '#dc2626',  # Red
        'high': '#ea580c',      # Orange-red  
        'medium': '#d97706',    # Amber
        'low': '#059669',       # Green
        'info': '#0284c7'       # Blue
    }
    
    # Text colors for better contrast
    text_colors = {
        'critical': '#ffffff',  # White text on red
        'high': '#ffffff',      # White text on orange
        'medium': '#ffffff',    # White text on amber
        'low': '#ffffff',       # White text on green
        'info': '#ffffff'       # White text on blue
    }
    
    # Create vulnerability lookup
    vuln_lookup = {}
    if vulnerabilities:
        for vuln in vulnerabilities:
            step_id = vuln.get('step', '')
            if step_id not in vuln_lookup:
                vuln_lookup[step_id] = []
            vuln_lookup[step_id].append(vuln)
    
    # Add nodes for each workflow step
    for step in workflow_data.get('steps', []):
        step_id = step['id']
        agent = step.get('agent', 'Unknown')
        action = step.get('action', 'Unknown')
        
        # Determine node color based on vulnerabilities
        node_color = '#0284c7'  # Default blue
        text_color = '#ffffff'  # Default white text
        vuln_count = 0
        highest_severity = 'info'
        
        if step_id in vuln_lookup:
            vuln_count = len(vuln_lookup[step_id])
            severities = [v.get('severity', 'info') for v in vuln_lookup[step_id]]
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            for sev in severity_order:
                if sev in severities:
                    highest_severity = sev
                    node_color = severity_colors[sev]
                    text_color = text_colors[sev]
                    break
        
        # Create node with better formatting
        agent_display = agent.replace('Agent', '').replace('_', ' ')
        action_display = action.replace('_', ' ').title()
        
        # Create multi-line label with better formatting
        label_lines = [
            f"🤖 {agent_display}",
            f"⚡ {action_display}"
        ]
        
        if vuln_count > 0:
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡',
                'low': '🟢',
                'info': '🔵'
            }
            label_lines.append(f"{severity_emoji.get(highest_severity, '⚠️')} {vuln_count} vuln(s)")
        
        label = "\n".join(label_lines)
        
        # Enhanced tooltip with more details
        tooltip_lines = [
            f"Agent: {agent}",
            f"Action: {action}",
            f"Vulnerabilities: {vuln_count}",
            f"Highest Severity: {highest_severity.title()}"
        ]
        
        if step.get('dependencies'):
            tooltip_lines.append(f"Dependencies: {', '.join(step['dependencies'])}")
        
        tooltip = "\n".join(tooltip_lines)
        
        nodes.append(Node(
            id=step_id,
            label=label,
            size=30 + (vuln_count * 8),  # Larger nodes for more vulnerabilities
            color=node_color,
            title=tooltip,
            font={
                'color': text_color,
                'size': 14,
                'face': 'Arial',
                'align': 'center'
            },
            borderWidth=2,
            borderColor='#ffffff',
            shadow=True
        ))
    
    # Add edges based on dependencies with better styling
    for step in workflow_data.get('steps', []):
        step_id = step['id']
        dependencies = step.get('dependencies', [])
        
        for dep in dependencies:
            edges.append(Edge(
                source=dep,
                target=step_id,
                color='#6b7280',
                width=2,
                arrows={'to': {'enabled': True, 'scaleFactor': 1.2}},
                smooth={'type': 'curvedCW', 'roundness': 0.2}
            ))
    
    # Configure the graph with better settings
    config = Config(
        width=1200,
        height=700,
        directed=True,
        physics={
            'enabled': True,
            'stabilization': {'iterations': 100}
        },
        hierarchical=False,
        nodeHighlightBehavior=True,
        highlightColor="#ffd700",
        collapsible=False,
        node={
            'labelHighlightBold': True,
            'borderWidth': 2,
            'borderWidthSelected': 4
        },
        edge={
            'color': {'inherit': False},
            'smooth': True,
            'arrows': {'to': True}
        }
    )
    
    return agraph(nodes=nodes, edges=edges, config=config)

def create_maestro_layer_visualization(layer_scores: Dict[str, Any]):
    """Create MAESTRO layer risk visualization"""
    
    # Prepare data for visualization
    layers = []
    wei_scores = []
    rps_scores = []
    vuln_counts = []
    colors = []
    
    layer_colors = {
        'L1_FOUNDATION_MODELS': '#ef4444',
        'L2_DATA_OPERATIONS': '#f59e0b',
        'L3_AGENT_FRAMEWORKS': '#eab308',
        'L4_DEPLOYMENT': '#22c55e',
        'L5_OBSERVABILITY': '#06b6d4',
        'L6_COMPLIANCE': '#3b82f6',
        'L7_ECOSYSTEM': '#8b5cf6'
    }
    
    # Handle both dict and object-based layer scores
    for layer_key, score_data in layer_scores.items():
        # Convert layer key to string if it's an enum
        if hasattr(layer_key, 'name'):
            layer_name = layer_key.name
        else:
            layer_name = str(layer_key)
        
        if hasattr(score_data, 'layer'):
            # Object-based structure
            layers.append(layer_name.replace('_', ' ').title())
            wei_scores.append(score_data.wei_contribution)
            rps_scores.append(score_data.rps_contribution)
            vuln_counts.append(score_data.vulnerability_count)
            colors.append(layer_colors.get(layer_name, '#6b7280'))
        elif isinstance(score_data, dict):
            # Dict-based structure
            layers.append(layer_name.replace('_', ' ').title())
            wei_scores.append(score_data.get('wei_contribution', 0))
            rps_scores.append(score_data.get('rps_contribution', 0))
            vuln_counts.append(score_data.get('vulnerability_count', 0))
            colors.append(layer_colors.get(layer_name, '#6b7280'))
        else:
            # Fallback for simple numeric values
            layers.append(layer_name.replace('_', ' ').title())
            wei_scores.append(0)
            rps_scores.append(0)
            vuln_counts.append(score_data if isinstance(score_data, (int, float)) else 0)
            colors.append(layer_colors.get(layer_name, '#6b7280'))
    
    # Only create visualization if we have data
    if not layers:
        return None
    
    # Create subplots
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('WEI Contributions by Layer', 'RPS Contributions by Layer', 
                       'Vulnerability Count by Layer', 'Layer Risk Distribution'),
        specs=[[{"type": "bar"}, {"type": "bar"}],
               [{"type": "bar"}, {"type": "pie"}]]
    )
    
    # WEI contributions
    fig.add_trace(
        go.Bar(x=layers, y=wei_scores, name="WEI", marker_color=colors),
        row=1, col=1
    )
    
    # RPS contributions
    fig.add_trace(
        go.Bar(x=layers, y=rps_scores, name="RPS", marker_color=colors),
        row=1, col=2
    )
    
    # Vulnerability counts
    fig.add_trace(
        go.Bar(x=layers, y=vuln_counts, name="Vulnerabilities", marker_color=colors),
        row=2, col=1
    )
    
    # Risk distribution pie chart (only if we have non-zero values)
    total_risk = [wei + rps for wei, rps in zip(wei_scores, rps_scores)]
    if any(risk > 0 for risk in total_risk):
        fig.add_trace(
            go.Pie(labels=layers, values=total_risk, name="Risk Distribution"),
            row=2, col=2
        )
    else:
        # Show vulnerability counts instead if no risk scores
        fig.add_trace(
            go.Pie(labels=layers, values=vuln_counts, name="Vulnerability Distribution"),
            row=2, col=2
        )
    
    fig.update_layout(height=800, showlegend=False, title_text="MAESTRO Layer Analysis")
    
    return fig

def create_cost_analysis_chart(cost_assessment: Dict[str, Any]):
    """Create cost analysis visualization"""
    
    # Cost breakdown data
    base_cost = cost_assessment.get('base_cost', 0)
    total_tco = cost_assessment.get('total_tco', 0)
    security_investment = total_tco - base_cost
    
    roi_data = cost_assessment.get('roi_analysis', {})
    potential_loss = roi_data.get('potential_annual_loss', 0)
    risk_reduction = roi_data.get('risk_reduction_value', 0)
    
    # Create cost comparison chart
    fig = make_subplots(
        rows=1, cols=2,
        subplot_titles=('Cost Breakdown', 'Risk vs Investment Analysis'),
        specs=[[{"type": "pie"}, {"type": "bar"}]]
    )
    
    # Cost breakdown pie chart
    fig.add_trace(
        go.Pie(
            labels=['Base Infrastructure', 'Security Investment'],
            values=[base_cost, security_investment],
            name="Cost Breakdown"
        ),
        row=1, col=1
    )
    
    # Risk vs investment bar chart
    fig.add_trace(
        go.Bar(
            x=['Potential Annual Loss', 'Security Investment', 'Risk Reduction Value'],
            y=[potential_loss, security_investment, risk_reduction],
            marker_color=['#ef4444', '#3b82f6', '#10b981'],
            name="Financial Analysis"
        ),
        row=1, col=2
    )
    
    fig.update_layout(height=500, title_text="Enterprise Cost Analysis")
    
    return fig

def display_assessment_results(report):
    """Display comprehensive assessment results"""
    
    # Executive Summary
    st.markdown('<div class="main-header">📊 Assessment Results</div>', unsafe_allow_html=True)
    
    exec_summary = report.executive_summary
    
    # Key Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        risk_level = exec_summary['risk_summary']['overall_risk_level']
        risk_class = f"risk-{risk_level.lower()}"
        st.markdown(f"""
        <div class="metric-card {risk_class}">
            <h3>🛡️ Risk Level</h3>
            <h2>{risk_level.upper()}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        wei_score = exec_summary['risk_summary']['wei_score']
        st.markdown(f"""
        <div class="metric-card">
            <h3>⚡ WEI Score</h3>
            <h2>{wei_score}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        rps_score = exec_summary['risk_summary']['rps_score']
        st.markdown(f"""
        <div class="metric-card">
            <h3>🔄 RPS Score</h3>
            <h2>{rps_score}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        total_vulns = exec_summary['risk_summary']['total_vulnerabilities']
        st.markdown(f"""
        <div class="metric-card">
            <h3>🔍 Vulnerabilities</h3>
            <h2>{total_vulns}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    # Workflow Flowchart
    st.subheader("🔄 Interactive Workflow Flowchart")
    st.info("Nodes are colored by vulnerability severity: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low")
    
    # Use the actual workflow data from the report
    workflow_data = {
        'steps': []
    }
    
    # Convert ParsedWorkflow steps to dict format for visualization
    for step in report.workflow.steps:
        workflow_data['steps'].append({
            'id': step.step_id,
            'agent': step.agent,
            'action': step.action,
            'dependencies': step.dependencies
        })
    
    # Get vulnerabilities list
    all_vulnerabilities = []
    for layer_vulns in report.risk_assessment.vulnerabilities_by_layer.values():
        all_vulnerabilities.extend(layer_vulns)
    
    create_workflow_flowchart(workflow_data, all_vulnerabilities)
    
    # MAESTRO Layer Analysis
    st.subheader("🏗️ MAESTRO Layer Analysis")
    try:
        if hasattr(report.risk_assessment, 'layer_scores'):
            layer_viz = create_maestro_layer_visualization(report.risk_assessment.layer_scores)
            if layer_viz:
                st.plotly_chart(layer_viz, use_container_width=True)
            else:
                st.info("No layer analysis data available for visualization.")
        else:
            st.info("Layer analysis data not available in the assessment report.")
    except Exception as e:
        st.warning(f"Could not generate layer visualization: {str(e)}")
        # Show basic layer vulnerability counts as fallback
        if hasattr(report.risk_assessment, 'vulnerabilities_by_layer'):
            layer_vuln_counts = {}
            for layer_key, vulns in report.risk_assessment.vulnerabilities_by_layer.items():
                # Convert layer key to string if it's an enum
                if hasattr(layer_key, 'name'):
                    layer_name = layer_key.name.replace('_', ' ').title()
                else:
                    layer_name = str(layer_key).replace('_', ' ').title()
                layer_vuln_counts[layer_name] = len(vulns)
            
            if layer_vuln_counts:
                st.bar_chart(layer_vuln_counts)
    
    # Cost Analysis
    st.subheader("💰 Cost Analysis")
    cost_viz = create_cost_analysis_chart(report.cost_assessment.__dict__)
    st.plotly_chart(cost_viz, use_container_width=True)
    
    # Detailed Vulnerability Table
    st.subheader("🔍 Detailed Vulnerability Analysis")
    
    vuln_data = []
    for layer_key, vulns in report.risk_assessment.vulnerabilities_by_layer.items():
        # Convert layer key to string if it's an enum
        if hasattr(layer_key, 'name'):
            layer_name = layer_key.name.replace('_', ' ').title()
        else:
            layer_name = str(layer_key).replace('_', ' ').title()
            
        for vuln in vulns:
            vuln_data.append({
                'Layer': layer_name,
                'Type': vuln.get('type', 'Unknown'),
                'Severity': vuln.get('severity', 'Unknown'),
                'Step': vuln.get('step', 'Unknown'),
                'Agent': vuln.get('agent', 'Unknown'),
                'Description': vuln.get('description', 'No description available')
            })
    
    if vuln_data:
        df = pd.DataFrame(vuln_data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No vulnerabilities detected in this workflow.")
    
    # Recommendations
    st.subheader("📋 Strategic Recommendations")
    for i, rec in enumerate(report.recommendations, 1):
        st.markdown(f"**{i}.** {rec}")

def main():
    """Main Streamlit application"""
    
    # Sidebar
    st.sidebar.title("🛡️ MAESTRO Framework")
    st.sidebar.markdown("---")
    
    # Navigation
    page = st.sidebar.selectbox("Navigate", [
        "🏠 Home",
        "📤 Upload Workflow",
        "⚙️ Configure Parameters", 
        "📊 Assessment Results",
        "📄 Export Reports"
    ])
    
    if page == "🏠 Home":
        st.markdown('<div class="main-header">🛡️ MAESTRO Threat Assessment Framework</div>', unsafe_allow_html=True)
        
        st.markdown("""
        ## Welcome to the MAESTRO Threat Assessment Framework
        
        This interactive platform provides comprehensive security analysis for multi-agent workflows using the MAESTRO (Multi-Agent Security Threat Risk Assessment Optimization) framework.
        
        ### Key Features:
        - **📤 YAML Workflow Upload**: Upload and analyze your workflow definitions
        - **🔄 Interactive Flowchart**: Visualize workflow steps with threat mapping
        - **⚙️ Configurable Risk Models**: Customize assessment parameters
        - **🏗️ MAESTRO Layer Analysis**: 7-layer security framework (L1-L7)
        - **💰 Cost Assessment**: Enterprise TCO and ROI analysis
        - **📊 Comprehensive Reporting**: Detailed vulnerability analysis and recommendations
        
        ### MAESTRO Layers:
        1. **L1 - Foundation Models**: Model security, bias mitigation
        2. **L2 - Data Operations**: Data privacy, vector security
        3. **L3 - Agent Frameworks**: Protocol validation, tool vetting
        4. **L4 - Deployment**: Sandboxing, zero trust networking
        5. **L5 - Observability**: Monitoring, audit trails
        6. **L6 - Compliance**: Regulatory compliance, policy enforcement
        7. **L7 - Ecosystem**: Third-party integrations, supply chain
        
        ### Getting Started:
        1. Navigate to **📤 Upload Workflow** to begin your assessment
        2. Optionally configure custom parameters in **⚙️ Configure Parameters**
        3. View comprehensive results in **📊 Assessment Results**
        4. Export detailed reports in **📄 Export Reports**
        """)
        
        # Expected YAML Format Section
        st.subheader("📝 Expected YAML Workflow Format")
        st.markdown("""
        Your workflow YAML file should follow this structure for optimal analysis:
        """)
        
        # Basic structure
        with st.expander("🔍 **View Complete YAML Format Specification**", expanded=False):
            st.markdown("""
            <div class="yaml-example">
workflow:
  name: "Your Workflow Name"
  description: "Brief description of what this workflow does"
  metadata:
    version: "1.0"
    category: "security"  # security, financial, healthcare, etc.
    sensitivity: "high"   # low, medium, high, critical
    compliance_frameworks: ["SOC2", "ISO27001", "NIST"]  # Optional
    mcp_version: "1.2"    # Model Context Protocol version (optional)
    
  steps:
    - id: "threat_intel_collection"
      agent: "ThreatIntelAgent"
      action: "collect_indicators"
      params:
        sources: ["mitre_attack", "cti_feeds", "dark_web_monitoring"]
        timeframe: "24h"
        threat_types: ["apt", "ransomware", "insider_threat"]
        classification_level: "confidential"
        mcp_endpoint: "threat-intel.internal.corp"  # Optional MCP endpoint
      dependencies: []  # List of step IDs this step depends on
    
    - id: "vulnerability_scanning"
      agent: "VulnScannerAgent"
      action: "scan_infrastructure"
      params:
        scan_type: "comprehensive"
        target_networks: ["10.0.0.0/8", "172.16.0.0/12"]
        credential_vault: "hashicorp_vault"
        tool_chain: ["nessus", "qualys", "custom_scanners"]
        parallel_execution: true
      input_from: "ThreatIntelAgent"  # Optional: explicit data flow
      dependencies: ["threat_intel_collection"]
    
    - id: "risk_analysis"
      agent: "RiskAnalysisAgent"
      action: "analyze_threats"
      params:
        analysis_models: ["cvss_v4", "epss", "custom_scoring"]
        risk_threshold: 7.0
        business_context: true
        real_time_updates: true
      input_from: "VulnScannerAgent"
      dependencies: ["vulnerability_scanning"]
    
    - id: "automated_response"
      agent: "ResponseAgent"
      action: "generate_response_plan"
      params:
        response_types: ["containment", "eradication", "recovery"]
        automation_level: "semi_automated"
        approval_workflow: true
        escalation_matrix: "security_operations"
      input_from: "RiskAnalysisAgent"
      dependencies: ["risk_analysis"]
            </div>
            """, unsafe_allow_html=True)
        
        # Key sections explanation
        st.markdown("""
        #### 🔑 **Key Components Explained:**
        
        **📋 Workflow Metadata:**
        - `name`: Clear, descriptive workflow name
        - `description`: Brief explanation of workflow purpose
        - `category`: Helps with industry-specific risk assessment
        - `sensitivity`: Influences security weight calculations
        
        **🔄 Workflow Steps:**
        - `id`: Unique identifier for each step
        - `agent`: Name of the AI agent performing the action
        - `action`: Specific action the agent will perform
        - `params`: Configuration parameters for the action
        - `dependencies`: List of prerequisite steps
        - `input_from`: Explicit data flow relationships (optional)
        
        **🔒 Security Considerations:**
        - Include `mcp_endpoint` for Model Context Protocol analysis
        - Specify `classification_level` for sensitive operations
        - Use `credential_vault` references instead of hardcoded secrets
        - Set appropriate `approval_workflow` for critical actions
        """)
        
        # Quick start example
        st.subheader("🚀 Quick Start Example")
        st.markdown("Here's a simple workflow to get you started:")
        
        with st.expander("📄 **Simple Example Workflow**"):
            st.code("""
workflow:
  name: "Basic Security Analysis Pipeline"
  description: "Simple multi-agent security workflow"
  metadata:
    version: "1.0"
    category: "security"
    sensitivity: "medium"
  
  steps:
    - id: "data_collection"
      agent: "DataCollectorAgent"
      action: "gather_security_data"
      params:
        sources: ["logs", "network_traffic", "user_behavior"]
        timeframe: "1h"
      dependencies: []
    
    - id: "threat_detection"
      agent: "ThreatDetectorAgent"
      action: "analyze_threats"
      params:
        detection_models: ["ml_classifier", "rule_based"]
        confidence_threshold: 0.8
      input_from: "DataCollectorAgent"
      dependencies: ["data_collection"]
    
    - id: "response_planning"
      agent: "ResponsePlannerAgent"
      action: "create_response_plan"
      params:
        response_types: ["alert", "isolate", "investigate"]
        auto_execute: false
      input_from: "ThreatDetectorAgent"
      dependencies: ["threat_detection"]
            """, language="yaml")
        
        # Tips section
        st.markdown("""
        #### 💡 **Pro Tips:**
        
        - **Start Simple**: Begin with a basic workflow and add complexity gradually
        - **Use Descriptive Names**: Clear agent and action names improve analysis accuracy
        - **Include Dependencies**: Proper dependency mapping enhances risk propagation analysis
        - **Specify Parameters**: Detailed parameters enable better vulnerability detection
        - **Consider MCP**: Include MCP-specific fields for advanced protocol analysis
        - **Security First**: Always use secure parameter references (vaults, configs)
        
        #### 📊 **Sample Files Available:**
        - `examples/mcp_a2a_workflow.yaml` - Complex MCP/A2A security pipeline
        - `examples/financial_analysis_workflow.yaml` - Financial services workflow
        """)
    
    elif page == "📤 Upload Workflow":
        st.markdown('<div class="main-header">📤 Upload Workflow</div>', unsafe_allow_html=True)
        
        # File upload
        uploaded_file = st.file_uploader(
            "Upload YAML Workflow File",
            type=['yaml', 'yml'],
            help="Upload a YAML file containing your workflow definition"
        )
        
        # Text area for direct input
        st.subheader("Or Paste YAML Content")
        yaml_content = st.text_area(
            "YAML Content",
            height=300,
            placeholder="Paste your workflow YAML content here..."
        )
        
        # Assessment parameters
        st.subheader("Assessment Parameters")
        col1, col2 = st.columns(2)
        
        with col1:
            base_cost = st.number_input(
                "Base Infrastructure Cost ($)",
                min_value=0,
                value=1000000,
                step=50000,
                help="Annual base infrastructure cost"
            )
            
            enterprise_size = st.selectbox(
                "Enterprise Size",
                ["small", "medium", "large", "enterprise"],
                index=3
            )
        
        with col2:
            industry = st.selectbox(
                "Industry Type",
                ["technology", "finance", "healthcare", "government", "manufacturing", "retail"],
                index=0
            )
        
        # Process assessment
        if st.button("🚀 Run MAESTRO Assessment", type="primary"):
            try:
                # Get YAML content
                if uploaded_file is not None:
                    yaml_content = uploaded_file.read().decode('utf-8')
                
                if not yaml_content.strip():
                    st.error("Please upload a file or paste YAML content.")
                    return
                
                # Validate YAML
                try:
                    yaml.safe_load(yaml_content)
                except yaml.YAMLError as e:
                    st.error(f"Invalid YAML format: {e}")
                    return
                
                # Run assessment
                with st.spinner("Running MAESTRO assessment..."):
                    engine = MAESTROEngine()
                    
                    # Apply custom parameters if configured
                    if st.session_state.custom_parameters:
                        # Here you would modify the engine's parameters
                        pass
                    
                    report = engine.assess_workflow_from_yaml(
                        yaml_content,
                        base_infrastructure_cost=base_cost,
                        enterprise_size=enterprise_size,
                        industry=industry
                    )
                    
                    st.session_state.assessment_report = report
                
                st.success("✅ Assessment completed successfully!")
                st.info("Navigate to 📊 Assessment Results to view the analysis.")
                
            except Exception as e:
                st.error(f"Assessment failed: {str(e)}")
    
    elif page == "⚙️ Configure Parameters":
        st.markdown('<div class="main-header">⚙️ Configure Risk Model Parameters</div>', unsafe_allow_html=True)
        
        st.markdown("""
        The quantitative risk model relies on configurable parameters. You can use:
        - **Default Values**: Fixed values based on industry standards
        - **Custom Values**: Your organization-specific parameters
        """)
        
        # Toggle for custom parameters
        use_custom = st.checkbox("Enable Custom Parameters", value=False)
        
        if use_custom:
            st.warning("⚠️ Custom parameters will affect risk calculations. Ensure values are validated.")
            
            # Layer Weights Configuration
            st.subheader("🏗️ MAESTRO Layer Weights")
            st.info("These weights determine the relative importance of each layer in risk calculations.")
            
            layer_weights = {}
            total_weight = 0
            
            for layer in MAESTROLayer:
                default_weight = MAESTRO_LAYER_WEIGHTS[layer]
                weight = st.slider(
                    f"{layer.name.replace('_', ' ').title()}",
                    min_value=0.0,
                    max_value=1.0,
                    value=default_weight,
                    step=0.01,
                    key=f"weight_{layer.name}"
                )
                layer_weights[layer] = weight
                total_weight += weight
            
            # Validate weights sum to 1.0
            if abs(total_weight - 1.0) > 0.01:
                st.error(f"⚠️ Layer weights must sum to 1.0 (current: {total_weight:.2f})")
            else:
                st.success(f"✅ Layer weights sum to {total_weight:.2f}")
            
            # Exposure Index Configuration
            st.subheader("🔍 MAESTRO Exposure Index")
            st.info("Exposure index represents how exposed each layer is to external threats.")
            
            exposure_index = {}
            for layer in MAESTROLayer:
                default_exposure = MAESTRO_EXPOSURE_INDEX[layer]
                exposure = st.slider(
                    f"{layer.name.replace('_', ' ').title()} Exposure",
                    min_value=0.0,
                    max_value=1.0,
                    value=default_exposure,
                    step=0.01,
                    key=f"exposure_{layer.name}"
                )
                exposure_index[layer] = exposure
            
            # Cost Weights Configuration
            st.subheader("💰 MAESTRO Cost Weights")
            st.info("Cost weights represent the relative cost of securing each layer.")
            
            cost_weights = {}
            total_cost_weight = 0
            
            for layer in MAESTROLayer:
                default_cost = MAESTRO_COST_WEIGHTS[layer]
                cost = st.slider(
                    f"{layer.name.replace('_', ' ').title()} Cost Weight",
                    min_value=0.0,
                    max_value=1.0,
                    value=default_cost,
                    step=0.01,
                    key=f"cost_{layer.name}"
                )
                cost_weights[layer] = cost
                total_cost_weight += cost
            
            # Validate cost weights
            if abs(total_cost_weight - 1.0) > 0.01:
                st.error(f"⚠️ Cost weights must sum to 1.0 (current: {total_cost_weight:.2f})")
            else:
                st.success(f"✅ Cost weights sum to {total_cost_weight:.2f}")
            
            # Save custom parameters
            if st.button("💾 Save Custom Parameters"):
                if abs(total_weight - 1.0) <= 0.01 and abs(total_cost_weight - 1.0) <= 0.01:
                    st.session_state.custom_parameters = {
                        'layer_weights': layer_weights,
                        'exposure_index': exposure_index,
                        'cost_weights': cost_weights
                    }
                    st.success("✅ Custom parameters saved successfully!")
                else:
                    st.error("❌ Cannot save parameters: weights must sum to 1.0")
        
        else:
            st.info("Using default parameter values based on industry standards and CSA guidelines.")
            
            # Display default values
            st.subheader("📋 Default Parameter Values")
            
            # Create dataframe for display
            param_data = []
            for layer in MAESTROLayer:
                param_data.append({
                    'Layer': layer.name.replace('_', ' ').title(),
                    'Layer Weight': MAESTRO_LAYER_WEIGHTS[layer],
                    'Exposure Index': MAESTRO_EXPOSURE_INDEX[layer],
                    'Cost Weight': MAESTRO_COST_WEIGHTS[layer]
                })
            
            df = pd.DataFrame(param_data)
            st.dataframe(df, use_container_width=True)
            
            # Reset to defaults
            if st.button("🔄 Reset to Defaults"):
                st.session_state.custom_parameters = {
                    'layer_weights': dict(MAESTRO_LAYER_WEIGHTS),
                    'exposure_index': dict(MAESTRO_EXPOSURE_INDEX),
                    'cost_weights': dict(MAESTRO_COST_WEIGHTS)
                }
                st.success("✅ Parameters reset to default values!")
    
    elif page == "📊 Assessment Results":
        st.markdown('<div class="main-header">📊 Assessment Results</div>', unsafe_allow_html=True)
        
        if st.session_state.assessment_report is None:
            st.warning("No assessment report available. Please upload and assess a workflow first.")
            st.info("👈 Navigate to '📤 Upload Workflow' to begin your assessment.")
        else:
            display_assessment_results(st.session_state.assessment_report)
    
    elif page == "📄 Export Reports":
        st.markdown('<div class="main-header">📄 Export Reports</div>', unsafe_allow_html=True)
        
        if st.session_state.assessment_report is None:
            st.warning("No assessment report available to export.")
            st.info("👈 Navigate to '📤 Upload Workflow' to begin your assessment.")
        else:
            report = st.session_state.assessment_report
            
            st.subheader("📋 Available Export Formats")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # JSON Export
                st.markdown("### 📄 JSON Report")
                st.info("Complete assessment data in JSON format")
                
                if st.button("📥 Download JSON Report"):
                    engine = MAESTROEngine()
                    json_report = engine.export_report_json(report)
                    
                    st.download_button(
                        label="💾 Download JSON",
                        data=json_report,
                        file_name=f"maestro_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
            
            with col2:
                # Executive Summary
                st.markdown("### 📊 Executive Summary")
                st.info("High-level summary for stakeholders")
                
                if st.button("📥 Generate Executive Summary"):
                    exec_summary = report.executive_summary
                    summary_text = f"""
# MAESTRO Threat Assessment - Executive Summary

## Workflow Overview
- **Name**: {exec_summary['workflow_overview']['name']}
- **Agents**: {exec_summary['workflow_overview']['agents_count']}
- **Steps**: {exec_summary['workflow_overview']['steps_count']}
- **Data Flows**: {exec_summary['workflow_overview']['data_flows_count']}

## Risk Assessment
- **Overall Risk Level**: {exec_summary['risk_summary']['overall_risk_level'].upper()}
- **WEI Score**: {exec_summary['risk_summary']['wei_score']}
- **RPS Score**: {exec_summary['risk_summary']['rps_score']}
- **Total Vulnerabilities**: {exec_summary['risk_summary']['total_vulnerabilities']}
- **Critical Vulnerabilities**: {exec_summary['risk_summary']['critical_vulnerabilities']}

## Cost Analysis
- **Base Infrastructure Cost**: ${exec_summary['cost_summary']['base_cost']:,.0f}
- **Total Cost of Ownership**: ${exec_summary['cost_summary']['total_tco']:,.0f}
- **Security Investment**: ${exec_summary['cost_summary']['security_investment']:,.0f}
- **Cost Increase**: {exec_summary['cost_summary']['cost_increase_percentage']:.1f}%
- **ROI**: {exec_summary['cost_summary']['roi_percentage']:.1f}%

## Key Recommendations
"""
                    for i, rec in enumerate(report.recommendations[:5], 1):
                        summary_text += f"{i}. {rec}\n"
                    
                    st.download_button(
                        label="💾 Download Summary",
                        data=summary_text,
                        file_name=f"maestro_executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown"
                    )
            
            # Display current report summary
            st.subheader("📋 Current Report Summary")
            exec_summary = report.executive_summary
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Risk Level", exec_summary['risk_summary']['overall_risk_level'].upper())
                st.metric("Vulnerabilities", exec_summary['risk_summary']['total_vulnerabilities'])
            
            with col2:
                st.metric("WEI Score", f"{exec_summary['risk_summary']['wei_score']:.2f}")
                st.metric("RPS Score", f"{exec_summary['risk_summary']['rps_score']:.2f}")
            
            with col3:
                cost_increase = exec_summary['cost_summary']['cost_increase_percentage']
                st.metric("Cost Increase", f"{cost_increase:.1f}%")
                roi = exec_summary['cost_summary']['roi_percentage']
                st.metric("ROI", f"{roi:.1f}%")

if __name__ == "__main__":
    main() 
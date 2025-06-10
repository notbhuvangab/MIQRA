"""
MAESTRO Threat Assessment Framework - Streamlit GUI
Interactive web interface for threat assessment with enhanced workflow visualization
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
        VULNERABILITY_LAYER_MAPPING
    )
    from maestro_threat_assessment.web.workflow_visualizer import render_workflow_diagram
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
        'exposure_index': dict(MAESTRO_EXPOSURE_INDEX)
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
            # Object-based structure with Monte Carlo results
            layers.append(layer_name.replace('_', ' ').title())
            
            # Handle Monte Carlo results (with .mean attribute) or regular numbers
            wei_contrib = score_data.wei_contribution
            if hasattr(wei_contrib, 'mean'):
                wei_scores.append(wei_contrib.mean)
            else:
                wei_scores.append(wei_contrib)
                
            rps_contrib = score_data.rps_contribution  
            if hasattr(rps_contrib, 'mean'):
                rps_scores.append(rps_contrib.mean)
            else:
                rps_scores.append(rps_contrib)
                
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

def display_assessment_results(report):
    """Display comprehensive assessment results with enhanced visualization"""
    
    # Extract key metrics
    exec_summary = report.executive_summary
    
    st.markdown('<div class="main-header">📊 MAESTRO Assessment Results</div>', unsafe_allow_html=True)
    
    # Key Metrics Cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        wei_score = exec_summary['risk_summary']['wei_score']
        st.markdown(f"""
        <div class="metric-card">
            <h3>⚡ WEI Score</h3>
            <h2>{wei_score:.3f}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        rps_score = exec_summary['risk_summary']['rps_score']
        st.markdown(f"""
        <div class="metric-card">
            <h3>🌊 RPS Score</h3>
            <h2>{rps_score:.1f}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        risk_level = exec_summary['risk_summary']['overall_risk_level']
        risk_colors = {
            'LOW': '#10b981',
            'MEDIUM': '#f59e0b', 
            'HIGH': '#ef4444',
            'CRITICAL': '#dc2626'
        }
        risk_color = risk_colors.get(risk_level.upper(), '#6b7280')
        
        st.markdown(f"""
        <div class="metric-card">
            <h3>🎯 Risk Level</h3>
            <h2 style="color: {risk_color};">{risk_level.upper()}</h2>
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
    
    # Enhanced Workflow Visualization
    st.subheader("🔄 Enhanced Workflow Architecture")
    st.info("Interactive diagram showing agents, tools, and communication flows")
    
    # Get the original YAML content from session state
    if 'uploaded_yaml_content' in st.session_state:
        # Get vulnerabilities list for visualization
        all_vulnerabilities = []
        for layer_vulns in report.risk_assessment.vulnerabilities_by_layer.values():
            all_vulnerabilities.extend(layer_vulns)
        
        render_workflow_diagram(st.session_state.uploaded_yaml_content, all_vulnerabilities)
    else:
        st.warning("Original YAML content not available for enhanced visualization")
    
    # MAESTRO Layer Analysis
    st.subheader("🏗️ MAESTRO Layer Analysis")
    
    # Create layer analysis visualization
    layer_data = []
    vulnerability_counts = {}
    
    for layer_name, vulnerabilities in report.risk_assessment.vulnerabilities_by_layer.items():
        # Handle MAESTROLayer enum objects properly
        if hasattr(layer_name, 'name'):
            # It's a MAESTROLayer enum
            layer_display = layer_name.name.replace('_', ' ').title()
            layer_number = layer_name.name.split('_')[0]  # Get L1, L2, etc.
        else:
            # It's a string (fallback)
            layer_number = str(layer_name).replace('L', '').split(':')[0]
            layer_display = f"Layer {layer_number}"
        
        vulnerability_counts[layer_display] = len(vulnerabilities)
        
        for vuln in vulnerabilities:
            layer_data.append({
                'Layer': layer_display,
                'Severity': vuln.get('severity', 'unknown').title(),
                'Type': vuln.get('type', 'unknown'),
                'Description': vuln.get('description', 'No description')
            })
    
    if layer_data:
        df_layers = pd.DataFrame(layer_data)
        
        # Layer vulnerability count chart
        col1, col2 = st.columns(2)
        
        with col1:
            fig_count = px.bar(
                x=list(vulnerability_counts.keys()),
                y=list(vulnerability_counts.values()),
                title="Vulnerabilities by MAESTRO Layer",
                labels={'x': 'MAESTRO Layer', 'y': 'Vulnerability Count'},
                color=list(vulnerability_counts.values()),
                color_continuous_scale='Reds'
            )
            fig_count.update_layout(showlegend=False)
            st.plotly_chart(fig_count, use_container_width=True)
        
        with col2:
            # Severity distribution
            severity_counts = df_layers['Severity'].value_counts()
            fig_severity = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Vulnerability Severity Distribution",
                color_discrete_map={
                    'Critical': '#dc2626',
                    'High': '#ef4444',
                    'Medium': '#f59e0b',
                    'Low': '#10b981'
                }
            )
            st.plotly_chart(fig_severity, use_container_width=True)
        
        # Detailed layer breakdown
        st.subheader("📋 Detailed Vulnerability Breakdown")
        
        # Group by layer for display
        for layer in sorted(df_layers['Layer'].unique()):
            layer_vulns = df_layers[df_layers['Layer'] == layer]
            
            with st.expander(f"🏗️ {layer} ({len(layer_vulns)} vulnerabilities)"):
                for _, vuln in layer_vulns.iterrows():
                    severity = vuln['Severity'].lower()
                    severity_colors = {
                        'critical': '🔴',
                        'high': '🟠', 
                        'medium': '🟡',
                        'low': '🟢'
                    }
                    severity_icon = severity_colors.get(severity, '⚪')
                    
                    st.markdown(f"""
                    **{severity_icon} {vuln['Type'].replace('_', ' ').title()}** ({vuln['Severity']})
                    
                    {vuln['Description']}
                    """)
    
    # Risk Score Evolution (if multiple assessments exist)
    st.subheader("📈 Risk Assessment Summary")
    
    # Create summary metrics
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🎯 Risk Metrics:**")
        st.write(f"• **WEI Score:** {wei_score:.3f}")
        st.write(f"• **RPS Score:** {rps_score:.1f}")
        st.write(f"• **Risk Level:** {risk_level}")
        st.write(f"• **Total Vulnerabilities:** {total_vulns}")
        
        if hasattr(report.workflow, 'steps'):
            st.write(f"• **Workflow Steps:** {len(report.workflow.steps)}")
        if hasattr(report.workflow, 'agents'):
            agent_count = len([agent for agent in report.workflow.agents if agent])
            st.write(f"• **Agents Involved:** {agent_count}")
    
    with col2:
        st.markdown("**🏗️ MAESTRO Layer Coverage:**")
        layer_coverage = list(vulnerability_counts.keys())
        if layer_coverage:
            for layer in layer_coverage:
                count = vulnerability_counts[layer]
                st.write(f"• **{layer}:** {count} vulnerabilities")
        else:
            st.write("No layer-specific vulnerabilities detected")
    
    # Export Options
    st.subheader("📤 Export Options")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📋 Download Summary", type="secondary"):
            summary_data = {
                'workflow_name': getattr(report.workflow, 'name', 'Unknown'),
                'assessment_timestamp': datetime.now().isoformat(),
                'risk_metrics': {
                    'wei_score': wei_score,
                    'rps_score': rps_score,
                    'risk_level': risk_level,
                    'total_vulnerabilities': total_vulns
                },
                'vulnerabilities_by_layer': vulnerability_counts
            }
            
            st.download_button(
                label="Download JSON Summary",
                data=json.dumps(summary_data, indent=2),
                file_name=f"maestro_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("📊 Download Full Report", type="secondary"):
            # This would generate a full PDF report
            st.info("Full PDF report generation coming soon!")
    
    with col3:
        if st.button("🔄 Run New Assessment", type="primary"):
            # Clear session state to start fresh
            for key in list(st.session_state.keys()):
                if key.startswith('assessment_'):
                    del st.session_state[key]
            st.rerun()

def main():
    """Main Streamlit application"""
    
    # Page configuration and styling (existing code remains the same)
    
    # Sidebar
    with st.sidebar:
        st.markdown('<div class="sidebar-header">🛡️ MAESTRO Framework</div>', unsafe_allow_html=True)
        
        page = st.selectbox(
            "Navigate",
            ["🏠 Home", "📤 Upload Workflow", "📊 View Results", "⚙️ Configuration"],
            index=0
        )
        
        st.markdown("---")
        st.markdown("### ℹ️ About MAESTRO")
        st.markdown("""
        **MAESTRO** is a comprehensive threat assessment framework for AI agent workflows.
        
        **Key Features:**
        - 🔍 Multi-layer security analysis
        - 🎯 Risk quantification (WEI/RPS)
        - 🔄 Interactive workflow visualization
        - 📊 Comprehensive reporting
        """)
    
    # Main content area
    if page == "🏠 Home":
        # Home page content (existing code remains the same)
        pass
        
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
        
        # Process assessment
        if st.button("🚀 Run MAESTRO Assessment", type="primary"):
            try:
                # Get YAML content
                if uploaded_file is not None:
                    yaml_content = uploaded_file.read().decode('utf-8')
                
                if not yaml_content.strip():
                    st.error("Please upload a file or paste YAML content.")
                    return
                
                # Store YAML content for visualization
                st.session_state.uploaded_yaml_content = yaml_content
                
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
                    
                    report = engine.assess_workflow_from_yaml(yaml_content)
                    
                    st.session_state.assessment_report = report
                
                st.success("✅ Assessment completed successfully!")
                st.info("Navigate to 'View Results' to see the comprehensive analysis.")
                
            except Exception as e:
                st.error(f"Assessment failed: {str(e)}")
                st.error("Please check your workflow format and try again.")
    
    elif page == "📊 View Results":
        if st.session_state.assessment_report:
            display_assessment_results(st.session_state.assessment_report)
        else:
            st.warning("No assessment results available. Please upload and analyze a workflow first.")
    
    elif page == "⚙️ Configuration":
        # Configuration page (existing code remains the same)
        pass

if __name__ == "__main__":
    main() 
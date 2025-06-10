"""
MAESTRO Threat Assessment Report Generator

Generates comprehensive security assessment reports in multiple formats:
- PDF reports with visualizations
- HTML interactive reports  
- JSON structured data
- CSV summary tables
"""

import os
import json
import csv
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import tempfile

# PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

# HTML generation
try:
    from jinja2 import Template, Environment, FileSystemLoader
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

# Visualization imports
from .charts import (
    RiskHeatmapGenerator,
    EvolutionGraphGenerator,
    ThresholdTuningMatrix,
    BaselineRadarChart
)


class ReportGenerator:
    """Generate comprehensive assessment reports in multiple formats"""
    
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.charts = {
            'heatmap': RiskHeatmapGenerator(),
            'evolution': EvolutionGraphGenerator(),
            'tuning': ThresholdTuningMatrix(),
            'radar': BaselineRadarChart()
        }
        
    def generate_pdf_report(self, assessment_data: Dict[str, Any], 
                          workflow_data: Any, output_path: str) -> None:
        """Generate comprehensive PDF report"""
        if not HAS_REPORTLAB:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
            
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        styles = getSampleStyleSheet()
        story = []
        
        # Title page
        story.extend(self._create_title_page(assessment_data, styles))
        
        # Executive summary
        story.extend(self._create_executive_summary(assessment_data, styles))
        
        # Risk assessment details
        story.extend(self._create_risk_assessment_section(assessment_data, styles))
        
        # Visualizations
        story.extend(self._create_visualizations_section(assessment_data, styles))
        
        # Recommendations
        story.extend(self._create_recommendations_section(assessment_data, styles))
        
        # Generate PDF
        doc.build(story)
        
    def generate_html_report(self, assessment_data: Dict[str, Any],
                           workflow_data: Any, output_path: str) -> None:
        """Generate interactive HTML report"""
        html_template = self._get_html_template()
        
        # Generate visualization files
        viz_files = self._generate_visualization_files(assessment_data)
        
        # Render HTML
        html_content = html_template.render(
            assessment_data=assessment_data,
            workflow_data=workflow_data,
            viz_files=viz_files,
            generation_time=datetime.now().isoformat()
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def generate_csv_report(self, assessment_data: Dict[str, Any], output_path: str) -> None:
        """Generate CSV summary report"""
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Header
            writer.writerow(['MAESTRO Threat Assessment Summary'])
            writer.writerow(['Generated:', datetime.now().isoformat()])
            writer.writerow([])
            
            # Risk scores
            writer.writerow(['Risk Assessment'])
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['WEI Score', assessment_data.get('wei_score', 'N/A')])
            writer.writerow(['RPS Score', assessment_data.get('rps_score', 'N/A')])
            writer.writerow(['Risk Level', assessment_data.get('risk_level', 'N/A')])
            writer.writerow([])
            
            # Vulnerabilities
            vulnerabilities = assessment_data.get('vulnerabilities', [])
            if vulnerabilities:
                writer.writerow(['Vulnerabilities'])
                writer.writerow(['Type', 'Severity', 'Layer', 'Description'])
                for vuln in vulnerabilities:
                    writer.writerow([
                        vuln.get('type', ''),
                        vuln.get('severity', ''),
                        vuln.get('layer', ''),
                        vuln.get('description', '')[:100] + '...' if len(vuln.get('description', '')) > 100 else vuln.get('description', '')
                    ])
            
    def _create_title_page(self, assessment_data: Dict[str, Any], styles) -> List:
        """Create title page elements"""
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        
        story.append(Paragraph("MAESTRO Threat Assessment Report", title_style))
        story.append(Spacer(1, 20))
        
        # Workflow info
        workflow_name = assessment_data.get('workflow_name', 'Unknown Workflow')
        story.append(Paragraph(f"<b>Workflow:</b> {workflow_name}", styles['Normal']))
        story.append(Paragraph(f"<b>Assessment Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 40))
        
        # Risk summary table
        risk_data = [
            ['Metric', 'Value', 'Status'],
            ['WEI Score', f"{assessment_data.get('wei_score', 0):.3f}", self._get_risk_status(assessment_data.get('wei_score', 0))],
            ['RPS Score', f"{assessment_data.get('rps_score', 0):.3f}", self._get_risk_status(assessment_data.get('rps_score', 0))],
            ['Risk Level', assessment_data.get('risk_level', 'Unknown').upper(), '']
        ]
        
        risk_table = Table(risk_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(risk_table)
        story.append(Spacer(1, 40))
        
        return story
    
    def _create_executive_summary(self, assessment_data: Dict[str, Any], styles) -> List:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # Risk overview
        wei_score = assessment_data.get('wei_score', 0)
        rps_score = assessment_data.get('rps_score', 0)
        total_vulns = len(assessment_data.get('vulnerabilities', []))
        
        summary_text = f"""
        This MAESTRO threat assessment analyzed the workflow for security vulnerabilities using the 
        comprehensive 7-layer framework. The assessment identified {total_vulns} potential security issues 
        with a Workflow Exploitability Index (WEI) of {wei_score:.3f} and Risk Propagation Score (RPS) 
        of {rps_score:.3f}.
        
        The overall risk level is classified as <b>{assessment_data.get('risk_level', 'Unknown').upper()}</b> 
        based on the MAESTRO threat modeling framework.
        """
        
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        return story
    
    def _create_risk_assessment_section(self, assessment_data: Dict[str, Any], styles) -> List:
        """Create detailed risk assessment section"""
        story = []
        
        story.append(Paragraph("Risk Assessment Details", styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # MAESTRO Layer Analysis
        story.append(Paragraph("MAESTRO Layer Analysis", styles['Heading2']))
        
        vulnerabilities_by_layer = assessment_data.get('vulnerabilities_by_layer', {})
        if vulnerabilities_by_layer:
            layer_data = [['Layer', 'Vulnerabilities', 'Risk Level']]
            
            layer_names = {
                'L1': 'Foundation Models',
                'L2': 'Data Operations', 
                'L3': 'Agent Frameworks',
                'L4': 'Deployment',
                'L5': 'Observability',
                'L6': 'Compliance',
                'L7': 'Ecosystem'
            }
            
            for layer_key, vulns in vulnerabilities_by_layer.items():
                layer_name = layer_names.get(layer_key, layer_key)
                vuln_count = len(vulns) if isinstance(vulns, list) else 0
                risk_level = self._calculate_layer_risk(vulns)
                layer_data.append([f"{layer_key}: {layer_name}", str(vuln_count), risk_level])
            
            layer_table = Table(layer_data, colWidths=[3*inch, 1*inch, 1.5*inch])
            layer_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(layer_table)
        
        story.append(Spacer(1, 20))
        return story
    
    def _create_visualizations_section(self, assessment_data: Dict[str, Any], styles) -> List:
        """Create visualizations section with charts"""
        story = []
        
        story.append(Paragraph("Security Analysis Visualizations", styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # Generate and embed visualizations
        viz_files = self._generate_visualization_files(assessment_data)
        
        for viz_name, viz_path in viz_files.items():
            if os.path.exists(viz_path):
                try:
                    story.append(Paragraph(f"{viz_name.replace('_', ' ').title()}", styles['Heading2']))
                    story.append(Image(viz_path, width=6*inch, height=4*inch))
                    story.append(Spacer(1, 20))
                except Exception as e:
                    story.append(Paragraph(f"Error loading {viz_name}: {str(e)}", styles['Normal']))
        
        return story
    
    def _create_recommendations_section(self, assessment_data: Dict[str, Any], styles) -> List:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("Security Recommendations", styles['Heading1']))
        story.append(Spacer(1, 12))
        
        recommendations = assessment_data.get('recommendations', [])
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
                story.append(Spacer(1, 6))
        else:
            # Generate default recommendations based on findings
            default_recs = self._generate_default_recommendations(assessment_data)
            for i, rec in enumerate(default_recs, 1):
                story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
                story.append(Spacer(1, 6))
        
        return story
    
    def _generate_visualization_files(self, assessment_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate visualization files and return their paths"""
        viz_files = {}
        
        try:
            # Risk heatmap
            heatmap_path = os.path.join(self.temp_dir, 'risk_heatmap.png')
            heatmap_fig = self.charts['heatmap'].generate_heatmap(assessment_data)
            heatmap_fig.write_image(heatmap_path, width=800, height=600, scale=2)
            viz_files['risk_heatmap'] = heatmap_path
            
            # Baseline radar chart if baseline data available
            if 'baseline_comparison' in assessment_data:
                radar_path = os.path.join(self.temp_dir, 'baseline_radar.png')
                radar_fig = self.charts['radar'].generate_radar_chart(assessment_data['baseline_comparison'])
                radar_fig.write_image(radar_path, width=800, height=600, scale=2)
                viz_files['baseline_radar'] = radar_path
                
        except Exception as e:
            print(f"Warning: Could not generate some visualizations: {e}")
        
        return viz_files
    
    def _get_risk_status(self, score: float) -> str:
        """Get risk status based on score"""
        if score >= 0.7:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_layer_risk(self, vulnerabilities) -> str:
        """Calculate risk level for a layer based on vulnerabilities"""
        if not vulnerabilities:
            return "LOW"
        
        if isinstance(vulnerabilities, list):
            critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
            high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
            
            if critical_count > 0:
                return "CRITICAL"
            elif high_count > 0:
                return "HIGH"
            elif len(vulnerabilities) > 2:
                return "MEDIUM"
            else:
                return "LOW"
        
        return "LOW"
    
    def _generate_default_recommendations(self, assessment_data: Dict[str, Any]) -> List[str]:
        """Generate default recommendations based on assessment data"""
        recommendations = []
        
        wei_score = assessment_data.get('wei_score', 0)
        rps_score = assessment_data.get('rps_score', 0)
        
        if wei_score > 0.5:
            recommendations.append("Implement additional input validation and sanitization measures")
            recommendations.append("Review and strengthen authentication mechanisms")
        
        if rps_score > 0.5:
            recommendations.append("Enhance network segmentation and access controls")
            recommendations.append("Implement comprehensive logging and monitoring")
        
        recommendations.extend([
            "Conduct regular security assessments using the MAESTRO framework",
            "Establish incident response procedures for detected threats",
            "Provide security training for development and operations teams"
        ])
        
        return recommendations
    
    def _get_html_template(self) -> Template:
        """Get HTML template for report generation"""
        html_template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MAESTRO Threat Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .section { margin: 30px 0; }
        .metric { display: inline-block; margin: 10px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .high-risk { background-color: #ffebee; }
        .medium-risk { background-color: #fff3e0; }
        .low-risk { background-color: #e8f5e8; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MAESTRO Threat Assessment Report</h1>
        <p><strong>Workflow:</strong> {{ assessment_data.get('workflow_name', 'Unknown') }}</p>
        <p><strong>Generated:</strong> {{ generation_time }}</p>
    </div>
    
    <div class="section">
        <h2>Risk Metrics</h2>
        <div class="metric">
            <h3>WEI Score</h3>
            <p>{{ "%.3f"|format(assessment_data.get('wei_score', 0)) }}</p>
        </div>
        <div class="metric">
            <h3>RPS Score</h3>
            <p>{{ "%.3f"|format(assessment_data.get('rps_score', 0)) }}</p>
        </div>
        <div class="metric">
            <h3>Risk Level</h3>
            <p>{{ assessment_data.get('risk_level', 'Unknown').upper() }}</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Vulnerabilities</h2>
        {% if assessment_data.get('vulnerabilities') %}
        <table>
            <thead>
                <tr><th>Type</th><th>Severity</th><th>Layer</th><th>Description</th></tr>
            </thead>
            <tbody>
                {% for vuln in assessment_data.vulnerabilities %}
                <tr>
                    <td>{{ vuln.get('type', 'Unknown') }}</td>
                    <td>{{ vuln.get('severity', 'Unknown') }}</td>
                    <td>{{ vuln.get('layer', 'Unknown') }}</td>
                    <td>{{ vuln.get('description', 'No description') }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No vulnerabilities detected.</p>
        {% endif %}
    </div>
</body>
</html>
        """
        
        return Template(html_template_str) 
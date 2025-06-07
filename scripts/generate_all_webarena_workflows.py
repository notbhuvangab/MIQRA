#!/usr/bin/env python3
"""
Master WebArena to MAESTRO Converter

This script runs both WebArena conversion approaches:
1. Sample-based converter with basic security features
2. Enhanced security-focused converter with comprehensive threat assessment

It also provides a summary of all generated workflows.
"""

import subprocess
import sys
from pathlib import Path
import yaml
from typing import Dict, List, Any
import argparse

class MasterWebArenaConverter:
    def __init__(self, output_dir: str = "examples"):
        self.output_dir = Path(output_dir)
        self.scripts_dir = Path("scripts")
        
    def run_basic_converter(self):
        """Run the basic WebArena converter"""
        print("=" * 60)
        print("🔄 Running Basic WebArena Converter")
        print("=" * 60)
        
        script_path = self.scripts_dir / "fetch_webarena_workflows.py"
        try:
            result = subprocess.run([
                sys.executable, str(script_path),
                "--output-dir", str(self.output_dir)
            ], capture_output=True, text=True, check=True)
            
            print(result.stdout)
            if result.stderr:
                print("Warnings:", result.stderr)
                
        except subprocess.CalledProcessError as e:
            print(f"Error running basic converter: {e}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
    
    def run_enhanced_converter(self, limit: int = 3):
        """Run the enhanced security-focused converter"""
        print("\n" + "=" * 60)
        print("🛡️ Running Enhanced Security Converter")
        print("=" * 60)
        
        script_path = self.scripts_dir / "fetch_real_webarena_configs.py"
        try:
            result = subprocess.run([
                sys.executable, str(script_path),
                "--output-dir", str(self.output_dir),
                "--limit", str(limit)
            ], capture_output=True, text=True, check=True)
            
            print(result.stdout)
            if result.stderr:
                print("Warnings:", result.stderr)
                
        except subprocess.CalledProcessError as e:
            print(f"Error running enhanced converter: {e}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
    
    def analyze_generated_workflows(self) -> Dict[str, Any]:
        """Analyze all generated workflows"""
        workflows = []
        
        for yaml_file in self.output_dir.glob("webarena_*.yaml"):
            try:
                with open(yaml_file, 'r') as f:
                    workflow = yaml.safe_load(f)
                    
                workflow_info = {
                    "filename": yaml_file.name,
                    "name": workflow["workflow"]["name"],
                    "category": workflow["workflow"]["metadata"]["category"],
                    "sensitivity": workflow["workflow"]["metadata"]["sensitivity"],
                    "step_count": len(workflow["workflow"]["steps"]),
                    "has_mcp": "mcp_version" in workflow["workflow"]["metadata"],
                    "has_a2a": "a2a_protocol" in workflow["workflow"]["metadata"],
                    "security_features": self._extract_security_features(workflow)
                }
                workflows.append(workflow_info)
                
            except Exception as e:
                print(f"Error analyzing {yaml_file.name}: {e}")
        
        return {
            "total_workflows": len(workflows),
            "workflows": workflows,
            "categories": list(set(w["category"] for w in workflows)),
            "security_coverage": self._analyze_security_coverage(workflows)
        }
    
    def _extract_security_features(self, workflow: Dict[str, Any]) -> List[str]:
        """Extract security features from workflow"""
        features = []
        
        # Check metadata for security indicators
        metadata = workflow["workflow"]["metadata"]
        if "threat_model" in metadata:
            features.append("threat_modeling")
        if "compliance_frameworks" in metadata:
            features.append("compliance_frameworks")
        
        # Check steps for security actions
        steps = workflow["workflow"]["steps"]
        security_keywords = [
            "auth", "security", "threat", "vulnerability", "encryption",
            "monitoring", "compliance", "incident", "forensic"
        ]
        
        for step in steps:
            agent_name = step.get("agent", "").lower()
            action_name = step.get("action", "").lower()
            
            for keyword in security_keywords:
                if keyword in agent_name or keyword in action_name:
                    if keyword not in features:
                        features.append(keyword)
        
        return features
    
    def _analyze_security_coverage(self, workflows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze security coverage across all workflows"""
        all_features = set()
        mcp_count = 0
        a2a_count = 0
        
        for workflow in workflows:
            all_features.update(workflow["security_features"])
            if workflow["has_mcp"]:
                mcp_count += 1
            if workflow["has_a2a"]:
                a2a_count += 1
        
        return {
            "unique_security_features": len(all_features),
            "security_features": sorted(list(all_features)),
            "mcp_coverage": f"{mcp_count}/{len(workflows)}",
            "a2a_coverage": f"{a2a_count}/{len(workflows)}"
        }
    
    def generate_summary_report(self) -> str:
        """Generate a comprehensive summary report"""
        analysis = self.analyze_generated_workflows()
        
        report = []
        report.append("# WebArena to MAESTRO Conversion Summary")
        report.append("=" * 50)
        report.append("")
        
        # Overview
        report.append("## 📊 Overview")
        report.append(f"- **Total Workflows Generated**: {analysis['total_workflows']}")
        report.append(f"- **Categories Covered**: {', '.join(analysis['categories'])}")
        report.append(f"- **MCP Protocol Coverage**: {analysis['security_coverage']['mcp_coverage']}")
        report.append(f"- **A2A Pattern Coverage**: {analysis['security_coverage']['a2a_coverage']}")
        report.append("")
        
        # Security Features
        report.append("## 🛡️ Security Features")
        report.append(f"- **Unique Security Features**: {analysis['security_coverage']['unique_security_features']}")
        for feature in analysis['security_coverage']['security_features']:
            report.append(f"  - {feature}")
        report.append("")
        
        # Workflow Details
        report.append("## 📋 Workflow Details")
        report.append("")
        
        # Group by category
        by_category = {}
        for workflow in analysis['workflows']:
            category = workflow['category']
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(workflow)
        
        for category, workflows in sorted(by_category.items()):
            report.append(f"### {category.title()} ({len(workflows)} workflows)")
            
            for workflow in workflows:
                report.append(f"- **{workflow['name']}**")
                report.append(f"  - File: `{workflow['filename']}`")
                report.append(f"  - Sensitivity: {workflow['sensitivity']}")
                report.append(f"  - Steps: {workflow['step_count']}")
                report.append(f"  - MCP: {'✅' if workflow['has_mcp'] else '❌'}")
                report.append(f"  - A2A: {'✅' if workflow['has_a2a'] else '❌'}")
                report.append(f"  - Security Features: {', '.join(workflow['security_features'])}")
                report.append("")
        
        # Usage Instructions
        report.append("## 🚀 Usage Instructions")
        report.append("")
        report.append("To run these workflows with the MAESTRO framework:")
        report.append("")
        report.append("```bash")
        report.append("# Basic assessment")
        report.append("python -m maestro_threat_assessment assess examples/webarena_shopping_101.yaml")
        report.append("")
        report.append("# Enhanced security assessment")
        report.append("python -m maestro_threat_assessment assess examples/webarena_security_shopping_201.yaml")
        report.append("")
        report.append("# GUI interface")
        report.append("python src/maestro_threat_assessment/web/streamlit_app.py")
        report.append("```")
        report.append("")
        
        # Future Enhancements
        report.append("## 🔮 Future Enhancements")
        report.append("")
        report.append("- Real-time GitHub API integration for latest WebArena configs")
        report.append("- Domain-specific threat intelligence integration")
        report.append("- Automated workflow validation and testing")
        report.append("- Integration with additional agent frameworks")
        report.append("- Enhanced MCP protocol implementations")
        
        return "\n".join(report)
    
    def run_full_conversion(self, enhanced_limit: int = 3):
        """Run both converters and generate summary"""
        print("🎯 Starting Complete WebArena to MAESTRO Conversion")
        print("=" * 60)
        
        # Run both converters
        self.run_basic_converter()
        self.run_enhanced_converter(enhanced_limit)
        
        # Generate and save summary
        print("\n" + "=" * 60)
        print("📝 Generating Summary Report")
        print("=" * 60)
        
        summary = self.generate_summary_report()
        
        summary_file = self.output_dir / "WEBARENA_CONVERSION_SUMMARY.md"
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        print(f"Summary saved to: {summary_file}")
        print("\n" + summary)

def main():
    parser = argparse.ArgumentParser(description="Master WebArena to MAESTRO converter")
    parser.add_argument("--output-dir", default="examples",
                       help="Output directory for workflows")
    parser.add_argument("--enhanced-limit", type=int, default=3,
                       help="Limit for enhanced converter")
    parser.add_argument("--basic-only", action="store_true",
                       help="Run only basic converter")
    parser.add_argument("--enhanced-only", action="store_true",
                       help="Run only enhanced converter")
    parser.add_argument("--summary-only", action="store_true",
                       help="Generate summary only")
    
    args = parser.parse_args()
    
    converter = MasterWebArenaConverter(args.output_dir)
    
    if args.summary_only:
        summary = converter.generate_summary_report()
        print(summary)
    elif args.basic_only:
        converter.run_basic_converter()
    elif args.enhanced_only:
        converter.run_enhanced_converter(args.enhanced_limit)
    else:
        converter.run_full_conversion(args.enhanced_limit)

if __name__ == "__main__":
    main() 
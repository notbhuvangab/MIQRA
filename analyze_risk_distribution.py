#!/usr/bin/env python3

import os
import subprocess
import re
import json

def extract_scores(workflow_file):
    """Extract WEI and RPS scores from maestro output"""
    try:
        result = subprocess.run(['./maestro', 'analyze-workflow', '-i', workflow_file, '-r', 'json'], 
                              capture_output=True, text=True)
        output = result.stdout
        
        # Extract WEI score
        wei_match = re.search(r'WEI Score: ([0-9.]+)', output)
        wei_score = float(wei_match.group(1)) if wei_match else 0.0
        
        # Extract RPS score  
        rps_match = re.search(r'RPS Score: ([0-9.]+)', output)
        rps_score = float(rps_match.group(1)) if rps_match else 0.0
        
        # Extract actual risk level
        risk_match = re.search(r'Risk Level: (.+)', output)
        actual_risk = risk_match.group(1).strip() if risk_match else "UNKNOWN"
        
        return wei_score, rps_score, actual_risk
    except Exception as e:
        print(f"Error analyzing {workflow_file}: {e}")
        return 0.0, 0.0, "ERROR"

def calculate_combined_risk(wei_score, rps_score):
    """Calculate combined risk using current formula"""
    return (wei_score * 0.7) + (rps_score / 30.0 * 0.3)

def categorize_risk(combined_score):
    """Categorize risk based on current thresholds"""
    if combined_score >= 0.75:
        return "🔴 CRITICAL RISK"
    elif combined_score >= 0.55:
        return "🟠 HIGH RISK"
    elif combined_score >= 0.30:
        return "🟡 MEDIUM RISK"
    else:
        return "🟢 LOW RISK"

def main():
    print("Risk Distribution Analysis")
    print("=" * 50)
    
    workflows = []
    
    # Analyze all workflows
    for i in range(1, 17):
        workflow_files = [f for f in os.listdir('examples') if f.startswith(f'{i:02d}_')]
        if workflow_files:
            workflow_file = f'examples/{workflow_files[0]}'
            
            # Extract expected risk from filename
            expected_risk = "unknown"
            if "_low_risk_" in workflow_file:
                expected_risk = "low"
            elif "_medium_risk_" in workflow_file:
                expected_risk = "medium"
            elif "_high_risk_" in workflow_file:
                expected_risk = "high"
            elif "_critical_risk_" in workflow_file:
                expected_risk = "critical"
            
            wei_score, rps_score, actual_risk = extract_scores(workflow_file)
            combined_score = calculate_combined_risk(wei_score, rps_score)
            predicted_risk = categorize_risk(combined_score)
            
            workflows.append({
                'id': i,
                'file': workflow_file,
                'expected': expected_risk,
                'wei_score': wei_score,
                'rps_score': rps_score,
                'combined_score': combined_score,
                'actual_risk': actual_risk,
                'predicted_risk': predicted_risk
            })
            
            print(f"{i:02d}. {expected_risk:8s} | Combined: {combined_score:.3f} | "
                  f"Predicted: {predicted_risk} | Actual: {actual_risk}")
    
    # Analyze accuracy
    print("\n" + "=" * 50)
    print("Accuracy Analysis:")
    print("=" * 50)
    
    correct = 0
    total = len(workflows)
    
    # Count risk level distribution
    risk_distribution = {'low': [], 'medium': [], 'high': [], 'critical': []}
    
    for w in workflows:
        risk_distribution[w['expected']].append(w['combined_score'])
        
        # Check if prediction matches expectation (simplified)
        expected_simplified = w['expected'].upper()
        actual_simplified = w['actual_risk'].split()[-2] if len(w['actual_risk'].split()) > 1 else w['actual_risk']
        
        if expected_simplified in actual_simplified:
            correct += 1
    
    accuracy = (correct / total) * 100 if total > 0 else 0
    print(f"Overall Accuracy: {correct}/{total} ({accuracy:.1f}%)")
    
    # Show distribution stats
    print("\nCombined Score Distribution by Expected Risk:")
    print("-" * 50)
    for risk_level, scores in risk_distribution.items():
        if scores:
            avg_score = sum(scores) / len(scores)
            min_score = min(scores)
            max_score = max(scores)
            print(f"{risk_level:8s}: avg={avg_score:.3f}, min={min_score:.3f}, max={max_score:.3f}")
    
    # Suggest new thresholds
    print("\nSuggested Threshold Adjustments:")
    print("-" * 50)
    
    all_low = [w['combined_score'] for w in workflows if w['expected'] == 'low']
    all_medium = [w['combined_score'] for w in workflows if w['expected'] == 'medium']
    all_high = [w['combined_score'] for w in workflows if w['expected'] == 'high']
    all_critical = [w['combined_score'] for w in workflows if w['expected'] == 'critical']
    
    if all_low and all_medium:
        low_high = max(all_low)
        medium_low = min(all_medium)
        suggested_low_medium = (low_high + medium_low) / 2
        print(f"Low/Medium boundary: {suggested_low_medium:.3f} (current: 0.30)")
    
    if all_medium and all_high:
        medium_high = max(all_medium)
        high_low = min(all_high)
        suggested_medium_high = (medium_high + high_low) / 2
        print(f"Medium/High boundary: {suggested_medium_high:.3f} (current: 0.55)")
    
    if all_high and all_critical:
        high_high = max(all_high)
        critical_low = min(all_critical)
        suggested_high_critical = (high_high + critical_low) / 2
        print(f"High/Critical boundary: {suggested_high_critical:.3f} (current: 0.75)")

if __name__ == "__main__":
    main() 
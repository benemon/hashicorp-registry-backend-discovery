#!/usr/bin/env python3
"""
Compare HashiCorp registry backend scan results using cached previous results.

This script compares the current scan results with the cached previous scan
to detect changes in S3 backend infrastructure endpoints.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional

def load_json_file(file_path: str) -> Optional[Dict]:
    """Load and parse a JSON file, returning None if it fails or if file is empty."""
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            if not content:  # Check if file is empty
                print(f"File {file_path} is empty")
                return None
            return json.loads(content)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading {file_path}: {e}")
        return None

def is_valid_scan_data(data: Dict) -> bool:
    """Check if the loaded JSON data has the expected structure of a scan result."""
    if not data:
        return False
    
    # Check for required fields in scan data
    required_fields = ["summary", "discovery_timestamp"]
    for field in required_fields:
        if field not in data:
            print(f"Invalid scan data: missing '{field}' field")
            return False
    
    # Check if summary has expected structure
    if not isinstance(data.get("summary"), dict):
        print(f"Invalid scan data: 'summary' is not a dictionary")
        return False
    
    return True

def is_json(text: str) -> bool:
    """Check if a string is valid JSON."""
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        return False

def extract_summary_data(data: Dict) -> Dict:
    """Extract comparable summary data from backend scan results."""
    if not data or 'summary' not in data:
        return {}
    
    summary = data['summary']
    
    # Sort S3 endpoints for consistent comparison
    s3_endpoints = sorted(summary.get('s3_endpoints', []))
    
    return {
        's3_endpoint_count': summary.get('s3_endpoint_count', 0),
        's3_endpoints': s3_endpoints,
        'tags_analyzed': len(data.get('tags', {})),
        'total_layers': sum(len(tag_data.get('layers', [])) for tag_data in data.get('tags', {}).values())
    }

def compare_summaries(current: Dict, previous: Dict) -> Tuple[bool, List[str]]:
    """Compare two summary dictionaries and return (has_changes, change_descriptions)."""
    changes = []
    has_changes = False
    
    # Compare S3 endpoint count
    current_count = current.get('s3_endpoint_count', 0)
    previous_count = previous.get('s3_endpoint_count', 0)
    
    if current_count != previous_count:
        has_changes = True
        changes.append(f"S3 endpoint count changed: {previous_count} → {current_count}")
    
    # Compare S3 endpoints (order-independent)
    current_endpoints = set(current.get('s3_endpoints', []))
    previous_endpoints = set(previous.get('s3_endpoints', []))
    
    added_endpoints = current_endpoints - previous_endpoints
    removed_endpoints = previous_endpoints - current_endpoints
    
    if added_endpoints:
        has_changes = True
        changes.append(f"New S3 endpoints detected: {', '.join(sorted(added_endpoints))}")
    
    if removed_endpoints:
        has_changes = True
        changes.append(f"S3 endpoints no longer found: {', '.join(sorted(removed_endpoints))}")
    
    # Compare other metrics (informational)
    current_tags = current.get('tags_analyzed', 0)
    previous_tags = previous.get('tags_analyzed', 0)
    
    if current_tags != previous_tags:
        changes.append(f"Tags analyzed changed: {previous_tags} → {current_tags}")
    
    current_layers = current.get('total_layers', 0)
    previous_layers = previous.get('total_layers', 0)
    
    if current_layers != previous_layers:
        changes.append(f"Total layers analyzed changed: {previous_layers} → {current_layers}")
    
    return has_changes, changes

def generate_comparison_report(current_data: Dict, previous_data: Optional[Dict], 
                             changes: List[str]) -> str:
    """Generate a detailed markdown comparison report."""
    
    current_summary = extract_summary_data(current_data)
    previous_summary = extract_summary_data(previous_data) if previous_data else {}
    
    current_time = current_data.get('discovery_timestamp', 'Unknown')
    previous_time = previous_data.get('discovery_timestamp', 'Unknown') if previous_data else 'No previous scan'
    
    # Check if this is the first run
    is_first_run = not previous_data
    
    report = f"""## Detailed Backend Comparison Report

### Scan Information
- **Current Scan:** {current_time}
- **Previous Scan:** {previous_time}
- **Repository:** {current_data.get('repository', 'Unknown')}

### Summary of Changes
"""
    
    if is_first_run:
        report += "- 🚀 First run - establishing baseline for future comparisons\n"
    elif changes:
        for change in changes:
            report += f"- ⚠️ {change}\n"
    else:
        report += "- ✅ No significant changes detected\n"
    
    report += f"""
### Current Backend State
- **S3 Endpoints:** {current_summary.get('s3_endpoint_count', 0)}
- **Tags Analyzed:** {current_summary.get('tags_analyzed', 0)}
- **Total Layers:** {current_summary.get('total_layers', 0)}

### S3 Backend Endpoints
"""
    
    if current_summary.get('s3_endpoints'):
        for endpoint in current_summary['s3_endpoints']:
            report += f"- `{endpoint}`\n"
    else:
        report += "- None detected\n"
    
    if previous_data:
        report += f"""
### Previous Backend State (for comparison)
- **S3 Endpoints:** {previous_summary.get('s3_endpoint_count', 0)}
- **Tags Analyzed:** {previous_summary.get('tags_analyzed', 0)}
- **Total Layers:** {previous_summary.get('total_layers', 0)}
"""
    
    return report

def main():
    """Main comparison logic using cached results."""
    
    # File paths for current and previous scans
    current_file = "results/current-scan.json"
    previous_file = "results/current-scan.json.backup"
    
    # Check if the current_file exists and has valid content before backing it up
    if os.path.exists(current_file):
        try:
            with open(current_file, 'r') as f:
                content = f.read().strip()
            
            # Only backup if file has content and is valid JSON
            if content and is_json(content):
                with open(current_file, 'r') as src, open(previous_file, 'w') as dest:
                    dest.write(content)
                print(f"INFO: Successfully copied restored cache to {previous_file}")
            else:
                print(f"INFO: Restored cache file exists but is empty or invalid, skipping backup")
                # Remove the backup file if it exists to avoid comparing with invalid data
                if os.path.exists(previous_file):
                    os.remove(previous_file)
        except Exception as e:
            print(f"WARNING: Failed to backup restored cache: {e}")
    
    # Load current results
    current_data = load_json_file(current_file)
    if not current_data:
        print(f"ERROR: Could not load current results from {current_file}")
        sys.exit(1)
    
    # Load previous results (may not exist on first run)
    previous_data = load_json_file(previous_file)
    is_first_run = not previous_data or not is_valid_scan_data(previous_data)

    if is_first_run:
        print("INFO: No valid previous scan results found (first run)")
        # Set output for GitHub Actions
        with open(os.environ.get('GITHUB_OUTPUT', '/dev/null'), 'a') as f:
            f.write(f"changes_detected=false\n")
            f.write(f"first_run=true\n")  # Add a new output parameter
        
        # Still generate a report for the first run
        report = generate_comparison_report(current_data, None, ["This is the first run - establishing baseline"])
        os.makedirs("results", exist_ok=True)
        with open("results/comparison-report.md", "w") as f:
            f.write(report)
        
        print("INFO: First run completed, baseline established for future comparisons")
        sys.exit(0)
    
    print(f"INFO: Comparing current scan with previous cached results")
    
    # Extract and compare summaries
    current_summary = extract_summary_data(current_data)
    previous_summary = extract_summary_data(previous_data)
    
    has_changes, changes = compare_summaries(current_summary, previous_summary)
    
    # Generate detailed report
    report = generate_comparison_report(current_data, previous_data, changes)
    
    # Save report
    os.makedirs("results", exist_ok=True)
    with open("results/comparison-report.md", "w") as f:
        f.write(report)
    
    # Output results
    if has_changes:
        print("ALERT: Changes detected in HashiCorp registry backend infrastructure!")
        print("\nChanges:")
        for change in changes:
            print(f"  - {change}")
        print(f"\nDetailed report saved to: results/comparison-report.md")
        
        # Set output for GitHub Actions
        with open(os.environ.get('GITHUB_OUTPUT', '/dev/null'), 'a') as f:
            f.write(f"changes_detected=true\n")
    else:
        print("INFO: No significant changes detected")
        with open(os.environ.get('GITHUB_OUTPUT', '/dev/null'), 'a') as f:
            f.write(f"changes_detected=false\n")
    
    print(f"\nComparison completed successfully")

if __name__ == "__main__":
    main()
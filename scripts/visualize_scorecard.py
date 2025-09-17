#!/usr/bin/env python3
"""
OWASP Benchmark Scorecard Visualizer

Creates HTML visualization of Elise assessment results.
"""

import json
import sys
from pathlib import Path

def create_scorecard_html(job_dir, output_file="scorecard.html"):
    """Create HTML scorecard visualization."""
    
    # Read scorecard data
    scorecard_file = Path(job_dir) / "scorecard.txt"
    if not scorecard_file.exists():
        print(f"❌ Scorecard file not found: {scorecard_file}")
        return False
    
    # Parse scorecard
    with open(scorecard_file) as f:
        lines = f.readlines()
    
    # Extract metrics
    tp = fp = fn = tn = 0
    precision = recall = f1 = 0.0
    
    for line in lines:
        if line.startswith("TP="):
            tp = int(line.split("=")[1].split()[0])
        elif line.startswith("FP="):
            fp = int(line.split("=")[1].split()[0])
        elif line.startswith("FN="):
            fn = int(line.split("=")[1].split()[0])
        elif line.startswith("TN="):
            tn = int(line.split("=")[1].split()[0])
        elif line.startswith("Precision="):
            precision = float(line.split("=")[1].split()[0])
        elif line.startswith("Recall="):
            recall = float(line.split("=")[1].split()[0])
        elif line.startswith("F1="):
            f1 = float(line.split("=")[1].split()[0])
    
    # Read assessment results for detailed breakdown
    results_file = Path(job_dir) / "assessment_results.json"
    vulnerabilities = []
    if results_file.exists():
        with open(results_file) as f:
            data = json.load(f)
            vulnerabilities = data.get('results', [])
    
    # Create HTML
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elise OWASP Benchmark Scorecard</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.8;
            font-size: 1.1em;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .metric-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }}
        .metric-card:hover {{
            transform: translateY(-5px);
        }}
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .metric-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .tp {{ color: #27ae60; }}
        .fp {{ color: #e74c3c; }}
        .fn {{ color: #f39c12; }}
        .tn {{ color: #3498db; }}
        .precision {{ color: #9b59b6; }}
        .recall {{ color: #e67e22; }}
        .f1 {{ color: #1abc9c; }}
        .chart-container {{
            padding: 30px;
        }}
        .confusion-matrix {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            max-width: 400px;
            margin: 0 auto;
        }}
        .confusion-cell {{
            padding: 20px;
            text-align: center;
            border-radius: 10px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        .confusion-cell.actual-positive {{
            background: #e8f5e8;
            color: #27ae60;
        }}
        .confusion-cell.actual-negative {{
            background: #e8f4fd;
            color: #3498db;
        }}
        .confusion-cell.predicted-positive {{
            background: #fdf2e8;
            color: #e67e22;
        }}
        .confusion-cell.predicted-negative {{
            background: #f8f9fa;
            color: #6c757d;
        }}
        .vulnerabilities {{
            padding: 30px;
            background: white;
        }}
        .vuln-list {{
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #e9ecef;
            border-radius: 10px;
        }}
        .vuln-item {{
            padding: 15px;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .vuln-item:last-child {{
            border-bottom: none;
        }}
        .vuln-url {{
            font-family: monospace;
            color: #2c3e50;
        }}
        .vuln-family {{
            background: #e74c3c;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            text-transform: uppercase;
        }}
        .summary {{
            background: #2c3e50;
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .summary h2 {{
            margin: 0 0 20px 0;
            font-size: 1.8em;
        }}
        .summary p {{
            margin: 10px 0;
            font-size: 1.1em;
            opacity: 0.9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Elise Security Assessment</h1>
            <p>OWASP Benchmark Scorecard - Job {Path(job_dir).name}</p>
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <div class="metric-value tp">{tp}</div>
                <div class="metric-label">True Positives</div>
            </div>
            <div class="metric-card">
                <div class="metric-value fp">{fp}</div>
                <div class="metric-label">False Positives</div>
            </div>
            <div class="metric-card">
                <div class="metric-value fn">{fn}</div>
                <div class="metric-label">False Negatives</div>
            </div>
            <div class="metric-card">
                <div class="metric-value tn">{tn}</div>
                <div class="metric-label">True Negatives</div>
            </div>
            <div class="metric-card">
                <div class="metric-value precision">{precision:.1%}</div>
                <div class="metric-label">Precision</div>
            </div>
            <div class="metric-card">
                <div class="metric-value recall">{recall:.1%}</div>
                <div class="metric-label">Recall</div>
            </div>
            <div class="metric-card">
                <div class="metric-value f1">{f1:.1%}</div>
                <div class="metric-label">F1-Score</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h2 style="text-align: center; margin-bottom: 30px;">Confusion Matrix</h2>
            <div class="confusion-matrix">
                <div class="confusion-cell actual-positive">
                    <div>TP: {tp}</div>
                    <div style="font-size: 0.8em; margin-top: 5px;">Correctly Identified Vulnerabilities</div>
                </div>
                <div class="confusion-cell predicted-positive">
                    <div>FP: {fp}</div>
                    <div style="font-size: 0.8em; margin-top: 5px;">False Alarms</div>
                </div>
                <div class="confusion-cell predicted-negative">
                    <div>FN: {fn}</div>
                    <div style="font-size: 0.8em; margin-top: 5px;">Missed Vulnerabilities</div>
                </div>
                <div class="confusion-cell actual-negative">
                    <div>TN: {tn}</div>
                    <div style="font-size: 0.8em; margin-top: 5px;">Correctly Identified Safe</div>
                </div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>🔍 Detected Vulnerabilities ({len(vulnerabilities)} total)</h2>
            <div class="vuln-list">
                {''.join([f'''
                <div class="vuln-item">
                    <div class="vuln-url">{vuln.get('target', {}).get('url', 'Unknown URL')}</div>
                    <div class="vuln-family">{vuln.get('family', 'Unknown')}</div>
                </div>
                ''' for vuln in vulnerabilities[:50]])}
                {f'<div style="padding: 20px; text-align: center; color: #666;">... and {len(vulnerabilities) - 50} more vulnerabilities</div>' if len(vulnerabilities) > 50 else ''}
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 Assessment Summary</h2>
            <p><strong>Precision:</strong> {precision:.1%} - {precision:.1%} of findings were correct</p>
            <p><strong>Recall:</strong> {recall:.1%} - Found {recall:.1%} of actual vulnerabilities</p>
            <p><strong>F1-Score:</strong> {f1:.1%} - Overall performance metric</p>
            <p><strong>Total Findings:</strong> {tp + fp} vulnerabilities detected</p>
            <p><strong>Accuracy:</strong> {((tp + tn) / (tp + fp + fn + tn)):.1%} overall accuracy</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Write HTML file
    with open(output_file, 'w') as f:
        f.write(html)
    
    print(f"✅ HTML scorecard created: {output_file}")
    return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python visualize_scorecard.py <job_directory>")
        sys.exit(1)
    
    job_dir = sys.argv[1]
    create_scorecard_html(job_dir)

# 🔍 Elise Evaluation Framework

Comprehensive evaluation system for Elise vulnerability scanner with comparison against conventional tools.

## 📊 Evaluation Metrics

The framework implements 5 key metrics as requested:

### 1. **Recall@Param (↑)** — "How many real vulns did we actually catch?"
- Measures the percentage of known vulnerabilities that were successfully detected
- Calculated per vulnerability type (XSS, SQLi, Redirect)
- Higher is better (0.0 - 1.0)

### 2. **Median Probes per Confirm (↓)** — "How many shots until the first hit?"
- Measures efficiency of payload selection and ranking
- Lower is better (fewer attempts = more efficient)
- Calculated per vulnerability type

### 3. **TTFC (median / p90) (↓)** — Time-to-First-Confirm
- Measures speed of vulnerability detection
- Provides both median and 90th percentile times
- Lower is better (faster detection)

### 4. **P@5 (↑) for payload ranking** — "Is the ML ranking actually helpful?"
- Measures effectiveness of ML-based payload ranking
- Precision@5: How many of the top 5 ranked payloads are actually relevant
- Higher is better (0.0 - 1.0)

### 5. **FPR on safe cases (↓)** — False-Positive Rate
- Measures false positive rate on known safe endpoints
- Lower is better (fewer false alarms)
- Critical for production use

## 🛠️ Baseline Tools Comparison

The framework compares Elise against conventional tools:

- **XSStrike** - XSS detection
- **SQLmap** - SQL injection detection  
- **FFUF** - Parameter fuzzing and endpoint discovery

## 🚀 Quick Start

### 1. Basic Evaluation

```bash
# Evaluate against lab environment (includes ground truth)
python scripts/evaluate_elise.py --target https://localhost:5001 --lab-mode

# Evaluate against custom target with ground truth
python scripts/evaluate_elise.py --target https://example.com --ground-truth examples/ground_truth_example.json
```

### 2. Comparative Evaluation

```bash
# Compare against all baseline tools
python scripts/evaluate_elise.py --target https://example.com --compare-all --ground-truth examples/ground_truth_example.json

# Compare against specific tools
python scripts/evaluate_elise.py --target https://example.com --tools xsser sqlmap --ground-truth examples/ground_truth_example.json
```

### 3. Report Generation

```bash
# Generate HTML report (default)
python scripts/evaluate_elise.py --target https://example.com --format html

# Generate Markdown report
python scripts/evaluate_elise.py --target https://example.com --format markdown

# Generate JSON report
python scripts/evaluate_elise.py --target https://example.com --format json
```

## 📁 Output Structure

```
evaluation_results/
├── evaluation_report.html          # Main report
├── elise_metrics_<timestamp>.json  # Elise metrics
├── elise_vulns_<timestamp>.json    # Detected vulnerabilities
├── comparative_evaluation_<timestamp>.json  # Full results
└── lab_ground_truth.json          # Lab ground truth (if --lab-mode)
```

## 📋 Ground Truth Format

Ground truth files should follow this JSON structure:

```json
{
  "vulnerabilities": [
    {
      "endpoint": "https://example.com/search",
      "parameter": "q", 
      "vulnerability_type": "xss",
      "payload": "<script>alert('XSS')</script>",
      "context": {
        "injection_mode": "query",
        "content_type": "text/html"
      }
    }
  ],
  "safe_endpoints": [
    {
      "endpoint": "https://example.com/",
      "parameter": "index"
    }
  ]
}
```

## 🔧 Advanced Usage

### Custom Evaluation Configuration

```python
from backend.evaluation import EvaluationConfig, ComparativeEvaluator

config = EvaluationConfig(
    target_url="https://example.com",
    ground_truth_file=Path("ground_truth.json"),
    output_dir=Path("results"),
    include_baseline_tools=True,
    tools_to_run=["xsser", "sqlmap"],
    evaluation_timeout=1800
)

evaluator = ComparativeEvaluator()
results = evaluator.run_comparative_evaluation(config)
```

### Programmatic Metrics Access

```python
from backend.evaluation import EvaluationMetrics, GroundTruth

# Load ground truth
ground_truth = GroundTruth()
ground_truth.add_vulnerability("https://example.com", "param", "xss", "payload")

# Load detected vulnerabilities
detected_vulns = [...]  # List of VulnerabilityInstance objects

# Compute metrics
metrics_calc = EvaluationMetrics()
result = metrics_calc.evaluate(ground_truth, detected_vulns)

print(f"Recall: {result.recall_at_param}")
print(f"Median Probes: {result.median_probes_per_confirm}")
print(f"TTFC: {result.time_to_first_confirm}")
print(f"Precision@5: {result.precision_at_5}")
print(f"FPR: {result.false_positive_rate}")
```

## 📊 Report Features

### HTML Reports
- Interactive tables with performance indicators
- Color-coded metrics (🟢 Excellent, 🟡 Good, 🔴 Needs Improvement)
- Side-by-side tool comparisons
- Summary statistics dashboard

### Markdown Reports
- Clean, readable format
- Perfect for documentation and sharing
- GitHub-compatible tables

### JSON Reports
- Machine-readable format
- Complete evaluation data
- Easy integration with CI/CD pipelines

## 🎯 Lab Environment

The framework includes built-in ground truth for the lab environment:

- **XSS vulnerabilities**: 4 different contexts (HTML, Attribute, JS, Stored)
- **SQL injection**: 3 different types (Error-based, Login, JSON API)
- **Open redirect**: 1 vulnerability
- **Safe endpoints**: 4 known safe cases

Use `--lab-mode` to automatically use this ground truth.

## 🔍 Baseline Tool Requirements

### XSStrike
```bash
pip install xsser
```

### SQLmap
```bash
git clone https://github.com/sqlmapproject/sqlmap.git
# Add to PATH or specify tool path
```

### FFUF
```bash
# Download from https://github.com/ffuf/ffuf/releases
# Add to PATH or specify tool path
```

## 📈 Interpreting Results

### Excellent Performance
- **Recall**: ≥ 0.9 (90%+ of vulnerabilities found)
- **Precision@5**: ≥ 0.8 (80%+ of top 5 payloads relevant)
- **FPR**: ≤ 0.05 (5% or fewer false positives)
- **Median Probes**: ≤ 2 (very efficient)
- **TTFC**: ≤ 30s (fast detection)

### Good Performance
- **Recall**: 0.7-0.9 (70-90% of vulnerabilities found)
- **Precision@5**: 0.6-0.8 (60-80% of top 5 payloads relevant)
- **FPR**: 0.05-0.1 (5-10% false positives)
- **Median Probes**: 2-5 (reasonably efficient)
- **TTFC**: 30-60s (acceptable speed)

### Needs Improvement
- **Recall**: < 0.7 (less than 70% of vulnerabilities found)
- **Precision@5**: < 0.6 (less than 60% of top 5 payloads relevant)
- **FPR**: > 0.1 (more than 10% false positives)
- **Median Probes**: > 5 (inefficient)
- **TTFC**: > 60s (slow detection)

## 🚨 Troubleshooting

### Common Issues

1. **Baseline tools not found**
   - Install required tools or specify custom paths
   - Check tool executables are in PATH

2. **Ground truth file not found**
   - Use `--lab-mode` for built-in ground truth
   - Create custom ground truth file following the format

3. **Evaluation timeout**
   - Increase timeout with `--timeout` parameter
   - Reduce target scope or complexity

4. **No vulnerabilities detected**
   - Check target URL is accessible
   - Verify ground truth matches actual target
   - Review Elise configuration and strategy

### Debug Mode

Enable detailed logging:

```bash
export PYTHONPATH=/path/to/elise
python -m logging.basicConfig level=DEBUG
python scripts/evaluate_elise.py --target https://example.com --lab-mode
```

## 🔮 Future Enhancements

- [ ] Interactive charts and visualizations
- [ ] CI/CD integration examples
- [ ] Automated baseline tool installation
- [ ] Custom metric definitions
- [ ] Performance regression detection
- [ ] Multi-target batch evaluation
- [ ] Real-time evaluation dashboard

---

**Need help?** Check the examples in `examples/` directory or create an issue for support.

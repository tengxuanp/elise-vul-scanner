# Elise Unified Workflow

This document describes the unified workflow system for Elise that orchestrates the complete build/train/reassess/export/scorecard pipeline.

## Overview

The unified workflow script (`scripts/elise_workflow.py`) provides a single entry point to run the complete Elise vulnerability assessment pipeline, from data preparation to final scoring.

## Workflow Steps

### 1. **Build** - Dataset Preparation
- Builds training datasets from evidence files
- Creates ranker datasets for ML training
- Generates XSS payload ranking datasets

### 2. **Train** - Model Training
- Trains XSS ranker models
- Trains general ranker models (SQLi, XSS, Redirect)
- Saves trained models for inference

### 3. **Reassess** - Vulnerability Assessment
- Crawls target application to discover endpoints
- Assesses endpoints for vulnerabilities using trained models
- Generates evidence files with findings

### 4. **Export** - Results Export
- Exports findings to ZAP JSON format
- Prepares results for external tools

### 5. **Scorecard** - Performance Evaluation
- Generates OWASP Benchmark scorecard
- Computes precision/recall/F1 metrics
- Provides performance evaluation

## Usage

### Command Line Interface

```bash
# Run complete workflow (using venv)
./venv/bin/python scripts/elise_workflow.py --workflow full --target https://localhost:8443/benchmark/ --insecure-tls

# Run build and train only
./venv/bin/python scripts/elise_workflow.py --workflow build-train --target https://example.com

# Run reassessment only (requires existing job)
./venv/bin/python scripts/elise_workflow.py --workflow reassess --job-id existing_job_id

# Run export and scorecard only
./venv/bin/python scripts/elise_workflow.py --workflow export-scorecard --job-id existing_job_id
```

**Note:** Always use `./venv/bin/python` to ensure you're using the virtual environment with all dependencies.

### Makefile Targets

```bash
# Run complete workflow
make workflow-full

# Run build and train
make workflow-build-train

# Run reassessment (requires JOB_ID)
make workflow-reassess JOB_ID=your_job_id

# Run export and scorecard (requires JOB_ID)
make workflow-export-scorecard JOB_ID=your_job_id
```

**Note:** The Makefile targets use the virtual environment (`./venv/bin/python`) automatically.

## Configuration Options

### Crawl Options
- `--max-depth`: Maximum crawl depth (default: 5)
- `--max-endpoints`: Maximum endpoints to discover (default: 2000)
- `--max-seconds`: Maximum crawl time in seconds (default: 900)
- `--insecure-tls`: Allow insecure TLS connections

### Assessment Options
- `--strategy`: Assessment strategy (default: auto)
- `--ctx-mode`: XSS context mode (default: always)
- `--sqli-ml-mode`: SQLi ML mode (default: never)
- `--top-k`: Top K payloads to test (default: 7)

### Export Options
- `--export-base-url`: Base URL for ZAP export (default: https://localhost:8443/benchmark)

## Workflow Types

### `full`
Runs all steps: build → train → reassess → export → scorecard

### `build-train`
Runs only: build → train

### `reassess`
Runs only: crawl → reassess (requires existing job or target)

### `export-scorecard`
Runs only: export → scorecard (requires existing job)

## Output Files

The workflow creates the following output structure:

```
backend/data/jobs/{job_id}/
├── endpoints.json              # Discovered endpoints
├── assessment_results.json     # Assessment results
├── zap_export.json            # ZAP format export
├── scorecard.txt              # Scorecard output
└── workflow_state.json        # Workflow state and metadata
```

## Examples

### Complete OWASP Benchmark Assessment

```bash
# Start OWASP Benchmark
make benchmark-up

# Wait for benchmark to be ready, then run full workflow
make workflow-full
```

### Custom Target Assessment

```bash
./venv/bin/python scripts/elise_workflow.py \
  --workflow full \
  --target https://example.com \
  --max-depth 3 \
  --max-endpoints 500 \
  --strategy auto \
  --ctx-mode always
```

### Resume Workflow

```bash
# If you have an existing job, you can resume from reassessment
./venv/bin/python scripts/elise_workflow.py \
  --workflow reassess \
  --job-id workflow-1234567890
```

## Troubleshooting

### Common Issues

1. **TLS Certificate Errors**
   - Use `--insecure-tls` flag for self-signed certificates

2. **Missing Expected Results**
   - The script will automatically download OWASP Benchmark expected results
   - If download fails, manually download and place at `/tmp/expectedresults-1.2.csv`

3. **No Endpoints Found**
   - Check that the target URL is accessible
   - Verify crawl options (max-depth, max-endpoints)
   - Check for JavaScript-heavy applications that might need different crawl settings

4. **ML Model Training Fails**
   - Ensure sufficient evidence data exists
   - Check that evidence files are in the correct format
   - Verify ML dependencies are installed

### Debug Mode

For detailed logging, set the `ELISE_DEBUG` environment variable:

```bash
ELISE_DEBUG=1 ./venv/bin/python scripts/elise_workflow.py --workflow full --target https://example.com
```

## Integration

The workflow script can be integrated into CI/CD pipelines, automated testing, or research workflows. Each step can be run independently, allowing for flexible pipeline composition.

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
- name: Run Elise Assessment
  run: |
    make benchmark-up
    sleep 60  # Wait for benchmark to start
    make workflow-full
```

### Research Workflow

```bash
# Train models on new data
./venv/bin/python scripts/elise_workflow.py --workflow build-train --target https://research-target.com

# Assess multiple targets with same models
for target in target1.com target2.com target3.com; do
  ./venv/bin/python scripts/elise_workflow.py --workflow reassess --target $target
done
```

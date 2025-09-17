# Elise Unified Workflow - Quick Reference

## 🚀 Quick Start

```bash
# Run complete workflow (build/train/reassess/export/scorecard)
make workflow-full

# Run build and train only
make workflow-build-train

# Run reassessment only (requires existing job)
make workflow-reassess JOB_ID=your_job_id
```

## 📋 What You Get

The unified workflow script (`scripts/elise_workflow.py`) orchestrates these steps:

1. **Build** - Creates training datasets from evidence files
2. **Train** - Trains ML models (XSS ranker, general rankers)
3. **Reassess** - Crawls target and assesses for vulnerabilities
4. **Export** - Exports results to ZAP JSON format
5. **Scorecard** - Generates OWASP Benchmark performance metrics

## 🔧 Key Features

- **Virtual Environment Support** - Automatically uses `./venv/bin/python`
- **Graceful Error Handling** - Continues workflow even if some steps fail
- **Flexible Workflows** - Run individual steps or complete pipeline
- **State Persistence** - Saves workflow state and results
- **Makefile Integration** - Easy-to-use targets

## 📁 Output Structure

```
backend/data/jobs/{job_id}/
├── endpoints.json              # Discovered endpoints
├── assessment_results.json     # Assessment results
├── zap_export.json            # ZAP format export
├── scorecard.txt              # Scorecard output
└── workflow_state.json        # Workflow state and metadata
```

## 🎯 Common Use Cases

### Complete OWASP Benchmark Assessment
```bash
make benchmark-up
# Wait for benchmark to start
make workflow-full
```

### Custom Target Assessment
```bash
./venv/bin/python scripts/elise_workflow.py \
  --workflow full \
  --target https://example.com \
  --max-depth 3 \
  --max-endpoints 500
```

### Research Workflow
```bash
# Train models first
make workflow-build-train

# Then assess multiple targets
for target in target1.com target2.com target3.com; do
  ./venv/bin/python scripts/elise_workflow.py --workflow reassess --target $target
done
```

## ⚠️ Notes

- The workflow gracefully handles missing training data
- Use `--insecure-tls` for self-signed certificates
- All commands use the virtual environment automatically
- Workflow state is saved for resuming interrupted runs

For detailed documentation, see `WORKFLOW_README.md`.

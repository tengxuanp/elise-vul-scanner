# Elise System Workflow Documentation

## System Architecture Overview

```
Frontend (Next.js) ↔ Backend (FastAPI) ↔ ML Models ↔ Evidence Storage
     ↓                    ↓                    ↓              ↓
  UI Components    Assessment Engine    Ranker/Classifier   SQLite DB
```

## Complete Assessment Workflow

### 1. Assessment Request Flow

#### Step 1: User Initiates Assessment
- User selects strategy (Smart-XSS, Full-Smart, Rules-Only, Exhaustive)
- User configures ML settings (XSS tau, SQLi short-circuit, etc.)
- User provides target URL or selects persisted endpoints

#### Step 2: Strategy Configuration
```javascript
// Frontend sends strategy config
{
  strategy: "smart_xss",
  families: ["xss", "sqli"],
  xss: { ml_mode: "auto", tau_ml: 0.80, topk: 3 },
  sqli: { dialect_mode: "rules", short_circuit: {enabled: true, M: 12, K: 20} }
}
```

#### Step 3: Backend Processing Pipeline

**A. Job Context Setup**
```python
# Set up job-scoped aggregator
set_current_job(job_id)
reset_aggregator()
```

**B. Crawling**
```python
crawl_result = crawl_site(
    target_url=target_url,
    max_depth=2,
    max_endpoints=30,
    submit_get_forms=True,
    submit_post_forms=True,
    click_buttons=True
)
```

**C. Target Enumeration**
- Extract all parameters from crawled endpoints
- Create `Target` objects for each parameter
- Filter out non-applicable targets (no parameters)

### 2. Per-Target Processing Pipeline

For each target, the system follows this sequence:

#### Phase 1: Probe Execution
```python
# Run probes based on strategy
families_to_probe = ["xss", "sqli", "redirect"] if probe_enabled(plan, family)
probe_bundle = run_probes(target, families_to_probe, plan, ctx_mode, meta)
```

**Probe Types:**
- **XSS Probe**: Tests for reflection and context detection
- **SQLi Probe**: Tests for error-based and timing-based signals  
- **Redirect Probe**: Tests for redirect influence

#### Phase 2: Vulnerability Confirmation
```python
# Check if probes confirmed vulnerability
probe_result = _confirmed_family(probe_bundle)
if probe_result:
    fam, reason_code = probe_result
    # Create evidence row for probe-confirmed findings
```

#### Phase 3: ML Payload Ranking (if applicable)
```python
# Build features for ML ranking
features = build_features(ctx)

# Rank payloads using ML or defaults
ranked = rank_payloads(fam, features, top_k=top_k, ml_mode=ctx_mode)
```

**ML Ranking Logic:**
- **XSS**: Uses ML ranking when `ml_mode` is "auto", "always", or "force_ml"
- **SQLi**: Uses rule-based ranking (no ML)
- **Redirect**: Uses rule-based ranking (no ML)

#### Phase 4: Payload Injection
```python
for attempt_idx, cand in enumerate(ranked):
    payload = cand.get("payload")
    score = cand.get("score")
    p_cal = cand.get("p_cal")
    rank_source = cand.get("rank_source")
    
    # Inject payload
    inj = inject_once(target, fam, payload)
    
    # Check for vulnerability confirmation
    if fam == "sqli":
        decision, reason_code, extras = decide_sqli(signals, payload, target, confirm_helper)
    else:
        # Use family-specific decision logic
```

### 3. ML State Tracking

The system now properly tracks ML state throughout the pipeline:

```python
ml_state = {
    "rank_source": rank_source,           # "ml", "defaults", "probe_only"
    "ranker_active": rank_source in ["ml", "ctx_pool"],
    "classifier_used": rank_source in ["ml", "ctx_pool"] and p_cal is not None,
    "p_cal": p_cal if classifier_used else None,
    "skip_reason": payload_skip_reason    # "model_unavailable", "features_missing", etc.
}
```

### 4. Evidence Creation

For each confirmed vulnerability:

```python
ev = EvidenceRow.from_injection(
    target, fired_family, probe_bundle, cand, inj,
    rank_source=payload_rank_source,
    ml_family=fam,
    ml_proba=p_cal,
    ml_threshold=threshold,
    model_tag=model_tag
)

# Add honest ML telemetry
ev.telemetry["ml"] = ml_state
```

### 5. Event Aggregation

The system tracks all events in a job-scoped aggregator:

```python
# Record attempts
record_probe_attempt(target_id, family, success)
record_inject_attempt(target_id, family, success)

# Build truthful summary
summary = aggregator.build_summary(results)
```

### 6. Frontend Rendering

The frontend renders results with honest ML state:

```javascript
// Only show p_cal when classifier actually ran
{result.ml?.classifier_used && result.ml_proba != null ? 
  result.ml_proba.toFixed(2) : "—"}

// Show appropriate rank source
<RankSourceBadge rank_source={result.rank_source} />

// Show honest ML chip
<MLChip 
  rank_source={result.rank_source} 
  ml_proba={result.ml_proba} 
  ml={result.ml} 
/>
```

## Key Decision Points

### Strategy Enforcement
- **Rules-Only**: Probes only, no injections
- **Smart-XSS**: XSS uses ML ranking, SQLi uses rules
- **Full-Smart**: Both XSS and SQLi use ML ranking
- **Exhaustive**: All families, maximum ML usage

### ML Mode Semantics
- **"auto"**: Use ML if available, fallback to defaults
- **"always"**: Force ML usage (may fail if unavailable)
- **"never"**: Always use defaults
- **"force_ml"**: Force ML with context awareness

### Family Purity
- XSS signals never influence SQLi decisions
- SQLi signals never influence XSS decisions
- Each family has its own decision logic

## Data Flow Summary

```
Target URL → Crawl → Enumerate Parameters → 
For Each Parameter:
  ├── Run Probes → Check Confirmation
  ├── Build Features → ML Ranking (if applicable)
  ├── Inject Payloads → Check Confirmation
  └── Create Evidence → Record Events
→ Aggregate Results → Build Summary → Return to Frontend
```

## Honest Reporting Principles

1. **ML State Truthfulness**: Only show `p_cal` when classifier actually ran
2. **Rank Source Accuracy**: Correctly report "ml", "defaults", or "probe_only"
3. **Skip Reason Tracking**: Explain why ML wasn't used when applicable
4. **Server-Side Summary**: All counters come from aggregator, not client computation
5. **Family Purity**: No cross-contamination between vulnerability families

## File Structure

```
backend/
├── modules/
│   ├── ml/
│   │   ├── infer_ranker.py      # ML payload ranking
│   │   └── feature_spec.py      # Feature extraction
│   ├── fuzzer_core.py           # Main assessment engine
│   ├── event_aggregator.py      # Event tracking
│   ├── evidence.py              # Evidence creation
│   └── targets.py               # Target enumeration
├── triage/
│   └── sqli_decider.py          # SQLi decision logic
└── routes/
    └── assess_routes.py         # Assessment API endpoints

frontend/
└── src/app/components/
    ├── FindingsTable.jsx        # Results display
    ├── SummaryPanel.jsx         # Summary display
    └── EvidenceModal.jsx        # Evidence details
```

## Recent Patches Applied

### 1. Fixed XSS ranker to actually run and return proper rank_source
- Fixed feature vector conversion in `_features_to_vector()`
- Enhanced `rank_payloads()` with proper `skip_reason` tracking
- Fixed ML model integration

### 2. Fixed classifier honesty - only show p_cal when classifier actually ran
- Updated ML state tracking in `fuzzer_core.py`
- Fixed evidence creation to properly track `classifier_used` state
- Enhanced ML state structure with `skip_reason` tracking

### 3. Fixed SQLi URL suppression to read real param values
- Verified URL suppression logic in `sqli_decider.py`
- Confirmed parameter checking for URL-like patterns

### 4. Ensured server-side summary is the only truth source
- Added job context setup in `run_job()` and `assess_endpoints()`
- Enhanced aggregator integration for all assessment jobs
- Maintained SSOT principle

### 5. Updated frontend to render chips truthfully without client math
- Fixed MLChip component to only show `p_cal` when `classifier_used === true`
- Enhanced ML state handling for all scenarios
- Fixed probability display in table columns
- Maintained server-side summary usage

This workflow ensures that the system provides accurate, honest reporting about what ML components were used and when, while maintaining the flexibility to handle different strategies and fallback scenarios gracefully.

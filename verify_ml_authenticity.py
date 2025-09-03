#!/usr/bin/env python3

from modules.fuzzer_core import _rank_payloads_for_family
from modules.fuzzer_core import _ranker_predict

print('🔍 VERIFYING ML SCORE AUTHENTICITY')
print('=' * 50)

# Test with the same data structure as your fuzzer
feats = {
    'url': 'http://localhost:8082/rest/products/search',
    'method': 'GET',
    'content_type': 'application/json',
    'target_param': 'q',
    'control_value': 'test'
}

print('1️⃣ Testing family ranking (this generates the ML Ranker scores)...')
try:
    recs, meta = _rank_payloads_for_family(feats, 'sqli', top_n=3)
    print('✅ Family ranking successful!')
    print(f'   Used path: {meta.get("used_path")}')
    print(f'   Enhanced: {meta.get("enhanced")}')
    print(f'   Ranker score: {meta.get("ranker_score")}')
    print(f'   Model IDs: {meta.get("model_ids")}')
    print(f'   Features: {meta.get("feature_dim_total")}')
    print(f'   Family probs: {meta.get("family_probs")}')
    
    # Check if this looks like real ML data
    if meta.get('used_path') == 'enhanced_ml':
        print('✅ This is REAL enhanced ML data!')
    elif meta.get('used_path') == 'fallback':
        print('❌ This is FALLBACK data (not real ML)!')
    else:
        print(f'⚠️  Unknown path: {meta.get("used_path")}')
        
except Exception as e:
    print(f'❌ Family ranking failed: {e}')

print('\n2️⃣ Testing individual ML prediction...')
features = {
    'payload_family_used': 'sqli',
    'detector_hits': {'sql_error': True},
    'status_delta': 300,
    'len_delta': 283,
    'latency_ms_delta': 0,
    'method': 'GET',
    'in': 'query',
    'target_param': 'q',
    'url': 'http://localhost:8082/rest/products/search',
    'response': {'headers': {'content-type': 'application/json'}}
}

try:
    result = _ranker_predict(features)
    print('✅ Individual prediction successful!')
    print(f'   Source: {result.get("source")}')
    print(f'   Enhanced: {result.get("enhanced")}')
    print(f'   Model Type: {result.get("model_type")}')
    print(f'   Probability: {result.get("p")}')
    print(f'   Confidence: {result.get("confidence")}')
    
    # Check if this looks like real ML data
    if 'fallback' in str(result.get('source', '')):
        print('❌ This is FALLBACK data (not real ML)!')
    elif 'enhanced' in str(result.get('source', '')):
        print('✅ This is REAL enhanced ML data!')
    else:
        print(f'⚠️  Unknown source: {result.get("source")}')
        
except Exception as e:
    print(f'❌ Individual prediction failed: {e}')

print('\n🎯 AUTHENTICITY CHECK:')
print('   Real ML should show: used_path=enhanced_ml, source=enhanced_xgboost')
print('   Fallback would show: used_path=fallback, source=fallback')
print('   Synthetic would show: model_ids starting with "synthetic_"')

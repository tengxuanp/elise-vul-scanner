#!/usr/bin/env python3

from modules.fuzzer_core import _rank_payloads_for_family

print('🔍 TESTING ENHANCED ML INTEGRATION IN FUZZER')
print('=' * 60)

# Test with the same data structure as used in the fuzzer
feats = {
    'url': 'http://localhost:8082/rest/products/search',
    'method': 'GET',
    'content_type': 'application/json',
    'target_param': 'q',
    'control_value': 'test'
}

print('1️⃣ Testing enhanced ML ranking in fuzzer context...')
try:
    recs, meta = _rank_payloads_for_family(feats, 'sqli', top_n=3)
    print('✅ Enhanced ML ranking successful!')
    print(f'   Used path: {meta.get("used_path")}')
    print(f'   Enhanced: {meta.get("enhanced")}')
    print(f'   Confidence: {meta.get("confidence")}')
    print(f'   Uncertainty: {meta.get("uncertainty")}')
    print(f'   Results count: {len(recs)}')
    print(f'   First result: {recs[0] if recs else "None"}')
    
    # Check if this is real enhanced ML data
    if meta.get('used_path') == 'enhanced_ml':
        print('✅ This is REAL enhanced ML data!')
    else:
        print(f'❌ This is NOT enhanced ML data: {meta.get("used_path")}')
        
except Exception as e:
    print(f'❌ Enhanced ML ranking failed: {e}')
    import traceback
    traceback.print_exc()

print('\n2️⃣ Checking what the enhanced ML engine returns...')
try:
    from modules.ml.enhanced_inference import EnhancedInferenceEngine
    engine = EnhancedInferenceEngine()
    
    endpoint = {
        'url': 'http://localhost:8082/rest/products/search',
        'method': 'GET',
        'content_type': 'application/json'
    }
    param = {
        'name': 'q',
        'value': 'test',
        'loc': 'query'
    }
    
    # Test the rank_payloads method directly
    ranked = engine.rank_payloads(endpoint, param, 'sqli', ['test1', 'test2', 'test3'], top_k=3)
    print('✅ Enhanced ML engine rank_payloads successful!')
    print(f'   Returned {len(ranked)} results')
    print(f'   First result structure: {ranked[0] if ranked else "None"}')
    
except Exception as e:
    print(f'❌ Enhanced ML engine test failed: {e}')
    import traceback
    traceback.print_exc()

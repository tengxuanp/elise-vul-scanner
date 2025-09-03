#!/usr/bin/env python3

from modules.fuzzer_core import _rank_payloads_for_family

print('✅ Testing Fixed Enhanced ML Integration')
print('=' * 50)

feats = {
    'url': 'http://localhost:8082/test',
    'method': 'GET',
    'content_type': 'application/json',
    'target_param': 'test',
    'control_value': 'test'
}

try:
    recs, meta = _rank_payloads_for_family(feats, 'sqli', top_n=3)
    print('✅ Enhanced ML integration successful!')
    print(f'   Used path: {meta.get("used_path")}')
    print(f'   Enhanced: {meta.get("enhanced")}')
    print(f'   Ranker score: {meta.get("ranker_score")}')
    print(f'   Model IDs: {meta.get("model_ids")}')
    print(f'   Feature dim: {meta.get("feature_dim_total")}')
    print(f'   Family probs: {meta.get("family_probs")}')
    print(f'   Enhanced ML: {meta.get("enhanced_ml")}')
    
    # Check if we now have the complete metadata
    if meta.get('ranker_score') and meta.get('model_ids') and meta.get('feature_dim_total'):
        print('✅ Complete metadata structure achieved!')
    else:
        print('❌ Metadata still incomplete')
        
except Exception as e:
    print(f'❌ Test failed: {e}')
    import traceback
    traceback.print_exc()

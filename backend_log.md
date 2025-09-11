INFO:     127.0.0.1:55937 - "OPTIONS /api/crawl HTTP/1.1" 200 OK
[CRAWL] start=http://127.0.0.1:5001/ max_depth=2
[CRAWL] visiting depth=0 url=http://127.0.0.1:5001/
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/search?q=test
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/profile?name=test
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/script?msg=hello
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/notes
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/product?id=1
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/login
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/api/search-json
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/go?url=https://example.com
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/transfer
[CRAWL] enqueue depth=1 url=http://127.0.0.1:5001/healthz
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/search?q=test
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/profile?name=test
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/script?msg=hello
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/notes
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/product?id=1
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/login
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/api/search-json
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/go?url=https://example.com
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/transfer
[CRAWL] visiting depth=1 url=http://127.0.0.1:5001/healthz
INFO:     127.0.0.1:55937 - "POST /api/crawl HTTP/1.1" 200 OK
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
ASSESS_STRATEGY preset=legacy strategy=auto xss.ml=auto xss.topk=3
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/go?url=https://example.com param=url ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/go?url=https://example.com param=url canary_found=False
CANDIDATE_DEBUG xss probe exists, reflected=False
CANDIDATE_DEBUG xss gate passed but no reflection, skipping xss candidate
SQLI_SUPPRESSED URL-like param url suppressed for SQLi
CANDIDATE_DEBUG final candidates=[]
FAMILY_PROCESSING_DEBUG Processing family: redirect
XSS_PROBE_DEBUG fam=redirect has_probe_bundle=True has_xss=True
PAYLOAD_SELECTION_DEBUG fam=redirect - using probe-only ranking
RANK_PAYLOADS_CALLED fam=redirect xss_context=None xss_escaping=None ml_mode=never
RANK_PAYLOADS_ML_DISABLED fam=redirect
RANK_PAYLOADS_FALLBACK_DEFAULTS fam=redirect
RANK_PAYLOADS_DEFAULTS_SUCCESS fam=redirect count=3
RANKED_RESULT_DEBUG fam=redirect ranked_count=3 first_payload=https://example.com/
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/go?url=https://example.com, fam=redirect, payload=https://example.com/
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/login param=password ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/login param=password canary_found=False
CANDIDATE_DEBUG xss probe exists, reflected=False
CANDIDATE_DEBUG xss gate passed but no reflection, skipping xss candidate
CANDIDATE_DEBUG final candidates=['sqli']
FAMILY_PROCESSING_DEBUG Processing family: sqli
XSS_PROBE_DEBUG fam=sqli has_probe_bundle=True has_xss=True
PAYLOAD_SELECTION_DEBUG fam=sqli - using probe-only ranking
RANK_PAYLOADS_CALLED fam=sqli xss_context=None xss_escaping=None ml_mode=never
RANK_PAYLOADS_ML_DISABLED fam=sqli
RANK_PAYLOADS_FALLBACK_DEFAULTS fam=sqli
RANK_PAYLOADS_DEFAULTS_SUCCESS fam=sqli count=3
RANKED_RESULT_DEBUG fam=sqli ranked_count=3 first_payload='
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/login, fam=sqli, payload='
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
SQLI_STRICT_DECISION decision=positive reason=error_signature fired=sqli
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/login param=username ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/login param=username canary_found=False
CANDIDATE_DEBUG xss probe exists, reflected=False
CANDIDATE_DEBUG xss gate passed but no reflection, skipping xss candidate
CANDIDATE_DEBUG final candidates=['sqli']
FAMILY_PROCESSING_DEBUG Processing family: sqli
XSS_PROBE_DEBUG fam=sqli has_probe_bundle=True has_xss=True
PAYLOAD_SELECTION_DEBUG fam=sqli - using probe-only ranking
RANK_PAYLOADS_CALLED fam=sqli xss_context=None xss_escaping=None ml_mode=never
RANK_PAYLOADS_ML_DISABLED fam=sqli
RANK_PAYLOADS_FALLBACK_DEFAULTS fam=sqli
RANK_PAYLOADS_DEFAULTS_SUCCESS fam=sqli count=3
RANKED_RESULT_DEBUG fam=sqli ranked_count=3 first_payload='
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/login, fam=sqli, payload='
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
SQLI_STRICT_DECISION decision=positive reason=error_signature fired=sqli
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/notes param=content ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/notes param=content canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/notes param=content canary_pos=938
Failed to load context model: No module named 'numpy._core'
Using mock context model
Mock context model classes: ['attr' 'comment' 'css' 'html_body' 'js_string' 'json' 'url']
Failed to load escaping model: No module named 'numpy._core'
Using mock escaping model
Mock escaping model classes: ['html' 'js' 'raw' 'url']
XSS_ML_DEBUG ctx_mode=auto call_ml=True context_ml={'pred': 'js_string', 'proba': 0.6, 'all_probas': {'attr': 0.1, 'comment': 0.1, 'css': 0.1, 'html_body': 0.1, 'js_string': 0.6, 'json': 0.1, 'url': 0.1}} escaping_ml={'pred': 'url', 'proba': 0.4, 'all_probas': {'html': 0.2, 'js': 0.2, 'raw': 0.2, 'url': 0.4}}
XSS_FUSION rule: ctx=html_body src=rule_low_conf conf=0.7 r_conf=0.7 m_ctx=js_string m_p=0.6
XSS_PROBE_CONFIRMED continuing to ML payload selection for context optimization
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=html_body xss_context_final=html_body xss_context_source=rule_low_conf
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=html_body xss_escaping=raw ml_mode=auto
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 0, 'param_in_form': 1, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 1, 'probe_reflection_js': 0, 'probe_redirect_location_reflects': 0, 'status_class_2': 0, 'status_class_3': 1, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 1, 'ctx_attr': 0, 'ctx_js': 0, 'param_len': 7, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/notes, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/product?id=1 param=id ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/product?id=1 param=id canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/product?id=1 param=id canary_pos=27
XSS_ML_DEBUG ctx_mode=auto call_ml=True context_ml={'pred': 'js_string', 'proba': 0.6, 'all_probas': {'attr': 0.1, 'comment': 0.1, 'css': 0.1, 'html_body': 0.1, 'js_string': 0.6, 'json': 0.1, 'url': 0.1}} escaping_ml={'pred': 'url', 'proba': 0.4, 'all_probas': {'html': 0.2, 'js': 0.2, 'raw': 0.2, 'url': 0.4}}
XSS_FUSION rule: ctx=unknown src=rule_low_conf conf=0.3 r_conf=0.3 m_ctx=js_string m_p=0.6
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=unknown xss_context_final=unknown xss_context_source=rule_low_conf
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=unknown xss_escaping=raw ml_mode=auto
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 0, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 0, 'ctx_js': 0, 'param_len': 2, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/product?id=1, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/profile?name=test param=name ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/profile?name=test param=name canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/profile?name=test param=name canary_pos=428
XSS_FUSION rule: ctx=attr src=rule_high_conf conf=0.9 r_conf=0.9 m_ctx=None m_p=0.0
XSS_PROBE_CONFIRMED continuing to ML payload selection for context optimization
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=attr xss_context_final=attr xss_context_source=rule_high_conf
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=attr xss_escaping=raw ml_mode=auto
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 0, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 1, 'ctx_js': 0, 'param_len': 4, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/profile?name=test, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/script?msg=hello param=msg ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/script?msg=hello param=msg canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/script?msg=hello param=msg canary_pos=421
XSS_FUSION rule: ctx=js_string src=rule_high_conf conf=0.95 r_conf=0.95 m_ctx=None m_p=0.0
XSS_PROBE_CONFIRMED continuing to ML payload selection for context optimization
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=js_string xss_context_final=js_string xss_context_source=rule_high_conf
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=js_string xss_escaping=raw ml_mode=auto
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 1, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 0, 'ctx_js': 1, 'param_len': 3, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/script?msg=hello, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/search?q=test param=q ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/search?q=test param=q canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/search?q=test param=q canary_pos=427
XSS_ML_DEBUG ctx_mode=auto call_ml=True context_ml={'pred': 'js_string', 'proba': 0.6, 'all_probas': {'attr': 0.1, 'comment': 0.1, 'css': 0.1, 'html_body': 0.1, 'js_string': 0.6, 'json': 0.1, 'url': 0.1}} escaping_ml={'pred': 'url', 'proba': 0.4, 'all_probas': {'html': 0.2, 'js': 0.2, 'raw': 0.2, 'url': 0.4}}
XSS_FUSION rule: ctx=html_body src=rule_low_conf conf=0.7 r_conf=0.7 m_ctx=js_string m_p=0.6
XSS_PROBE_CONFIRMED continuing to ML payload selection for context optimization
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=html_body xss_context_final=html_body xss_context_source=rule_low_conf
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=html_body xss_escaping=raw ml_mode=auto
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 1, 'probe_reflection_js': 0, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 1, 'ctx_attr': 0, 'ctx_js': 0, 'param_len': 1, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/search?q=test, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
XSS_TELEMETRY ml_final=3 rs_ml=0 used=0 saved=0
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
INFO:     127.0.0.1:56314 - "POST /api/assess HTTP/1.1" 200 OK
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
INFO:     127.0.0.1:56314 - "GET /api/healthz HTTP/1.1" 200 OK
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
INFO:     127.0.0.1:56314 - "GET /api/healthz HTTP/1.1" 200 OK
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
ASSESS_STRATEGY preset=smart_xss legacy_strategy=auto xss.ml=force_ml xss.topk=3 sqli.dialect=rules sqli.topk=6 sqli.sc=on(M=12/K=20)
Found existing evidence files for job crawl-1757612046788-qkw8l6cvy with strategies {'auto'} and ctx_modes {'auto'}, but current strategy is auto and ctx_mode is force_ml. Re-running assessment.
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/go?url=https://example.com param=url ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/go?url=https://example.com param=url canary_found=False
CANDIDATE_DEBUG xss probe exists, reflected=False
CANDIDATE_DEBUG xss gate passed but no reflection, skipping xss candidate
SQLI_SUPPRESSED URL-like param url suppressed for SQLi
CANDIDATE_DEBUG final candidates=[]
FAMILY_PROCESSING_DEBUG Processing family: redirect
XSS_PROBE_DEBUG fam=redirect has_probe_bundle=True has_xss=True
PAYLOAD_SELECTION_DEBUG fam=redirect - using probe-only ranking
RANK_PAYLOADS_CALLED fam=redirect xss_context=None xss_escaping=None ml_mode=never
RANK_PAYLOADS_ML_DISABLED fam=redirect
RANK_PAYLOADS_FALLBACK_DEFAULTS fam=redirect
RANK_PAYLOADS_DEFAULTS_SUCCESS fam=redirect count=3
RANKED_RESULT_DEBUG fam=redirect ranked_count=3 first_payload=https://example.com/
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/go?url=https://example.com, fam=redirect, payload=https://example.com/
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/login param=password ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/login param=password canary_found=False
CANDIDATE_DEBUG xss probe exists, reflected=False
CANDIDATE_DEBUG xss gate passed but no reflection, skipping xss candidate
CANDIDATE_DEBUG final candidates=['sqli']
FAMILY_PROCESSING_DEBUG Processing family: sqli
XSS_PROBE_DEBUG fam=sqli has_probe_bundle=True has_xss=True
PAYLOAD_SELECTION_DEBUG fam=sqli - using probe-only ranking
RANK_PAYLOADS_CALLED fam=sqli xss_context=None xss_escaping=None ml_mode=never
RANK_PAYLOADS_ML_DISABLED fam=sqli
RANK_PAYLOADS_FALLBACK_DEFAULTS fam=sqli
RANK_PAYLOADS_DEFAULTS_SUCCESS fam=sqli count=3
RANKED_RESULT_DEBUG fam=sqli ranked_count=3 first_payload='
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/login, fam=sqli, payload='
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
SQLI_STRICT_DECISION decision=positive reason=error_signature fired=sqli
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/login param=username ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/login param=username canary_found=False
CANDIDATE_DEBUG xss probe exists, reflected=False
CANDIDATE_DEBUG xss gate passed but no reflection, skipping xss candidate
CANDIDATE_DEBUG final candidates=['sqli']
FAMILY_PROCESSING_DEBUG Processing family: sqli
XSS_PROBE_DEBUG fam=sqli has_probe_bundle=True has_xss=True
PAYLOAD_SELECTION_DEBUG fam=sqli - using probe-only ranking
RANK_PAYLOADS_CALLED fam=sqli xss_context=None xss_escaping=None ml_mode=never
RANK_PAYLOADS_ML_DISABLED fam=sqli
RANK_PAYLOADS_FALLBACK_DEFAULTS fam=sqli
RANK_PAYLOADS_DEFAULTS_SUCCESS fam=sqli count=3
RANKED_RESULT_DEBUG fam=sqli ranked_count=3 first_payload='
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=defaults
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/login, fam=sqli, payload='
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
SQLI_STRICT_DECISION decision=positive reason=error_signature fired=sqli
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/notes param=content ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/notes param=content canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/notes param=content canary_pos=938
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'js_string', 'proba': 0.6, 'all_probas': {'attr': 0.1, 'comment': 0.1, 'css': 0.1, 'html_body': 0.1, 'js_string': 0.6, 'json': 0.1, 'url': 0.1}} escaping_ml={'pred': 'url', 'proba': 0.4, 'all_probas': {'html': 0.2, 'js': 0.2, 'raw': 0.2, 'url': 0.4}}
XSS_FUSION force_ml: ctx=js_string src=ml conf=0.6
XSS_PROBE_CONFIRMED continuing to ML payload selection for context optimization
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=js_string xss_context_final=js_string xss_context_source=ml
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=js_string xss_escaping=url ml_mode=force_ml
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 0, 'param_in_form': 1, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 1, 'probe_redirect_location_reflects': 0, 'status_class_2': 0, 'status_class_3': 1, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 0, 'ctx_js': 1, 'param_len': 7, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/notes, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/product?id=1 param=id ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/product?id=1 param=id canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/product?id=1 param=id canary_pos=27
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'js_string', 'proba': 0.6, 'all_probas': {'attr': 0.1, 'comment': 0.1, 'css': 0.1, 'html_body': 0.1, 'js_string': 0.6, 'json': 0.1, 'url': 0.1}} escaping_ml={'pred': 'url', 'proba': 0.4, 'all_probas': {'html': 0.2, 'js': 0.2, 'raw': 0.2, 'url': 0.4}}
XSS_FUSION force_ml: ctx=js_string src=ml conf=0.6
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=js_string xss_context_final=js_string xss_context_source=ml
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=js_string xss_escaping=url ml_mode=force_ml
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 1, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 0, 'ctx_js': 1, 'param_len': 2, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/product?id=1, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/profile?name=test param=name ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/profile?name=test param=name canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/profile?name=test param=name canary_pos=428
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'js_string', 'proba': 0.6, 'all_probas': {'attr': 0.1, 'comment': 0.1, 'css': 0.1, 'html_body': 0.1, 'js_string': 0.6, 'json': 0.1, 'url': 0.1}} escaping_ml={'pred': 'url', 'proba': 0.4, 'all_probas': {'html': 0.2, 'js': 0.2, 'raw': 0.2, 'url': 0.4}}
XSS_FUSION force_ml: ctx=js_string src=ml conf=0.6
XSS_PROBE_CONFIRMED continuing to ML payload selection for context optimization
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=js_string xss_context_final=js_string xss_context_source=ml
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=js_string xss_escaping=url ml_mode=force_ml
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 1, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 0, 'ctx_js': 1, 'param_len': 4, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/profile?name=test, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/script?msg=hello param=msg ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/script?msg=hello param=msg canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/script?msg=hello param=msg canary_pos=421
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'js_string', 'proba': 0.6, 'all_probas': {'attr': 0.1, 'comment': 0.1, 'css': 0.1, 'html_body': 0.1, 'js_string': 0.6, 'json': 0.1, 'url': 0.1}} escaping_ml={'pred': 'url', 'proba': 0.4, 'all_probas': {'html': 0.2, 'js': 0.2, 'raw': 0.2, 'url': 0.4}}
XSS_FUSION force_ml: ctx=js_string src=ml conf=0.6
XSS_PROBE_CONFIRMED continuing to ML payload selection for context optimization
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=js_string xss_context_final=js_string xss_context_source=ml
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=js_string xss_escaping=url ml_mode=force_ml
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 1, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 0, 'ctx_js': 1, 'param_len': 3, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/script?msg=hello, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/search?q=test param=q ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/search?q=test param=q canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/search?q=test param=q canary_pos=427
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'js_string', 'proba': 0.6, 'all_probas': {'attr': 0.1, 'comment': 0.1, 'css': 0.1, 'html_body': 0.1, 'js_string': 0.6, 'json': 0.1, 'url': 0.1}} escaping_ml={'pred': 'url', 'proba': 0.4, 'all_probas': {'html': 0.2, 'js': 0.2, 'raw': 0.2, 'url': 0.4}}
XSS_FUSION force_ml: ctx=js_string src=ml conf=0.6
XSS_PROBE_CONFIRMED continuing to ML payload selection for context optimization
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=js_string xss_context_final=js_string xss_context_source=ml
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=js_string xss_escaping=url ml_mode=force_ml
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 1, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 0, 'ctx_js': 1, 'param_len': 1, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload="><svg onload=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/search?q=test, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
XSS_TELEMETRY ml_final=5 rs_ml=0 used=0 saved=0
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
INFO:     127.0.0.1:56381 - "POST /api/assess HTTP/1.1" 200 OK
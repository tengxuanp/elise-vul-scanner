SQLI_GATE_CHECK param=id param_in=query url=http://127.0.0.1:5001/product?id=1
SQLI_GATE_CHECK param=id param_value='1'
SQLI_GATE_ALLOWED param id allowed for SQLi
SQLI_CANDIDATE_DEBUG Added SQLi candidate for param id
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_LOOP_DEBUG Starting family processing loop with candidates: ['xss', 'sqli']
CANDIDATE_TRACK_1 After initial candidates: ['xss', 'sqli']
SQLI_BUDGET_DEBUG param=id is_paused=False null_streak=5
SQLI_BUDGET_ALLOWED SQLi allowed to proceed
CANDIDATE_TRACK_2 After SQLi budget check: ['xss', 'sqli']
FAMILY_LOOP_FINAL_DEBUG About to process candidates: ['xss', 'sqli']
CANDIDATE_TRACK_3 Right before family loop: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
FAMILY_PROCESSING_DEBUG Current candidates: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family xss in loop
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=unknown xss_context_final=unknown xss_context_source=rule_low_conf
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=unknown xss_escaping=raw ml_mode=auto
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 1, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 0, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 0, 'ctx_js': 0, 'param_len': 2, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload=<img src=x onerror=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/product?id=1, fam=xss, payload=<img src=x onerror=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
INJECTION_DEBUG attempt_idx=1, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/product?id=1, fam=xss, payload='"><script>alert(1)</script>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
INJECTION_DEBUG attempt_idx=2, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/product?id=1, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
FAMILY_PROCESSING_DEBUG Completed processing family: xss
FAMILY_PROCESSING_DEBUG Processing family: sqli
FAMILY_PROCESSING_DEBUG Current candidates: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family sqli in loop
SQLI_DEBUG Processing SQLi family with sqli_ml_mode=never
SQLI_DEBUG probe_bundle exists: True
SQLI_DEBUG probe_bundle has sqli: True
SQLI_DEBUG sqli probe: SqliProbe(error_based=True, time_based=False, boolean_delta=0.16055045871559634, dialect='sqlite', dialect_signals=['unrecognized token', 'header:Python', 'header:Werkzeug', 'ml:postgresql(0.36)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.3634531363947399, dialect_ml_source='ml', skipped=False)
SQLI_ML_MODE_DEBUG sqli_ml_mode=never in_force_ml=False
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
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/product?id=1, fam=sqli, payload='
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/product?id=1 param=id
[SQLI_PROBE_DEBUG] Error response: SQL Error: unrecognized token: "'"...
[SQLI_PROBE_DEBUG] Status code: 500
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: sql error: unrecognized token: "'"
[SQLI_PROBE_DEBUG] SQL error detected!
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=sqlite dialect_ml=postgresql dialect_ml_proba=0.3634531363947399 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=positive reason=error_signature fired=sqli
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
EVIDENCE_SQLI_DEBUG family=sqli has_probe_bundle=True probe_bundle_sqli=SqliProbe(error_based=True, time_based=False, boolean_delta=0.16055045871559634, dialect='sqlite', dialect_signals=['unrecognized token', 'header:Python', 'header:Werkzeug', 'ml:postgresql(0.36)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.3634531363947399, dialect_ml_source='ml', skipped=False)
EVIDENCE_SQLI_DEBUG dialect=sqlite dialect_ml=postgresql dialect_rule=None dialect_source=ml
EVIDENCE_SQLI_DEBUG family=sqli has_probe_bundle=True probe_bundle_sqli=SqliProbe(error_based=True, time_based=False, boolean_delta=0.16055045871559634, dialect='sqlite', dialect_signals=['unrecognized token', 'header:Python', 'header:Werkzeug', 'ml:postgresql(0.36)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.3634531363947399, dialect_ml_source='ml', skipped=False)
EVIDENCE_SQLI_DEBUG dialect=sqlite dialect_ml=postgresql dialect_rule=None dialect_source=ml
EVIDENCE_SQLI_ML_PROBA_DEBUG sqli_dialect_source=ml sqli_dialect_ml_proba=0.3634531363947399
RESULT_DICT_DEBUG fired_family=sqli ev.sqli_dialect=sqlite ev.sqli_dialect_source=ml ev.sqli_dialect_ml_proba=0.3634531363947399
POSITIVE_RESULT_DEBUG Found sqli vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family sqli, continuing to next family
INJECTION_DEBUG attempt_idx=1, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/product?id=1, fam=sqli, payload=' OR '1'='1' --
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/product?id=1 param=id
[SQLI_PROBE_DEBUG] Error response: SQL Error: unrecognized token: "'"...
[SQLI_PROBE_DEBUG] Status code: 500
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: sql error: unrecognized token: "'"
[SQLI_PROBE_DEBUG] SQL error detected!
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=sqlite dialect_ml=postgresql dialect_ml_proba=0.3634531363947399 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=positive reason=error_signature fired=sqli
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
EVIDENCE_SQLI_DEBUG family=sqli has_probe_bundle=True probe_bundle_sqli=SqliProbe(error_based=True, time_based=False, boolean_delta=0.16055045871559634, dialect='sqlite', dialect_signals=['unrecognized token', 'header:Python', 'header:Werkzeug', 'ml:postgresql(0.36)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.3634531363947399, dialect_ml_source='ml', skipped=False)
EVIDENCE_SQLI_DEBUG dialect=sqlite dialect_ml=postgresql dialect_rule=None dialect_source=ml
EVIDENCE_SQLI_DEBUG family=sqli has_probe_bundle=True probe_bundle_sqli=SqliProbe(error_based=True, time_based=False, boolean_delta=0.16055045871559634, dialect='sqlite', dialect_signals=['unrecognized token', 'header:Python', 'header:Werkzeug', 'ml:postgresql(0.36)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.3634531363947399, dialect_ml_source='ml', skipped=False)
EVIDENCE_SQLI_DEBUG dialect=sqlite dialect_ml=postgresql dialect_rule=None dialect_source=ml
EVIDENCE_SQLI_ML_PROBA_DEBUG sqli_dialect_source=ml sqli_dialect_ml_proba=0.3634531363947399
RESULT_DICT_DEBUG fired_family=sqli ev.sqli_dialect=sqlite ev.sqli_dialect_source=ml ev.sqli_dialect_ml_proba=0.3634531363947399
POSITIVE_RESULT_DEBUG Found sqli vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family sqli, continuing to next family
INJECTION_DEBUG attempt_idx=2, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/product?id=1, fam=sqli, payload=1 AND SLEEP(2) --
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/product?id=1 param=id
[SQLI_PROBE_DEBUG] Error response: SQL Error: unrecognized token: "'"...
[SQLI_PROBE_DEBUG] Status code: 500
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: sql error: unrecognized token: "'"
[SQLI_PROBE_DEBUG] SQL error detected!
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=sqlite dialect_ml=postgresql dialect_ml_proba=0.3634531363947399 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=positive reason=error_signature fired=sqli
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
EVIDENCE_SQLI_DEBUG family=sqli has_probe_bundle=True probe_bundle_sqli=SqliProbe(error_based=True, time_based=False, boolean_delta=0.16055045871559634, dialect='sqlite', dialect_signals=['unrecognized token', 'header:Python', 'header:Werkzeug', 'ml:postgresql(0.36)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.3634531363947399, dialect_ml_source='ml', skipped=False)
EVIDENCE_SQLI_DEBUG dialect=sqlite dialect_ml=postgresql dialect_rule=None dialect_source=ml
EVIDENCE_SQLI_DEBUG family=sqli has_probe_bundle=True probe_bundle_sqli=SqliProbe(error_based=True, time_based=False, boolean_delta=0.16055045871559634, dialect='sqlite', dialect_signals=['unrecognized token', 'header:Python', 'header:Werkzeug', 'ml:postgresql(0.36)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.3634531363947399, dialect_ml_source='ml', skipped=False)
EVIDENCE_SQLI_DEBUG dialect=sqlite dialect_ml=postgresql dialect_rule=None dialect_source=ml
EVIDENCE_SQLI_ML_PROBA_DEBUG sqli_dialect_source=ml sqli_dialect_ml_proba=0.3634531363947399
RESULT_DICT_DEBUG fired_family=sqli ev.sqli_dialect=sqlite ev.sqli_dialect_source=ml ev.sqli_dialect_ml_proba=0.3634531363947399
POSITIVE_RESULT_DEBUG Found sqli vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family sqli, continuing to next family
FAMILY_PROCESSING_DEBUG Completed processing family: sqli
FAMILY_LOOP_COMPLETE_DEBUG Finished processing all families
FAMILY_LOOP_COMPLETE_DEBUG Final candidates processed: ['xss', 'sqli']
POSITIVE_RESULT_DEBUG Returning 6 stored positive results
POSITIVE_RESULT_DEBUG Returning first result: family=xss
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/profile?name=test param=name ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/profile?name=test param=name canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/profile?name=test param=name canary_pos=428
XSS_FUSION rule: ctx=attr src=rule_high_conf conf=0.9 r_conf=0.9 m_ctx=None m_p=0.0
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/profile?name=test param=name
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body { font-family...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>user profile</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .profile { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .name { font-size: 24px; font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>user profile</h1>
    <div class="profile">
        <p class="name">welcome, <span id="username" data-name="'">'</span>!</p>
        <p>this is your profile page.</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
ORACLE_DEBUG signals={'xss_context': 'attr', 'redirect_influence': False, 'sqli_error_based': False, 'sql_boolean_delta': 0.02877697841726619}
ORACLE_DEBUG sqli_ok=False redirect_ok=False xss_ok=True
PROBE_CONFIRM_DEBUG fam=xss plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=auto
PROBE_CONFIRM_DEBUG condition_met=True for fam=xss
PROBE_CONFIRMED continuing to ML payload selection for xss family
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
SQLI_GATE_CHECK param=name param_in=query url=http://127.0.0.1:5001/profile?name=test
SQLI_GATE_CHECK param=name param_value='test'
SQLI_GATE_ALLOWED param name allowed for SQLi
SQLI_CANDIDATE_DEBUG Added SQLi candidate for param name
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_LOOP_DEBUG Starting family processing loop with candidates: ['xss', 'sqli']
CANDIDATE_TRACK_1 After initial candidates: ['xss', 'sqli']
SQLI_BUDGET_DEBUG param=name is_paused=False null_streak=0
SQLI_BUDGET_ALLOWED SQLi allowed to proceed
CANDIDATE_TRACK_2 After SQLi budget check: ['xss', 'sqli']
FAMILY_LOOP_FINAL_DEBUG About to process candidates: ['xss', 'sqli']
CANDIDATE_TRACK_3 Right before family loop: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
FAMILY_PROCESSING_DEBUG Current candidates: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family xss in loop
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=attr xss_context_final=attr xss_context_source=rule_high_conf
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=attr xss_escaping=raw ml_mode=auto
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 0, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 1, 'ctx_js': 0, 'param_len': 4, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload=<img src=x onerror=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/profile?name=test, fam=xss, payload=<img src=x onerror=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
INJECTION_DEBUG attempt_idx=1, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/profile?name=test, fam=xss, payload='"><script>alert(1)</script>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
INJECTION_DEBUG attempt_idx=2, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/profile?name=test, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
FAMILY_PROCESSING_DEBUG Completed processing family: xss
FAMILY_PROCESSING_DEBUG Processing family: sqli
FAMILY_PROCESSING_DEBUG Current candidates: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family sqli in loop
SQLI_DEBUG Processing SQLi family with sqli_ml_mode=never
SQLI_DEBUG probe_bundle exists: True
SQLI_DEBUG probe_bundle has sqli: True
SQLI_DEBUG sqli probe: SqliProbe(error_based=False, time_based=False, boolean_delta=0.02877697841726619, dialect='postgresql', dialect_signals=['header:Python', 'header:Werkzeug', 'ml:postgresql(1.00)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.9999999607157481, dialect_ml_source='ml', skipped=False)
SQLI_ML_MODE_DEBUG sqli_ml_mode=never in_force_ml=False
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
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/profile?name=test, fam=sqli, payload='
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/profile?name=test param=name
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body { font-family...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>user profile</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .profile { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .name { font-size: 24px; font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>user profile</h1>
    <div class="profile">
        <p class="name">welcome, <span id="username" data-name="'">'</span>!</p>
        <p>this is your profile page.</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=postgresql dialect_ml=postgresql dialect_ml_proba=0.9999999607157481 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=clean reason=no_sql_evidence fired=None
INJECTION_DEBUG attempt_idx=1, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/profile?name=test, fam=sqli, payload=' OR '1'='1' --
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/profile?name=test param=name
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body { font-family...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>user profile</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .profile { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .name { font-size: 24px; font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>user profile</h1>
    <div class="profile">
        <p class="name">welcome, <span id="username" data-name="'">'</span>!</p>
        <p>this is your profile page.</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=postgresql dialect_ml=postgresql dialect_ml_proba=0.9999999607157481 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=clean reason=no_sql_evidence fired=None
INJECTION_DEBUG attempt_idx=2, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/profile?name=test, fam=sqli, payload=1 AND SLEEP(2) --
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/profile?name=test param=name
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body { font-family...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>user profile</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .profile { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .name { font-size: 24px; font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>user profile</h1>
    <div class="profile">
        <p class="name">welcome, <span id="username" data-name="'">'</span>!</p>
        <p>this is your profile page.</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=postgresql dialect_ml=postgresql dialect_ml_proba=0.9999999607157481 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=clean reason=no_sql_evidence fired=None
FAMILY_PROCESSING_DEBUG Completed processing family: sqli
FAMILY_LOOP_COMPLETE_DEBUG Finished processing all families
FAMILY_LOOP_COMPLETE_DEBUG Final candidates processed: ['xss', 'sqli']
POSITIVE_RESULT_DEBUG Returning 3 stored positive results
POSITIVE_RESULT_DEBUG Returning first result: family=xss
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/script?msg=hello param=msg ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/script?msg=hello param=msg canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/script?msg=hello param=msg canary_pos=421
XSS_FUSION rule: ctx=js_string src=rule_high_conf conf=0.95 r_conf=0.95 m_ctx=None m_p=0.0
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/script?msg=hello param=msg
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Script Page</title>
    <style>
        body { font-family:...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>script page</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .message { background: #e3f2fd; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>script page</h1>
    <div class="message">
        <p>this page demonstrates javascript string injection.</p>
    </div>

    <script>
        var m = "'";
        document.body.innerhtml += '<div class="message"><p>message from server: ' + m + '</p></div>';
    </script>

    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
ORACLE_DEBUG signals={'xss_context': 'js_string', 'redirect_influence': False, 'sqli_error_based': False, 'sql_boolean_delta': 0.013223140495867768}
ORACLE_DEBUG sqli_ok=False redirect_ok=False xss_ok=True
PROBE_CONFIRM_DEBUG fam=xss plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=auto
PROBE_CONFIRM_DEBUG condition_met=True for fam=xss
PROBE_CONFIRMED continuing to ML payload selection for xss family
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
SQLI_GATE_CHECK param=msg param_in=query url=http://127.0.0.1:5001/script?msg=hello
SQLI_GATE_CHECK param=msg param_value='hello'
SQLI_GATE_ALLOWED param msg allowed for SQLi
SQLI_CANDIDATE_DEBUG Added SQLi candidate for param msg
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_LOOP_DEBUG Starting family processing loop with candidates: ['xss', 'sqli']
CANDIDATE_TRACK_1 After initial candidates: ['xss', 'sqli']
SQLI_BUDGET_DEBUG param=msg is_paused=False null_streak=3
SQLI_BUDGET_ALLOWED SQLi allowed to proceed
CANDIDATE_TRACK_2 After SQLi budget check: ['xss', 'sqli']
FAMILY_LOOP_FINAL_DEBUG About to process candidates: ['xss', 'sqli']
CANDIDATE_TRACK_3 Right before family loop: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
FAMILY_PROCESSING_DEBUG Current candidates: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family xss in loop
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=js_string xss_context_final=js_string xss_context_source=rule_high_conf
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=js_string xss_escaping=raw ml_mode=auto
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 0, 'probe_reflection_js': 1, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 0, 'ctx_attr': 0, 'ctx_js': 1, 'param_len': 3, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload=<img src=x onerror=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/script?msg=hello, fam=xss, payload=<img src=x onerror=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
INJECTION_DEBUG attempt_idx=1, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/script?msg=hello, fam=xss, payload='"><script>alert(1)</script>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
INJECTION_DEBUG attempt_idx=2, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/script?msg=hello, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
FAMILY_PROCESSING_DEBUG Completed processing family: xss
FAMILY_PROCESSING_DEBUG Processing family: sqli
FAMILY_PROCESSING_DEBUG Current candidates: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family sqli in loop
SQLI_DEBUG Processing SQLi family with sqli_ml_mode=never
SQLI_DEBUG probe_bundle exists: True
SQLI_DEBUG probe_bundle has sqli: True
SQLI_DEBUG sqli probe: SqliProbe(error_based=False, time_based=False, boolean_delta=0.013223140495867768, dialect='postgresql', dialect_signals=['header:Python', 'header:Werkzeug', 'ml:postgresql(1.00)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.9999999914677212, dialect_ml_source='ml', skipped=False)
SQLI_ML_MODE_DEBUG sqli_ml_mode=never in_force_ml=False
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
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/script?msg=hello, fam=sqli, payload='
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/script?msg=hello param=msg
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Script Page</title>
    <style>
        body { font-family:...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>script page</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .message { background: #e3f2fd; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>script page</h1>
    <div class="message">
        <p>this page demonstrates javascript string injection.</p>
    </div>

    <script>
        var m = "'";
        document.body.innerhtml += '<div class="message"><p>message from server: ' + m + '</p></div>';
    </script>

    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=postgresql dialect_ml=postgresql dialect_ml_proba=0.9999999914677212 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=clean reason=no_sql_evidence fired=None
INJECTION_DEBUG attempt_idx=1, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/script?msg=hello, fam=sqli, payload=' OR '1'='1' --
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/script?msg=hello param=msg
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Script Page</title>
    <style>
        body { font-family:...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>script page</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .message { background: #e3f2fd; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>script page</h1>
    <div class="message">
        <p>this page demonstrates javascript string injection.</p>
    </div>

    <script>
        var m = "'";
        document.body.innerhtml += '<div class="message"><p>message from server: ' + m + '</p></div>';
    </script>

    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=postgresql dialect_ml=postgresql dialect_ml_proba=0.9999999914677212 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=clean reason=no_sql_evidence fired=None
INJECTION_DEBUG attempt_idx=2, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/script?msg=hello, fam=sqli, payload=1 AND SLEEP(2) --
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/script?msg=hello param=msg
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Script Page</title>
    <style>
        body { font-family:...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>script page</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .message { background: #e3f2fd; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>script page</h1>
    <div class="message">
        <p>this page demonstrates javascript string injection.</p>
    </div>

    <script>
        var m = "'";
        document.body.innerhtml += '<div class="message"><p>message from server: ' + m + '</p></div>';
    </script>

    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=postgresql dialect_ml=postgresql dialect_ml_proba=0.9999999914677212 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=clean reason=no_sql_evidence fired=None
FAMILY_PROCESSING_DEBUG Completed processing family: sqli
FAMILY_LOOP_COMPLETE_DEBUG Finished processing all families
FAMILY_LOOP_COMPLETE_DEBUG Final candidates processed: ['xss', 'sqli']
POSITIVE_RESULT_DEBUG Returning 3 stored positive results
POSITIVE_RESULT_DEBUG Returning first result: family=xss
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://127.0.0.1:5001/search?q=test param=q ctx_mode=auto
XSS_PROBE_CANARY url=http://127.0.0.1:5001/search?q=test param=q canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/search?q=test param=q canary_pos=427
XSS_ML_DEBUG ctx_mode=auto call_ml=True context_ml={'pred': 'html_body', 'proba': 0.2777274167597705, 'all_probas': {'attr': 0.2276551496371222, 'comment': 0.03784528335143821, 'css': 0.1375344845367833, 'html_body': 0.2777274167597705, 'js_string': 0.1698875116551869, 'json': 0.012603610870570308, 'url': 0.13674654318912866}} escaping_ml={'pred': 'html', 'proba': 0.43085428618947064, 'all_probas': {'html': 0.43085428618947064, 'js': 0.18750624368508684, 'raw': 0.36820516899345407, 'url': 0.013434301131988319}}
XSS_FUSION rule: ctx=html_body src=rule_low_conf conf=0.7 r_conf=0.7 m_ctx=html_body m_p=0.2777274167597705
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/search?q=test param=q
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
    <style>
        body { font-fami...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>search results</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 4px solid #1976d2; }
        .query { font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>search results</h1>
    <div class="result">
        <p>you searched for: <span class="query">'</span></p>
        <p>search results would appear here...</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
ORACLE_DEBUG signals={'xss_context': 'html', 'redirect_influence': False, 'sqli_error_based': False, 'sql_boolean_delta': 0.014285714285714285}
ORACLE_DEBUG sqli_ok=False redirect_ok=False xss_ok=True
PROBE_CONFIRM_DEBUG fam=xss plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=auto
PROBE_CONFIRM_DEBUG condition_met=True for fam=xss
PROBE_CONFIRMED continuing to ML payload selection for xss family
CANDIDATE_DEBUG xss probe exists, reflected=True
CANDIDATE_DEBUG added xss candidate for target with reflection
SQLI_GATE_CHECK param=q param_in=query url=http://127.0.0.1:5001/search?q=test
SQLI_GATE_CHECK param=q param_value='test'
SQLI_GATE_ALLOWED param q allowed for SQLi
SQLI_CANDIDATE_DEBUG Added SQLi candidate for param q
CANDIDATE_DEBUG final candidates=['xss', 'sqli']
FAMILY_LOOP_DEBUG Starting family processing loop with candidates: ['xss', 'sqli']
CANDIDATE_TRACK_1 After initial candidates: ['xss', 'sqli']
SQLI_BUDGET_DEBUG param=q is_paused=False null_streak=6
SQLI_BUDGET_ALLOWED SQLi allowed to proceed
CANDIDATE_TRACK_2 After SQLi budget check: ['xss', 'sqli']
FAMILY_LOOP_FINAL_DEBUG About to process candidates: ['xss', 'sqli']
CANDIDATE_TRACK_3 Right before family loop: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family: xss
FAMILY_PROCESSING_DEBUG Current candidates: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family xss in loop
XSS_PROBE_DEBUG fam=xss has_probe_bundle=True has_xss=True
XSS_PROBE_DEBUG xss_context=html_body xss_context_final=html_body xss_context_source=rule_low_conf
PAYLOAD_SELECTION_DEBUG fam=xss - using honest ML ranking
RANK_PAYLOADS_CALLED fam=xss xss_context=html_body xss_escaping=raw ml_mode=auto
MODEL_LOAD_CACHE_HIT fam=xss
RANK_PAYLOADS_ML_ATTEMPT fam=xss
RANK_PAYLOADS_ML_FEATURES fam=xss features={'family_xss': 0, 'family_sqli': 0, 'family_redirect': 0, 'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0, 'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 1, 'probe_reflection_js': 0, 'probe_redirect_location_reflects': 0, 'status_class_2': 1, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'content_type_html': 1, 'content_type_json': 0, 'ctx_html': 1, 'ctx_attr': 0, 'ctx_js': 0, 'param_len': 1, 'payload_len': 0, 'alnum_ratio': 0.0, 'digit_ratio': 0.0, 'symbol_ratio': 0.0, 'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.0, 'has_quote': 0, 'has_angle': 0, 'has_lt_gt': 0, 'has_script_tag': 0, 'has_event_handler': 0, 'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0}
RANK_PAYLOADS_ML_VECTOR fam=xss vector_shape=(1, 45)
RANK_PAYLOADS_ML_SUCCESS fam=xss count=3
RANKED_RESULT_DEBUG fam=xss ranked_count=3 first_payload=<img src=x onerror=alert(1)>
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before ML ranker check: ranked=True, len=3, rank_source=ml
RANKED_DEBUG before injection loop: ranked=True, len=3
INJECTION_DEBUG attempt_idx=0, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/search?q=test, fam=xss, payload=<img src=x onerror=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
INJECTION_DEBUG attempt_idx=1, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/search?q=test, fam=xss, payload='"><script>alert(1)</script>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
INJECTION_DEBUG attempt_idx=2, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/search?q=test, fam=xss, payload="><svg onload=alert(1)>
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
EVIDENCE_DEBUG before from_injection: cand=True, cand_type=<class 'dict'>, cand_keys=['payload', 'score', 'p_cal', 'rank_source', 'model_tag', 'family', 'skip_reason']
POSITIVE_RESULT_DEBUG Found xss vulnerability, continuing to process other families
FAMILY_LOOP_DEBUG Completed processing family xss, continuing to next family
FAMILY_PROCESSING_DEBUG Completed processing family: xss
FAMILY_PROCESSING_DEBUG Processing family: sqli
FAMILY_PROCESSING_DEBUG Current candidates: ['xss', 'sqli']
FAMILY_PROCESSING_DEBUG Processing family sqli in loop
SQLI_DEBUG Processing SQLi family with sqli_ml_mode=never
SQLI_DEBUG probe_bundle exists: True
SQLI_DEBUG probe_bundle has sqli: True
SQLI_DEBUG sqli probe: SqliProbe(error_based=False, time_based=False, boolean_delta=0.014285714285714285, dialect='postgresql', dialect_signals=['header:Python', 'header:Werkzeug', 'ml:postgresql(1.00)'], dialect_confident=True, dialect_ml='postgresql', dialect_ml_proba=0.9999999653196466, dialect_ml_source='ml', skipped=False)
SQLI_ML_MODE_DEBUG sqli_ml_mode=never in_force_ml=False
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
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/search?q=test, fam=sqli, payload='
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/search?q=test param=q
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
    <style>
        body { font-fami...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>search results</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 4px solid #1976d2; }
        .query { font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>search results</h1>
    <div class="result">
        <p>you searched for: <span class="query">'</span></p>
        <p>search results would appear here...</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=postgresql dialect_ml=postgresql dialect_ml_proba=0.9999999653196466 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=clean reason=no_sql_evidence fired=None
INJECTION_DEBUG attempt_idx=1, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/search?q=test, fam=sqli, payload=' OR '1'='1' --
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/search?q=test param=q
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
    <style>
        body { font-fami...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>search results</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 4px solid #1976d2; }
        .query { font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>search results</h1>
    <div class="result">
        <p>you searched for: <span class="query">'</span></p>
        <p>search results would appear here...</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=postgresql dialect_ml=postgresql dialect_ml_proba=0.9999999653196466 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=clean reason=no_sql_evidence fired=None
INJECTION_DEBUG attempt_idx=2, cand=True, cand_type=<class 'dict'>
INJECTION_DEBUG before inject_once: target=http://127.0.0.1:5001/search?q=test, fam=sqli, payload=1 AND SLEEP(2) --
INJECTION_DEBUG after inject_once: inj=True, inj_type=<class 'backend.modules.injector.InjectionResult'>
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/search?q=test param=q
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
    <style>
        body { font-fami...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>search results</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 4px solid #1976d2; }
        .query { font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>search results</h1>
    <div class="result">
        <p>you searched for: <span class="query">'</span></p>
        <p>search results would appear here...</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
SQLI_DIALECT_DEBUG Updated probe_bundle.sqli: dialect=postgresql dialect_ml=postgresql dialect_ml_proba=0.9999999653196466 dialect_ml_source=ml
SQLI_STRICT_DECISION decision=clean reason=no_sql_evidence fired=None
FAMILY_PROCESSING_DEBUG Completed processing family: sqli
FAMILY_LOOP_COMPLETE_DEBUG Finished processing all families
FAMILY_LOOP_COMPLETE_DEBUG Final candidates processed: ['xss', 'sqli']
POSITIVE_RESULT_DEBUG Returning 3 stored positive results
POSITIVE_RESULT_DEBUG Returning first result: family=xss
XSS_TELEMETRY ml_final=3 rs_ml=0 used=0 saved=0
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
INFO:     127.0.0.1:60380 - "POST /api/assess HTTP/1.1" 200 OK
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
INFO:     127.0.0.1:60380 - "GET /api/healthz HTTP/1.1" 200 OK
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
INFO:     127.0.0.1:60380 - "GET /api/healthz HTTP/1.1" 200 OK
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
ASSESS_STRATEGY preset=full_smart legacy_strategy=ml_with_context xss.ml=force_ml xss.topk=3 sqli.ml=force_ml sqli.topk=6 sqli.sc=on(M=12/K=20)
Found existing evidence files for job crawl-1757836385973-imao30938 with strategies {'auto'} and ctx_modes {'auto'}, but current strategy is ml_with_context and ctx_mode is force_ml. Re-running assessment.
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
PROBE_DEBUG plan=ml_with_context probes_disabled={'redirect'} families_to_probe=['xss', 'sqli']
XSS_PROBE_START url=http://127.0.0.1:5001/go?url=https://example.com param=url ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/go?url=https://example.com param=url canary_found=False
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/go?url=https://example.com param=url
[SQLI_PROBE_DEBUG] Error response: <!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should b...
[SQLI_PROBE_DEBUG] Status code: 302
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html lang=en>
<title>redirecting...</title>
<h1>redirecting...</h1>
<p>you should be redirected automatically to the target url: <a href="&#39;">&#39;</a>. if not, click the link.

[SQLI_PROBE_DEBUG] No SQL error detected
ORACLE_DEBUG signals={'xss_context': 'none', 'redirect_influence': False, 'sqli_error_based': False, 'sql_boolean_delta': 0.08465608465608465}
ORACLE_DEBUG sqli_ok=False redirect_ok=False xss_ok=False
CANDIDATE_DEBUG xss probe exists, reflected=False
CANDIDATE_DEBUG xss gate passed but no reflection, skipping xss candidate
SQLI_GATE_CHECK param=url param_in=query url=http://127.0.0.1:5001/go?url=https://example.com
SQLI_GATE_CHECK param=url param_value='https://example.com'
SQLI_SUPPRESSED URL-like param url suppressed for SQLi
SQLI_CANDIDATE_DEBUG SQLi candidate blocked for param url
CANDIDATE_DEBUG final candidates=[]
FAMILY_LOOP_DEBUG Starting family processing loop with candidates: []
CANDIDATE_TRACK_1 After initial candidates: []
SQLI_BUDGET_DEBUG param=url is_paused=False null_streak=9
SQLI_BUDGET_ALLOWED SQLi allowed to proceed
CANDIDATE_TRACK_2 After SQLi budget check: []
PROBE_DEBUG plan=ml_with_context probes_disabled={'redirect'} families_to_probe=['xss', 'sqli']
XSS_PROBE_START url=http://127.0.0.1:5001/login param=password ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/login param=password canary_found=False
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/login param=password
[SQLI_PROBE_DEBUG] Error response: SQL Error: unrecognized token: "'''"...
[SQLI_PROBE_DEBUG] Status code: 500
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: sql error: unrecognized token: "'''"
[SQLI_PROBE_DEBUG] SQL error detected!
ORACLE_DEBUG signals={'xss_context': 'none', 'redirect_influence': False, 'sqli_error_based': True, 'sql_boolean_delta': 0.0}
ORACLE_DEBUG sqli_ok=True redirect_ok=False xss_ok=False
PROBE_CONFIRM_DEBUG fam=sqli plan=Plan(name=<ScanStrategy.ML_WITH_CONTEXT: 'ml_with_context'>, probes_disabled={'redirect'}, allow_injections=True, force_ctx_inject_on_probe=True) plan_name=ml_with_context ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=True for fam=sqli
PROBE_CONFIRMED continuing to ML payload selection for sqli family
PROBE_DEBUG plan=ml_with_context probes_disabled={'redirect'} families_to_probe=['xss', 'sqli']
XSS_PROBE_START url=http://127.0.0.1:5001/login param=username ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/login param=username canary_found=False
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/login param=username
[SQLI_PROBE_DEBUG] Error response: SQL Error: unrecognized token: "''' AND password = ''"...
[SQLI_PROBE_DEBUG] Status code: 500
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: sql error: unrecognized token: "''' and password = ''"
[SQLI_PROBE_DEBUG] SQL error detected!
ORACLE_DEBUG signals={'xss_context': 'none', 'redirect_influence': False, 'sqli_error_based': True, 'sql_boolean_delta': 0.0}
ORACLE_DEBUG sqli_ok=True redirect_ok=False xss_ok=False
PROBE_CONFIRM_DEBUG fam=sqli plan=Plan(name=<ScanStrategy.ML_WITH_CONTEXT: 'ml_with_context'>, probes_disabled={'redirect'}, allow_injections=True, force_ctx_inject_on_probe=True) plan_name=ml_with_context ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=True for fam=sqli
PROBE_CONFIRMED continuing to ML payload selection for sqli family
PROBE_DEBUG plan=ml_with_context probes_disabled={'redirect'} families_to_probe=['xss', 'sqli']
XSS_PROBE_START url=http://127.0.0.1:5001/notes param=content ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/notes param=content canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/notes param=content canary_pos=937
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'html_body', 'proba': 0.2777274167597705, 'all_probas': {'attr': 0.2276551496371222, 'comment': 0.03784528335143821, 'css': 0.1375344845367833, 'html_body': 0.2777274167597705, 'js_string': 0.1698875116551869, 'json': 0.012603610870570308, 'url': 0.13674654318912866}} escaping_ml={'pred': 'html', 'proba': 0.43085428618947064, 'all_probas': {'html': 0.43085428618947064, 'js': 0.18750624368508684, 'raw': 0.36820516899345407, 'url': 0.013434301131988319}}
XSS_FUSION force_ml: ctx=html_body src=ml conf=0.2777274167597705
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/notes param=content
[SQLI_PROBE_DEBUG] Error response: <!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should b...
[SQLI_PROBE_DEBUG] Status code: 302
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html lang=en>
<title>redirecting...</title>
<h1>redirecting...</h1>
<p>you should be redirected automatically to the target url: <a href="/notes">/notes</a>. if not, click the link.

[SQLI_PROBE_DEBUG] No SQL error detected
ORACLE_DEBUG signals={'xss_context': 'html', 'redirect_influence': False, 'sqli_error_based': False, 'sql_boolean_delta': 0.0}
ORACLE_DEBUG sqli_ok=False redirect_ok=False xss_ok=True
PROBE_DEBUG plan=ml_with_context probes_disabled={'redirect'} families_to_probe=['xss', 'sqli']
XSS_PROBE_START url=http://127.0.0.1:5001/product?id=1 param=id ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/product?id=1 param=id canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/product?id=1 param=id canary_pos=27
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'attr', 'proba': 0.33453388906925074, 'all_probas': {'attr': 0.33453388906925074, 'comment': 0.03707227926787549, 'css': 0.1297224601734464, 'html_body': 0.16646268561644428, 'js_string': 0.20824578886468215, 'json': 0.021626350366565808, 'url': 0.10233654664173508}} escaping_ml={'pred': 'raw', 'proba': 0.5124421974899834, 'all_probas': {'html': 0.2879849387067814, 'js': 0.1704435057993857, 'raw': 0.5124421974899834, 'url': 0.029129358003849533}}
XSS_FUSION force_ml: ctx=attr src=ml conf=0.33453388906925074
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/product?id=1 param=id
[SQLI_PROBE_DEBUG] Error response: SQL Error: unrecognized token: "'"...
[SQLI_PROBE_DEBUG] Status code: 500
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: sql error: unrecognized token: "'"
[SQLI_PROBE_DEBUG] SQL error detected!
ORACLE_DEBUG signals={'xss_context': 'attr', 'redirect_influence': False, 'sqli_error_based': True, 'sql_boolean_delta': 0.16055045871559634}
ORACLE_DEBUG sqli_ok=True redirect_ok=False xss_ok=True
PROBE_CONFIRM_DEBUG fam=sqli plan=Plan(name=<ScanStrategy.ML_WITH_CONTEXT: 'ml_with_context'>, probes_disabled={'redirect'}, allow_injections=True, force_ctx_inject_on_probe=True) plan_name=ml_with_context ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=True for fam=sqli
PROBE_CONFIRMED continuing to ML payload selection for sqli family
PROBE_DEBUG plan=ml_with_context probes_disabled={'redirect'} families_to_probe=['xss', 'sqli']
XSS_PROBE_START url=http://127.0.0.1:5001/profile?name=test param=name ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/profile?name=test param=name canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/profile?name=test param=name canary_pos=428
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'html_body', 'proba': 0.2777274167597705, 'all_probas': {'attr': 0.2276551496371222, 'comment': 0.03784528335143821, 'css': 0.1375344845367833, 'html_body': 0.2777274167597705, 'js_string': 0.1698875116551869, 'json': 0.012603610870570308, 'url': 0.13674654318912866}} escaping_ml={'pred': 'html', 'proba': 0.43085428618947064, 'all_probas': {'html': 0.43085428618947064, 'js': 0.18750624368508684, 'raw': 0.36820516899345407, 'url': 0.013434301131988319}}
XSS_FUSION force_ml: ctx=html_body src=ml conf=0.2777274167597705
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/profile?name=test param=name
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body { font-family...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>user profile</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .profile { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .name { font-size: 24px; font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>user profile</h1>
    <div class="profile">
        <p class="name">welcome, <span id="username" data-name="'">'</span>!</p>
        <p>this is your profile page.</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
ORACLE_DEBUG signals={'xss_context': 'html', 'redirect_influence': False, 'sqli_error_based': False, 'sql_boolean_delta': 0.02877697841726619}
ORACLE_DEBUG sqli_ok=False redirect_ok=False xss_ok=True
PROBE_DEBUG plan=ml_with_context probes_disabled={'redirect'} families_to_probe=['xss', 'sqli']
XSS_PROBE_START url=http://127.0.0.1:5001/script?msg=hello param=msg ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/script?msg=hello param=msg canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/script?msg=hello param=msg canary_pos=421
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'html_body', 'proba': 0.2732830427683519, 'all_probas': {'attr': 0.20266751524197715, 'comment': 0.0356689785226659, 'css': 0.14064242674401836, 'html_body': 0.2732830427683519, 'js_string': 0.158373817562023, 'json': 0.023471003684758268, 'url': 0.1658932154762054}} escaping_ml={'pred': 'html', 'proba': 0.40468803214593996, 'all_probas': {'html': 0.40468803214593996, 'js': 0.18910878711582926, 'raw': 0.3814188509343786, 'url': 0.024784329803852267}}
XSS_FUSION force_ml: ctx=html_body src=ml conf=0.2732830427683519
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/script?msg=hello param=msg
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Script Page</title>
    <style>
        body { font-family:...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>script page</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .message { background: #e3f2fd; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>script page</h1>
    <div class="message">
        <p>this page demonstrates javascript string injection.</p>
    </div>

    <script>
        var m = "'";
        document.body.innerhtml += '<div class="message"><p>message from server: ' + m + '</p></div>';
    </script>

    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
ORACLE_DEBUG signals={'xss_context': 'html', 'redirect_influence': False, 'sqli_error_based': False, 'sql_boolean_delta': 0.013223140495867768}
ORACLE_DEBUG sqli_ok=False redirect_ok=False xss_ok=True
PROBE_DEBUG plan=ml_with_context probes_disabled={'redirect'} families_to_probe=['xss', 'sqli']
XSS_PROBE_START url=http://127.0.0.1:5001/search?q=test param=q ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/search?q=test param=q canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/search?q=test param=q canary_pos=427
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'html_body', 'proba': 0.2777274167597705, 'all_probas': {'attr': 0.2276551496371222, 'comment': 0.03784528335143821, 'css': 0.1375344845367833, 'html_body': 0.2777274167597705, 'js_string': 0.1698875116551869, 'json': 0.012603610870570308, 'url': 0.13674654318912866}} escaping_ml={'pred': 'html', 'proba': 0.43085428618947064, 'all_probas': {'html': 0.43085428618947064, 'js': 0.18750624368508684, 'raw': 0.36820516899345407, 'url': 0.013434301131988319}}
XSS_FUSION force_ml: ctx=html_body src=ml conf=0.2777274167597705
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://127.0.0.1:5001/search?q=test param=q
[SQLI_PROBE_DEBUG] Error response: <!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
    <style>
        body { font-fami...
[SQLI_PROBE_DEBUG] Status code: 200
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: <!doctype html>
<html>
<head>
    <title>search results</title>
    <style>
        body { font-family: arial, sans-serif; margin: 40px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 4px solid #1976d2; }
        .query { font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>search results</h1>
    <div class="result">
        <p>you searched for: <span class="query">'</span></p>
        <p>search results would appear here...</p>
    </div>
    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
ORACLE_DEBUG signals={'xss_context': 'html', 'redirect_influence': False, 'sqli_error_based': False, 'sql_boolean_delta': 0.014285714285714285}
ORACLE_DEBUG sqli_ok=False redirect_ok=False xss_ok=True
XSS_TELEMETRY ml_final=0 rs_ml=0 used=0 saved=0
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
INFO:     127.0.0.1:60600 - "POST /api/assess HTTP/1.1" 200 OK

    <p><a href="/">← back to index</a></p>
</body>
</html>
[SQLI_PROBE_DEBUG] No SQL error detected
ORACLE_DEBUG signals={'xss_context': 'html', 'redirect_influence': False, 'sqli_error_based': False, 'sql_boolean_delta': 0.02877697841726619}
ORACLE_DEBUG sqli_ok=False redirect_ok=False xss_ok=True
PROBE_DEBUG plan=ml_with_context probes_disabled={'redirect'} families_to_probe=['xss', 'sqli']
XSS_PROBE_START url=http://127.0.0.1:5001/script?msg=hello param=msg ctx_mode=force_ml
XSS_PROBE_CANARY url=http://127.0.0.1:5001/script?msg=hello param=msg canary_found=True
XSS_PROBE_CANARY_FOUND url=http://127.0.0.1:5001/script?msg=hello param=msg canary_pos=421
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'html_body', 'proba': 0.2732830427683519, 'all_probas': {'attr': 0.20266751524197715, 'comment': 0.0356689785226659, 'css': 0.14064242674401836, 'html_body': 0.2732830427683519, 'js_string': 0.158373817562023, 'json': 0.023471003684758268, 'url': 0.1658932154762054}} escaping_ml={'pred': 'htm
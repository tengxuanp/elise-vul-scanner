INFO:     127.0.0.1:57920 - "OPTIONS /api/assess HTTP/1.1" 200 OK
MODEL_LOAD_ATTEMPT fam=xss model_key=family_xss models=['family_xss', 'family_sqli', 'family_redirect']
MODEL_LOAD_PATH fam=xss path=/Users/raphaelpang/code/elise/backend/modules/ml/models/family_xss.joblib exists=True
MODEL_LOAD_ERROR fam=xss error=Can't get attribute 'ConstantProba' on <module '__mp_main__' from '/Users/raphaelpang/code/elise/venv/bin/uvicorn'>
MODEL_LOAD_FALLBACK fam=xss creating mock model
MODEL_LOAD_ATTEMPT fam=sqli model_key=family_sqli models=['family_xss', 'family_sqli', 'family_redirect']
MODEL_LOAD_PATH fam=sqli path=/Users/raphaelpang/code/elise/backend/modules/ml/models/family_sqli.joblib exists=True
MODEL_LOAD_ERROR fam=sqli error=Can't get attribute 'ConstantProba' on <module '__mp_main__' from '/Users/raphaelpang/code/elise/venv/bin/uvicorn'>
MODEL_LOAD_FALLBACK fam=sqli creating mock model
MODEL_LOAD_ATTEMPT fam=redirect model_key=family_redirect models=['family_xss', 'family_sqli', 'family_redirect']
MODEL_LOAD_PATH fam=redirect path=/Users/raphaelpang/code/elise/backend/modules/ml/models/family_redirect.joblib exists=True
MODEL_LOAD_ERROR fam=redirect error=Can't get attribute 'ConstantProba' on <module '__mp_main__' from '/Users/raphaelpang/code/elise/venv/bin/uvicorn'>
MODEL_LOAD_FALLBACK fam=redirect creating mock model
SQLi dialect model loaded from /Users/raphaelpang/code/elise/backend/modules/ml/models/sqli_dialect_model.joblib
/Users/raphaelpang/code/elise/venv/lib/python3.8/site-packages/sklearn/base.py:348: InconsistentVersionWarning: Trying to unpickle estimator TfidfTransformer from version 1.7.1 when using version 1.3.2. This might lead to breaking code or invalid results. Use at your own risk. For more info please refer to:
https://scikit-learn.org/stable/model_persistence.html#security-maintainability-limitations
  warnings.warn(
Failed to load XSS context pipeline: No module named 'numpy._core'
Context model loaded successfully
Failed to load XSS escaping pipeline: No module named 'numpy._core'
Escaping model loaded successfully
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
ASSESS_STRATEGY preset=smart_xss legacy_strategy=auto xss.ml=force_ml xss.topk=3 sqli.ml=force_ml sqli.topk=6 sqli.sc=on(M=12/K=20)
Found existing evidence files for job crawl-1757876626777-2zo7f206n with strategies {'auto'}, ctx_modes {'auto'}, sqli_ml_modes {'never'}; current strategy=auto, ctx_mode=force_ml, sqli_ml_mode=force_ml. Re-running assessment.
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://localhost:5001/go?url=https://example.com param=url ctx_mode=force_ml
XSS_PROBE_CANARY url=http://localhost:5001/go?url=https://example.com param=url canary_found=False
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://localhost:5001/go?url=https://example.com param=url
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
ORACLE_DEBUG signals={'xss_context': 'none', 'redirect_influence': True, 'sqli_error_based': False, 'sql_boolean_delta': 0.08465608465608465}
ORACLE_DEBUG sqli_ok=False redirect_ok=True xss_ok=False
PROBE_CONFIRM_DEBUG fam=redirect plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=False for fam=redirect
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://localhost:5001/login param=password ctx_mode=force_ml
XSS_PROBE_CANARY url=http://localhost:5001/login param=password canary_found=False
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://localhost:5001/login param=password
[SQLI_PROBE_DEBUG] Error response: SQL Error: unrecognized token: "'''"...
[SQLI_PROBE_DEBUG] Status code: 500
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: sql error: unrecognized token: "'''"
[SQLI_PROBE_DEBUG] SQL error detected!
ORACLE_DEBUG signals={'xss_context': 'none', 'redirect_influence': False, 'sqli_error_based': True, 'sql_boolean_delta': 0.0}
ORACLE_DEBUG sqli_ok=True redirect_ok=False xss_ok=False
PROBE_CONFIRM_DEBUG fam=sqli plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=False for fam=sqli
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://localhost:5001/login param=username ctx_mode=force_ml
XSS_PROBE_CANARY url=http://localhost:5001/login param=username canary_found=False
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://localhost:5001/login param=username
[SQLI_PROBE_DEBUG] Error response: SQL Error: unrecognized token: "''' AND password = ''"...
[SQLI_PROBE_DEBUG] Status code: 500
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: sql error: unrecognized token: "''' and password = ''"
[SQLI_PROBE_DEBUG] SQL error detected!
ORACLE_DEBUG signals={'xss_context': 'none', 'redirect_influence': False, 'sqli_error_based': True, 'sql_boolean_delta': 0.0}
ORACLE_DEBUG sqli_ok=True redirect_ok=False xss_ok=False
PROBE_CONFIRM_DEBUG fam=sqli plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=False for fam=sqli
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://localhost:5001/notes param=content ctx_mode=force_ml
XSS_PROBE_CANARY url=http://localhost:5001/notes param=content canary_found=True
XSS_PROBE_CANARY_FOUND url=http://localhost:5001/notes param=content canary_pos=937
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'html_body', 'proba': 0.9865041673891701, 'all_probas': {'attr': 0.009712520169245144, 'html_body': 0.9865041673891701, 'unknown': 0.003783312441584758}} escaping_ml={'pred': 'raw', 'proba': 1.0, 'all_probas': {'raw': 1.0}}
XSS_FUSION force_ml: ctx=html_body src=ml conf=0.9865041673891701
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://localhost:5001/notes param=content
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
PROBE_CONFIRM_DEBUG fam=xss plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=True for fam=xss
PROBE_CONFIRMED continuing to ML payload selection for xss family
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://localhost:5001/product?id=1 param=id ctx_mode=force_ml
XSS_PROBE_CANARY url=http://localhost:5001/product?id=1 param=id canary_found=True
XSS_PROBE_CANARY_FOUND url=http://localhost:5001/product?id=1 param=id canary_pos=27
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'unknown', 'proba': 0.9946209779098537, 'all_probas': {'attr': 0.0016329060389058, 'html_body': 0.003746116051240494, 'unknown': 0.9946209779098537}} escaping_ml={'pred': 'raw', 'proba': 1.0, 'all_probas': {'raw': 1.0}}
XSS_FUSION force_ml: ctx=unknown src=ml conf=0.9946209779098537
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://localhost:5001/product?id=1 param=id
[SQLI_PROBE_DEBUG] Error response: SQL Error: unrecognized token: "'"...
[SQLI_PROBE_DEBUG] Status code: 500
[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: ('sql syntax', 'sql error', 'sqlite error', 'warning: mysql', 'psql:', 'unterminated', 'odbc')
[SQLI_PROBE_DEBUG] Error text lower: sql error: unrecognized token: "'"
[SQLI_PROBE_DEBUG] SQL error detected!
ORACLE_DEBUG signals={'xss_context': 'none', 'redirect_influence': False, 'sqli_error_based': True, 'sql_boolean_delta': 0.16055045871559634}
ORACLE_DEBUG sqli_ok=True redirect_ok=False xss_ok=False
PROBE_CONFIRM_DEBUG fam=sqli plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=False for fam=sqli
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://localhost:5001/profile?name=test param=name ctx_mode=force_ml
XSS_PROBE_CANARY url=http://localhost:5001/profile?name=test param=name canary_found=True
XSS_PROBE_CANARY_FOUND url=http://localhost:5001/profile?name=test param=name canary_pos=428
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'attr', 'proba': 0.9899810559896451, 'all_probas': {'attr': 0.9899810559896451, 'html_body': 0.008358066089018986, 'unknown': 0.0016608779213359635}} escaping_ml={'pred': 'raw', 'proba': 1.0, 'all_probas': {'raw': 1.0}}
XSS_FUSION force_ml: ctx=attr src=ml conf=0.9899810559896451
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://localhost:5001/profile?name=test param=name
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
PROBE_CONFIRM_DEBUG fam=xss plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=True for fam=xss
PROBE_CONFIRMED continuing to ML payload selection for xss family
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://localhost:5001/script?msg=hello param=msg ctx_mode=force_ml
XSS_PROBE_CANARY url=http://localhost:5001/script?msg=hello param=msg canary_found=True
XSS_PROBE_CANARY_FOUND url=http://localhost:5001/script?msg=hello param=msg canary_pos=421
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'html_body', 'proba': 0.9938777047159872, 'all_probas': {'attr': 0.004216074687646814, 'html_body': 0.9938777047159872, 'unknown': 0.0019062205963658585}} escaping_ml={'pred': 'raw', 'proba': 1.0, 'all_probas': {'raw': 1.0}}
XSS_FUSION force_ml: ctx=html_body src=ml conf=0.9938777047159872
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://localhost:5001/script?msg=hello param=msg
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
PROBE_CONFIRM_DEBUG fam=xss plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=True for fam=xss
PROBE_CONFIRMED continuing to ML payload selection for xss family
PROBE_DEBUG plan=auto probes_disabled=set() families_to_probe=['xss', 'sqli', 'redirect']
XSS_PROBE_START url=http://localhost:5001/search?q=test param=q ctx_mode=force_ml
XSS_PROBE_CANARY url=http://localhost:5001/search?q=test param=q canary_found=True
XSS_PROBE_CANARY_FOUND url=http://localhost:5001/search?q=test param=q canary_pos=427
XSS_ML_DEBUG ctx_mode=force_ml call_ml=True context_ml={'pred': 'html_body', 'proba': 0.9851154710046301, 'all_probas': {'attr': 0.010951820794959473, 'html_body': 0.9851154710046301, 'unknown': 0.003932708200410493}} escaping_ml={'pred': 'raw', 'proba': 1.0, 'all_probas': {'raw': 1.0}}
XSS_FUSION force_ml: ctx=html_body src=ml conf=0.9851154710046301
[SQLI_PROBE_DEBUG] Starting SQLi probe for http://localhost:5001/search?q=test param=q
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
PROBE_CONFIRM_DEBUG fam=xss plan=Plan(name=<ScanStrategy.AUTO: 'auto'>, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=False) plan_name=auto ctx_mode=force_ml
PROBE_CONFIRM_DEBUG condition_met=True for fam=xss
PROBE_CONFIRMED continuing to ML payload selection for xss family
XSS_TELEMETRY ml_final=0 rs_ml=0 used=0 saved=0
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
MODEL_LOAD_CACHE_HIT fam=xss
MODEL_LOAD_CACHE_HIT fam=sqli
MODEL_LOAD_CACHE_HIT fam=redirect
INFO:     127.0.0.1:57920 - "POST /api/assess HTTP/1.1" 200 OK

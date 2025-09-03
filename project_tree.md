
```
elise
├─ LICENSE
├─ alembic.ini
├─ backend
│  ├─ __init__.py
│  ├─ db.py
│  ├─ debug_evidence.py
│  ├─ debug_features.py
│  ├─ fix_ml_ranker.py
│  ├─ init_db.py
│  ├─ main.py
│  ├─ migrations
│  │  └─ versions
│  │     └─ 20250824_add_testcase_evidence.py
│  ├─ models
│  ├─ models.py
│  ├─ modules
│  │  ├─ ENHANCED_ML_INTEGRATION_SUMMARY.md
│  │  ├─ __init__.py
│  │  ├─ categorize_endpoints.py
│  │  ├─ detectors.py
│  │  ├─ diff_utils.py
│  │  ├─ enhanced_fuzzer_core.py
│  │  ├─ evidence_sink.py
│  │  ├─ family_router.py
│  │  ├─ feature_extractor.py
│  │  ├─ fuzzer_core.py
│  │  ├─ fuzzer_core.py.backup
│  │  ├─ fuzzer_core_enhanced_patch.py
│  │  ├─ fuzzer_ffuf.py
│  │  ├─ injectors.py
│  │  ├─ ml
│  │  │  ├─ IMPROVED_SYNTHETIC_DATA_SUMMARY.md
│  │  │  ├─ README_ENHANCED_ML.md
│  │  │  ├─ __init__.py
│  │  │  ├─ confidence_calibration.py
│  │  │  ├─ enhanced_calibrator_redirect.joblib
│  │  │  ├─ enhanced_calibrator_sqli.joblib
│  │  │  ├─ enhanced_calibrator_xss.joblib
│  │  │  ├─ enhanced_features.py
│  │  │  ├─ enhanced_inference.py
│  │  │  ├─ enhanced_metadata_redirect.json
│  │  │  ├─ enhanced_metadata_sqli.json
│  │  │  ├─ enhanced_metadata_xss.json
│  │  │  ├─ enhanced_ranker_redirect.joblib
│  │  │  ├─ enhanced_ranker_sqli.joblib
│  │  │  ├─ enhanced_ranker_xss.joblib
│  │  │  ├─ enhanced_scaler_redirect.joblib
│  │  │  ├─ enhanced_scaler_sqli.joblib
│  │  │  ├─ enhanced_scaler_xss.joblib
│  │  │  ├─ enhanced_trainer.py
│  │  │  ├─ enhanced_training_results.json
│  │  │  ├─ features.py
│  │  │  ├─ infer_ranker.py
│  │  │  ├─ integration_example.py
│  │  │  ├─ param_prioritizer.py
│  │  │  ├─ prepare_ranker_data.py
│  │  │  ├─ ranker_manifest.json
│  │  │  ├─ ranker_redirect.joblib
│  │  │  ├─ ranker_report_redirect.json
│  │  │  ├─ ranker_report_sqli.json
│  │  │  ├─ ranker_report_xss.json
│  │  │  ├─ ranker_sqli.joblib
│  │  │  ├─ ranker_xss.joblib
│  │  │  ├─ recommender_meta.json
│  │  │  ├─ synth
│  │  │  │  └─ synthesize_training.py
│  │  │  ├─ test_all_models.py
│  │  │  ├─ test_enhanced_system.py
│  │  │  ├─ test_trained_model.py
│  │  │  ├─ train_enhanced_models.py
│  │  │  ├─ train_family_ranker.py
│  │  │  └─ train_ranker.py
│  │  ├─ ml_ranker.py
│  │  ├─ payloads.py
│  │  ├─ playwright_crawler.py
│  │  ├─ prioritizer
│  │  ├─ recommender.py
│  │  ├─ target_builder.py
│  │  ├─ test_enhanced_fuzzer_integration.py
│  │  ├─ triage
│  │  │  └─ delta_scorer.py
│  │  └─ xss_dom_prover.py
│  ├─ payloads
│  │  ├─ sqli.txt
│  │  ├─ sqli_login.txt
│  │  └─ xss_basic.txt
│  ├─ requirements.txt
│  ├─ requirements_enhanced.txt
│  ├─ routes
│  │  ├─ __init__.py
│  │  ├─ category_routes.py
│  │  ├─ crawl_routes.py
│  │  ├─ evidence_routes.py
│  │  ├─ fuzz_routes.py
│  │  ├─ job_routes.py
│  │  ├─ ml_routes.py
│  │  ├─ probe_routes.py
│  │  ├─ recommend_routes.py
│  │  ├─ report_routes.py
│  │  └─ verify_routes.py
│  ├─ schemas.py
│  ├─ scripts
│  │  ├─ train_param_prioritizer.py
│  │  └─ train_ranker.py
│  ├─ services
│  │  └─ report_builder.py
│  ├─ synth
│  │  ├─ gen_synth_datasets.py
│  │  └─ synth_to_evidence.py
│  ├─ templates
│  │  └─ report.md.j2
│  ├─ test_import_fix.py
│  ├─ test_ml_environment.py
│  ├─ test_ml_fix.py
│  ├─ test_ml_ui.py
│  └─ venv
│     ├─ bin
│     │  ├─ Activate.ps1
│     │  ├─ activate
│     │  ├─ activate.csh
│     │  ├─ activate.fish
│     │  ├─ alembic
│     │  ├─ dotenv
│     │  ├─ f2py
│     │  ├─ fastapi
│     │  ├─ flask
│     │  ├─ httpx
│     │  ├─ mako-render
│     │  ├─ mitmdump
│     │  ├─ mitmproxy
│     │  ├─ mitmweb
│     │  ├─ normalizer
│     │  ├─ numpy-config
│     │  ├─ pip
│     │  ├─ pip3
│     │  ├─ pip3.12
│     │  ├─ playwright
│     │  ├─ python
│     │  ├─ python3
│     │  ├─ python3.12
│     │  ├─ uvicorn
│     │  ├─ watchfiles
│     │  ├─ websockets
│     │  └─ wheel
│     ├─ include
│     │  ├─ python3.12
│     │  └─ site
│     │     └─ python3.12
│     │        └─ greenlet
│     │           └─ greenlet.h
│     ├─ lib
│     │  └─ python3.12
│     │     └─ site-packages
│     │        ├─ Brotli-1.1.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ MarkupSafe-3.0.2.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ OpenSSL
│     │        │  ├─ SSL.py
│     │        │  ├─ __init__.py
│     │        │  ├─ _util.py
│     │        │  ├─ crypto.py
│     │        │  ├─ debug.py
│     │        │  ├─ py.typed
│     │        │  ├─ rand.py
│     │        │  └─ version.py
│     │        ├─ PyYAML-6.0.2.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ _argon2_cffi_bindings
│     │        │  ├─ __init__.py
│     │        │  ├─ _ffi.abi3.so
│     │        │  └─ _ffi_build.py
│     │        ├─ _brotli.cpython-312-darwin.so
│     │        ├─ _cffi_backend.cpython-312-darwin.so
│     │        ├─ _distutils_hack
│     │        │  ├─ __init__.py
│     │        │  └─ override.py
│     │        ├─ _ruamel_yaml.cpython-312-darwin.so
│     │        ├─ _yaml
│     │        │  └─ __init__.py
│     │        ├─ aioquic
│     │        │  ├─ __init__.py
│     │        │  ├─ _buffer.abi3.so
│     │        │  ├─ _buffer.c
│     │        │  ├─ _buffer.pyi
│     │        │  ├─ _crypto.abi3.so
│     │        │  ├─ _crypto.c
│     │        │  ├─ _crypto.pyi
│     │        │  ├─ asyncio
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ client.py
│     │        │  │  ├─ protocol.py
│     │        │  │  └─ server.py
│     │        │  ├─ buffer.py
│     │        │  ├─ h0
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ connection.py
│     │        │  ├─ h3
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ connection.py
│     │        │  │  ├─ events.py
│     │        │  │  └─ exceptions.py
│     │        │  ├─ py.typed
│     │        │  ├─ quic
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ configuration.py
│     │        │  │  ├─ congestion
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ cubic.py
│     │        │  │  │  └─ reno.py
│     │        │  │  ├─ connection.py
│     │        │  │  ├─ crypto.py
│     │        │  │  ├─ events.py
│     │        │  │  ├─ logger.py
│     │        │  │  ├─ packet.py
│     │        │  │  ├─ packet_builder.py
│     │        │  │  ├─ rangeset.py
│     │        │  │  ├─ recovery.py
│     │        │  │  ├─ retry.py
│     │        │  │  └─ stream.py
│     │        │  └─ tls.py
│     │        ├─ aioquic-1.2.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ aiosqlite
│     │        │  ├─ __init__.py
│     │        │  ├─ __version__.py
│     │        │  ├─ context.py
│     │        │  ├─ core.py
│     │        │  ├─ cursor.py
│     │        │  ├─ py.typed
│     │        │  └─ tests
│     │        │     ├─ __init__.py
│     │        │     ├─ __main__.py
│     │        │     ├─ helpers.py
│     │        │     ├─ perf.py
│     │        │     └─ smoke.py
│     │        ├─ aiosqlite-0.21.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  └─ WHEEL
│     │        ├─ alembic
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ autogenerate
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ api.py
│     │        │  │  ├─ compare.py
│     │        │  │  ├─ render.py
│     │        │  │  └─ rewriter.py
│     │        │  ├─ command.py
│     │        │  ├─ config.py
│     │        │  ├─ context.py
│     │        │  ├─ context.pyi
│     │        │  ├─ ddl
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _autogen.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ impl.py
│     │        │  │  ├─ mssql.py
│     │        │  │  ├─ mysql.py
│     │        │  │  ├─ oracle.py
│     │        │  │  ├─ postgresql.py
│     │        │  │  └─ sqlite.py
│     │        │  ├─ environment.py
│     │        │  ├─ migration.py
│     │        │  ├─ op.py
│     │        │  ├─ op.pyi
│     │        │  ├─ operations
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ batch.py
│     │        │  │  ├─ ops.py
│     │        │  │  ├─ schemaobj.py
│     │        │  │  └─ toimpl.py
│     │        │  ├─ py.typed
│     │        │  ├─ runtime
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ environment.py
│     │        │  │  └─ migration.py
│     │        │  ├─ script
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ revision.py
│     │        │  │  └─ write_hooks.py
│     │        │  ├─ templates
│     │        │  │  ├─ async
│     │        │  │  │  ├─ README
│     │        │  │  │  ├─ alembic.ini.mako
│     │        │  │  │  ├─ env.py
│     │        │  │  │  └─ script.py.mako
│     │        │  │  ├─ generic
│     │        │  │  │  ├─ README
│     │        │  │  │  ├─ alembic.ini.mako
│     │        │  │  │  ├─ env.py
│     │        │  │  │  └─ script.py.mako
│     │        │  │  ├─ multidb
│     │        │  │  │  ├─ README
│     │        │  │  │  ├─ alembic.ini.mako
│     │        │  │  │  ├─ env.py
│     │        │  │  │  └─ script.py.mako
│     │        │  │  ├─ pyproject
│     │        │  │  │  ├─ README
│     │        │  │  │  ├─ alembic.ini.mako
│     │        │  │  │  ├─ env.py
│     │        │  │  │  ├─ pyproject.toml.mako
│     │        │  │  │  └─ script.py.mako
│     │        │  │  └─ pyproject_async
│     │        │  │     ├─ README
│     │        │  │     ├─ alembic.ini.mako
│     │        │  │     ├─ env.py
│     │        │  │     ├─ pyproject.toml.mako
│     │        │  │     └─ script.py.mako
│     │        │  ├─ testing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ assertions.py
│     │        │  │  ├─ env.py
│     │        │  │  ├─ fixtures.py
│     │        │  │  ├─ plugin
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ bootstrap.py
│     │        │  │  ├─ requirements.py
│     │        │  │  ├─ schemacompare.py
│     │        │  │  ├─ suite
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _autogen_fixtures.py
│     │        │  │  │  ├─ test_autogen_comments.py
│     │        │  │  │  ├─ test_autogen_computed.py
│     │        │  │  │  ├─ test_autogen_diffs.py
│     │        │  │  │  ├─ test_autogen_fks.py
│     │        │  │  │  ├─ test_autogen_identity.py
│     │        │  │  │  ├─ test_environment.py
│     │        │  │  │  └─ test_op.py
│     │        │  │  ├─ util.py
│     │        │  │  └─ warnings.py
│     │        │  └─ util
│     │        │     ├─ __init__.py
│     │        │     ├─ compat.py
│     │        │     ├─ editor.py
│     │        │     ├─ exc.py
│     │        │     ├─ langhelpers.py
│     │        │     ├─ messaging.py
│     │        │     ├─ pyfiles.py
│     │        │     └─ sqla_compat.py
│     │        ├─ alembic-1.16.4.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ annotated_types
│     │        │  ├─ __init__.py
│     │        │  ├─ py.typed
│     │        │  └─ test_cases.py
│     │        ├─ annotated_types-0.7.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ anyio
│     │        │  ├─ __init__.py
│     │        │  ├─ _backends
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _asyncio.py
│     │        │  │  └─ _trio.py
│     │        │  ├─ _core
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _asyncio_selector_thread.py
│     │        │  │  ├─ _eventloop.py
│     │        │  │  ├─ _exceptions.py
│     │        │  │  ├─ _fileio.py
│     │        │  │  ├─ _resources.py
│     │        │  │  ├─ _signals.py
│     │        │  │  ├─ _sockets.py
│     │        │  │  ├─ _streams.py
│     │        │  │  ├─ _subprocesses.py
│     │        │  │  ├─ _synchronization.py
│     │        │  │  ├─ _tasks.py
│     │        │  │  ├─ _tempfile.py
│     │        │  │  ├─ _testing.py
│     │        │  │  └─ _typedattr.py
│     │        │  ├─ abc
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _eventloop.py
│     │        │  │  ├─ _resources.py
│     │        │  │  ├─ _sockets.py
│     │        │  │  ├─ _streams.py
│     │        │  │  ├─ _subprocesses.py
│     │        │  │  ├─ _tasks.py
│     │        │  │  └─ _testing.py
│     │        │  ├─ from_thread.py
│     │        │  ├─ lowlevel.py
│     │        │  ├─ py.typed
│     │        │  ├─ pytest_plugin.py
│     │        │  ├─ streams
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ buffered.py
│     │        │  │  ├─ file.py
│     │        │  │  ├─ memory.py
│     │        │  │  ├─ stapled.py
│     │        │  │  ├─ text.py
│     │        │  │  └─ tls.py
│     │        │  ├─ to_interpreter.py
│     │        │  ├─ to_process.py
│     │        │  └─ to_thread.py
│     │        ├─ anyio-4.9.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  └─ top_level.txt
│     │        ├─ argon2
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ _legacy.py
│     │        │  ├─ _password_hasher.py
│     │        │  ├─ _typing.py
│     │        │  ├─ _utils.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ low_level.py
│     │        │  ├─ profiles.py
│     │        │  └─ py.typed
│     │        ├─ argon2_cffi-23.1.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ argon2_cffi_bindings-21.2.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ asgiref
│     │        │  ├─ __init__.py
│     │        │  ├─ compatibility.py
│     │        │  ├─ current_thread_executor.py
│     │        │  ├─ local.py
│     │        │  ├─ py.typed
│     │        │  ├─ server.py
│     │        │  ├─ sync.py
│     │        │  ├─ testing.py
│     │        │  ├─ timeout.py
│     │        │  ├─ typing.py
│     │        │  └─ wsgi.py
│     │        ├─ asgiref-3.8.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ attr
│     │        │  ├─ __init__.py
│     │        │  ├─ __init__.pyi
│     │        │  ├─ _cmp.py
│     │        │  ├─ _cmp.pyi
│     │        │  ├─ _compat.py
│     │        │  ├─ _config.py
│     │        │  ├─ _funcs.py
│     │        │  ├─ _make.py
│     │        │  ├─ _next_gen.py
│     │        │  ├─ _typing_compat.pyi
│     │        │  ├─ _version_info.py
│     │        │  ├─ _version_info.pyi
│     │        │  ├─ converters.py
│     │        │  ├─ converters.pyi
│     │        │  ├─ exceptions.py
│     │        │  ├─ exceptions.pyi
│     │        │  ├─ filters.py
│     │        │  ├─ filters.pyi
│     │        │  ├─ py.typed
│     │        │  ├─ setters.py
│     │        │  ├─ setters.pyi
│     │        │  ├─ validators.py
│     │        │  └─ validators.pyi
│     │        ├─ attrs
│     │        │  ├─ __init__.py
│     │        │  ├─ __init__.pyi
│     │        │  ├─ converters.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ filters.py
│     │        │  ├─ py.typed
│     │        │  ├─ setters.py
│     │        │  └─ validators.py
│     │        ├─ attrs-25.3.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ beautifulsoup4-4.13.4.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     ├─ AUTHORS
│     │        │     └─ LICENSE
│     │        ├─ blinker
│     │        │  ├─ __init__.py
│     │        │  ├─ _utilities.py
│     │        │  ├─ base.py
│     │        │  └─ py.typed
│     │        ├─ blinker-1.9.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  └─ WHEEL
│     │        ├─ brotli.py
│     │        ├─ bs4
│     │        │  ├─ __init__.py
│     │        │  ├─ _deprecation.py
│     │        │  ├─ _typing.py
│     │        │  ├─ _warnings.py
│     │        │  ├─ builder
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _html5lib.py
│     │        │  │  ├─ _htmlparser.py
│     │        │  │  └─ _lxml.py
│     │        │  ├─ css.py
│     │        │  ├─ dammit.py
│     │        │  ├─ diagnose.py
│     │        │  ├─ element.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ filter.py
│     │        │  ├─ formatter.py
│     │        │  ├─ py.typed
│     │        │  └─ tests
│     │        │     ├─ __init__.py
│     │        │     ├─ fuzz
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-4670634698080256.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-4818336571064320.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-4999465949331456.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-5000587759190016.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-5167584867909632.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-5270998950477824.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-5375146639360000.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-5492400320282624.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-5703933063462912.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-5843991618256896.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-5984173902397440.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-6124268085182464.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-6241471367348224.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-6306874195312640.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-6450958476902400.testcase
│     │        │     │  ├─ clusterfuzz-testcase-minimized-bs4_fuzzer-6600557255327744.testcase
│     │        │     │  ├─ crash-0d306a50c8ed8bcd0785b67000fcd5dea1d33f08.testcase
│     │        │     │  └─ crash-ffbdfa8a2b26f13537b68d3794b0478a4090ee4a.testcase
│     │        │     ├─ test_builder.py
│     │        │     ├─ test_builder_registry.py
│     │        │     ├─ test_css.py
│     │        │     ├─ test_dammit.py
│     │        │     ├─ test_element.py
│     │        │     ├─ test_filter.py
│     │        │     ├─ test_formatter.py
│     │        │     ├─ test_fuzz.py
│     │        │     ├─ test_html5lib.py
│     │        │     ├─ test_htmlparser.py
│     │        │     ├─ test_lxml.py
│     │        │     ├─ test_navigablestring.py
│     │        │     ├─ test_pageelement.py
│     │        │     ├─ test_soup.py
│     │        │     ├─ test_tag.py
│     │        │     └─ test_tree.py
│     │        ├─ certifi
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ cacert.pem
│     │        │  ├─ core.py
│     │        │  └─ py.typed
│     │        ├─ certifi-2025.7.14.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ cffi
│     │        │  ├─ __init__.py
│     │        │  ├─ _cffi_errors.h
│     │        │  ├─ _cffi_include.h
│     │        │  ├─ _embedding.h
│     │        │  ├─ _imp_emulation.py
│     │        │  ├─ _shimmed_dist_utils.py
│     │        │  ├─ api.py
│     │        │  ├─ backend_ctypes.py
│     │        │  ├─ cffi_opcode.py
│     │        │  ├─ commontypes.py
│     │        │  ├─ cparser.py
│     │        │  ├─ error.py
│     │        │  ├─ ffiplatform.py
│     │        │  ├─ lock.py
│     │        │  ├─ model.py
│     │        │  ├─ parse_c_type.h
│     │        │  ├─ pkgconfig.py
│     │        │  ├─ recompiler.py
│     │        │  ├─ setuptools_ext.py
│     │        │  ├─ vengine_cpy.py
│     │        │  ├─ vengine_gen.py
│     │        │  └─ verifier.py
│     │        ├─ cffi-1.17.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  └─ top_level.txt
│     │        ├─ charset_normalizer
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ api.py
│     │        │  ├─ cd.py
│     │        │  ├─ cli
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ __main__.py
│     │        │  ├─ constant.py
│     │        │  ├─ legacy.py
│     │        │  ├─ md.cpython-312-darwin.so
│     │        │  ├─ md.py
│     │        │  ├─ md__mypyc.cpython-312-darwin.so
│     │        │  ├─ models.py
│     │        │  ├─ py.typed
│     │        │  ├─ utils.py
│     │        │  └─ version.py
│     │        ├─ charset_normalizer-3.4.2.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ click
│     │        │  ├─ __init__.py
│     │        │  ├─ _compat.py
│     │        │  ├─ _termui_impl.py
│     │        │  ├─ _textwrap.py
│     │        │  ├─ _winconsole.py
│     │        │  ├─ core.py
│     │        │  ├─ decorators.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ formatting.py
│     │        │  ├─ globals.py
│     │        │  ├─ parser.py
│     │        │  ├─ py.typed
│     │        │  ├─ shell_completion.py
│     │        │  ├─ termui.py
│     │        │  ├─ testing.py
│     │        │  ├─ types.py
│     │        │  └─ utils.py
│     │        ├─ click-8.2.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE.txt
│     │        ├─ cryptography
│     │        │  ├─ __about__.py
│     │        │  ├─ __init__.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ fernet.py
│     │        │  ├─ hazmat
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _oid.py
│     │        │  │  ├─ backends
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ openssl
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     └─ backend.py
│     │        │  │  ├─ bindings
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _rust
│     │        │  │  │  │  ├─ __init__.pyi
│     │        │  │  │  │  ├─ _openssl.pyi
│     │        │  │  │  │  ├─ asn1.pyi
│     │        │  │  │  │  ├─ exceptions.pyi
│     │        │  │  │  │  ├─ ocsp.pyi
│     │        │  │  │  │  ├─ openssl
│     │        │  │  │  │  │  ├─ __init__.pyi
│     │        │  │  │  │  │  ├─ aead.pyi
│     │        │  │  │  │  │  ├─ ciphers.pyi
│     │        │  │  │  │  │  ├─ cmac.pyi
│     │        │  │  │  │  │  ├─ dh.pyi
│     │        │  │  │  │  │  ├─ dsa.pyi
│     │        │  │  │  │  │  ├─ ec.pyi
│     │        │  │  │  │  │  ├─ ed25519.pyi
│     │        │  │  │  │  │  ├─ ed448.pyi
│     │        │  │  │  │  │  ├─ hashes.pyi
│     │        │  │  │  │  │  ├─ hmac.pyi
│     │        │  │  │  │  │  ├─ kdf.pyi
│     │        │  │  │  │  │  ├─ keys.pyi
│     │        │  │  │  │  │  ├─ poly1305.pyi
│     │        │  │  │  │  │  ├─ rsa.pyi
│     │        │  │  │  │  │  ├─ x25519.pyi
│     │        │  │  │  │  │  └─ x448.pyi
│     │        │  │  │  │  ├─ pkcs12.pyi
│     │        │  │  │  │  ├─ pkcs7.pyi
│     │        │  │  │  │  ├─ test_support.pyi
│     │        │  │  │  │  └─ x509.pyi
│     │        │  │  │  ├─ _rust.abi3.so
│     │        │  │  │  └─ openssl
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ _conditional.py
│     │        │  │  │     └─ binding.py
│     │        │  │  ├─ decrepit
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ ciphers
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     └─ algorithms.py
│     │        │  │  └─ primitives
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ _asymmetric.py
│     │        │  │     ├─ _cipheralgorithm.py
│     │        │  │     ├─ _serialization.py
│     │        │  │     ├─ asymmetric
│     │        │  │     │  ├─ __init__.py
│     │        │  │     │  ├─ dh.py
│     │        │  │     │  ├─ dsa.py
│     │        │  │     │  ├─ ec.py
│     │        │  │     │  ├─ ed25519.py
│     │        │  │     │  ├─ ed448.py
│     │        │  │     │  ├─ padding.py
│     │        │  │     │  ├─ rsa.py
│     │        │  │     │  ├─ types.py
│     │        │  │     │  ├─ utils.py
│     │        │  │     │  ├─ x25519.py
│     │        │  │     │  └─ x448.py
│     │        │  │     ├─ ciphers
│     │        │  │     │  ├─ __init__.py
│     │        │  │     │  ├─ aead.py
│     │        │  │     │  ├─ algorithms.py
│     │        │  │     │  ├─ base.py
│     │        │  │     │  └─ modes.py
│     │        │  │     ├─ cmac.py
│     │        │  │     ├─ constant_time.py
│     │        │  │     ├─ hashes.py
│     │        │  │     ├─ hmac.py
│     │        │  │     ├─ kdf
│     │        │  │     │  ├─ __init__.py
│     │        │  │     │  ├─ argon2.py
│     │        │  │     │  ├─ concatkdf.py
│     │        │  │     │  ├─ hkdf.py
│     │        │  │     │  ├─ kbkdf.py
│     │        │  │     │  ├─ pbkdf2.py
│     │        │  │     │  ├─ scrypt.py
│     │        │  │     │  └─ x963kdf.py
│     │        │  │     ├─ keywrap.py
│     │        │  │     ├─ padding.py
│     │        │  │     ├─ poly1305.py
│     │        │  │     ├─ serialization
│     │        │  │     │  ├─ __init__.py
│     │        │  │     │  ├─ base.py
│     │        │  │     │  ├─ pkcs12.py
│     │        │  │     │  ├─ pkcs7.py
│     │        │  │     │  └─ ssh.py
│     │        │  │     └─ twofactor
│     │        │  │        ├─ __init__.py
│     │        │  │        ├─ hotp.py
│     │        │  │        └─ totp.py
│     │        │  ├─ py.typed
│     │        │  ├─ utils.py
│     │        │  └─ x509
│     │        │     ├─ __init__.py
│     │        │     ├─ base.py
│     │        │     ├─ certificate_transparency.py
│     │        │     ├─ extensions.py
│     │        │     ├─ general_name.py
│     │        │     ├─ name.py
│     │        │     ├─ ocsp.py
│     │        │     ├─ oid.py
│     │        │     └─ verification.py
│     │        ├─ cryptography-44.0.3.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     ├─ LICENSE
│     │        │     ├─ LICENSE.APACHE
│     │        │     └─ LICENSE.BSD
│     │        ├─ dateutil
│     │        │  ├─ __init__.py
│     │        │  ├─ _common.py
│     │        │  ├─ _version.py
│     │        │  ├─ easter.py
│     │        │  ├─ parser
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _parser.py
│     │        │  │  └─ isoparser.py
│     │        │  ├─ relativedelta.py
│     │        │  ├─ rrule.py
│     │        │  ├─ tz
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _common.py
│     │        │  │  ├─ _factories.py
│     │        │  │  ├─ tz.py
│     │        │  │  └─ win.py
│     │        │  ├─ tzwin.py
│     │        │  ├─ utils.py
│     │        │  └─ zoneinfo
│     │        │     ├─ __init__.py
│     │        │     ├─ dateutil-zoneinfo.tar.gz
│     │        │     └─ rebuild.py
│     │        ├─ distutils-precedence.pth
│     │        ├─ dotenv
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ cli.py
│     │        │  ├─ ipython.py
│     │        │  ├─ main.py
│     │        │  ├─ parser.py
│     │        │  ├─ py.typed
│     │        │  ├─ variables.py
│     │        │  └─ version.py
│     │        ├─ fastapi
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ _compat.py
│     │        │  ├─ applications.py
│     │        │  ├─ background.py
│     │        │  ├─ cli.py
│     │        │  ├─ concurrency.py
│     │        │  ├─ datastructures.py
│     │        │  ├─ dependencies
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ models.py
│     │        │  │  └─ utils.py
│     │        │  ├─ encoders.py
│     │        │  ├─ exception_handlers.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ logger.py
│     │        │  ├─ middleware
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ cors.py
│     │        │  │  ├─ gzip.py
│     │        │  │  ├─ httpsredirect.py
│     │        │  │  ├─ trustedhost.py
│     │        │  │  └─ wsgi.py
│     │        │  ├─ openapi
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ constants.py
│     │        │  │  ├─ docs.py
│     │        │  │  ├─ models.py
│     │        │  │  └─ utils.py
│     │        │  ├─ param_functions.py
│     │        │  ├─ params.py
│     │        │  ├─ py.typed
│     │        │  ├─ requests.py
│     │        │  ├─ responses.py
│     │        │  ├─ routing.py
│     │        │  ├─ security
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ api_key.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ http.py
│     │        │  │  ├─ oauth2.py
│     │        │  │  ├─ open_id_connect_url.py
│     │        │  │  └─ utils.py
│     │        │  ├─ staticfiles.py
│     │        │  ├─ templating.py
│     │        │  ├─ testclient.py
│     │        │  ├─ types.py
│     │        │  ├─ utils.py
│     │        │  └─ websockets.py
│     │        ├─ fastapi-0.116.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ flask
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ app.py
│     │        │  ├─ blueprints.py
│     │        │  ├─ cli.py
│     │        │  ├─ config.py
│     │        │  ├─ ctx.py
│     │        │  ├─ debughelpers.py
│     │        │  ├─ globals.py
│     │        │  ├─ helpers.py
│     │        │  ├─ json
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ provider.py
│     │        │  │  └─ tag.py
│     │        │  ├─ logging.py
│     │        │  ├─ py.typed
│     │        │  ├─ sansio
│     │        │  │  ├─ README.md
│     │        │  │  ├─ app.py
│     │        │  │  ├─ blueprints.py
│     │        │  │  └─ scaffold.py
│     │        │  ├─ sessions.py
│     │        │  ├─ signals.py
│     │        │  ├─ templating.py
│     │        │  ├─ testing.py
│     │        │  ├─ typing.py
│     │        │  ├─ views.py
│     │        │  └─ wrappers.py
│     │        ├─ flask-3.1.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ entry_points.txt
│     │        ├─ greenlet
│     │        │  ├─ CObjects.cpp
│     │        │  ├─ PyGreenlet.cpp
│     │        │  ├─ PyGreenlet.hpp
│     │        │  ├─ PyGreenletUnswitchable.cpp
│     │        │  ├─ PyModule.cpp
│     │        │  ├─ TBrokenGreenlet.cpp
│     │        │  ├─ TExceptionState.cpp
│     │        │  ├─ TGreenlet.cpp
│     │        │  ├─ TGreenlet.hpp
│     │        │  ├─ TGreenletGlobals.cpp
│     │        │  ├─ TMainGreenlet.cpp
│     │        │  ├─ TPythonState.cpp
│     │        │  ├─ TStackState.cpp
│     │        │  ├─ TThreadState.hpp
│     │        │  ├─ TThreadStateCreator.hpp
│     │        │  ├─ TThreadStateDestroy.cpp
│     │        │  ├─ TUserGreenlet.cpp
│     │        │  ├─ __init__.py
│     │        │  ├─ _greenlet.cpython-312-darwin.so
│     │        │  ├─ greenlet.cpp
│     │        │  ├─ greenlet.h
│     │        │  ├─ greenlet_allocator.hpp
│     │        │  ├─ greenlet_compiler_compat.hpp
│     │        │  ├─ greenlet_cpython_compat.hpp
│     │        │  ├─ greenlet_exceptions.hpp
│     │        │  ├─ greenlet_internal.hpp
│     │        │  ├─ greenlet_msvc_compat.hpp
│     │        │  ├─ greenlet_refs.hpp
│     │        │  ├─ greenlet_slp_switch.hpp
│     │        │  ├─ greenlet_thread_support.hpp
│     │        │  ├─ platform
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ setup_switch_x64_masm.cmd
│     │        │  │  ├─ switch_aarch64_gcc.h
│     │        │  │  ├─ switch_alpha_unix.h
│     │        │  │  ├─ switch_amd64_unix.h
│     │        │  │  ├─ switch_arm32_gcc.h
│     │        │  │  ├─ switch_arm32_ios.h
│     │        │  │  ├─ switch_arm64_masm.asm
│     │        │  │  ├─ switch_arm64_masm.obj
│     │        │  │  ├─ switch_arm64_msvc.h
│     │        │  │  ├─ switch_csky_gcc.h
│     │        │  │  ├─ switch_loongarch64_linux.h
│     │        │  │  ├─ switch_m68k_gcc.h
│     │        │  │  ├─ switch_mips_unix.h
│     │        │  │  ├─ switch_ppc64_aix.h
│     │        │  │  ├─ switch_ppc64_linux.h
│     │        │  │  ├─ switch_ppc_aix.h
│     │        │  │  ├─ switch_ppc_linux.h
│     │        │  │  ├─ switch_ppc_macosx.h
│     │        │  │  ├─ switch_ppc_unix.h
│     │        │  │  ├─ switch_riscv_unix.h
│     │        │  │  ├─ switch_s390_unix.h
│     │        │  │  ├─ switch_sh_gcc.h
│     │        │  │  ├─ switch_sparc_sun_gcc.h
│     │        │  │  ├─ switch_x32_unix.h
│     │        │  │  ├─ switch_x64_masm.asm
│     │        │  │  ├─ switch_x64_masm.obj
│     │        │  │  ├─ switch_x64_msvc.h
│     │        │  │  ├─ switch_x86_msvc.h
│     │        │  │  └─ switch_x86_unix.h
│     │        │  ├─ slp_platformselect.h
│     │        │  └─ tests
│     │        │     ├─ __init__.py
│     │        │     ├─ _test_extension.c
│     │        │     ├─ _test_extension.cpython-312-darwin.so
│     │        │     ├─ _test_extension_cpp.cpp
│     │        │     ├─ _test_extension_cpp.cpython-312-darwin.so
│     │        │     ├─ fail_clearing_run_switches.py
│     │        │     ├─ fail_cpp_exception.py
│     │        │     ├─ fail_initialstub_already_started.py
│     │        │     ├─ fail_slp_switch.py
│     │        │     ├─ fail_switch_three_greenlets.py
│     │        │     ├─ fail_switch_three_greenlets2.py
│     │        │     ├─ fail_switch_two_greenlets.py
│     │        │     ├─ leakcheck.py
│     │        │     ├─ test_contextvars.py
│     │        │     ├─ test_cpp.py
│     │        │     ├─ test_extension_interface.py
│     │        │     ├─ test_gc.py
│     │        │     ├─ test_generator.py
│     │        │     ├─ test_generator_nested.py
│     │        │     ├─ test_greenlet.py
│     │        │     ├─ test_greenlet_trash.py
│     │        │     ├─ test_leaks.py
│     │        │     ├─ test_stack_saved.py
│     │        │     ├─ test_throw.py
│     │        │     ├─ test_tracing.py
│     │        │     ├─ test_version.py
│     │        │     └─ test_weakref.py
│     │        ├─ greenlet-3.2.3.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  ├─ LICENSE
│     │        │  │  └─ LICENSE.PSF
│     │        │  └─ top_level.txt
│     │        ├─ h11
│     │        │  ├─ __init__.py
│     │        │  ├─ _abnf.py
│     │        │  ├─ _connection.py
│     │        │  ├─ _events.py
│     │        │  ├─ _headers.py
│     │        │  ├─ _readers.py
│     │        │  ├─ _receivebuffer.py
│     │        │  ├─ _state.py
│     │        │  ├─ _util.py
│     │        │  ├─ _version.py
│     │        │  ├─ _writers.py
│     │        │  └─ py.typed
│     │        ├─ h11-0.16.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE.txt
│     │        │  └─ top_level.txt
│     │        ├─ h2
│     │        │  ├─ __init__.py
│     │        │  ├─ config.py
│     │        │  ├─ connection.py
│     │        │  ├─ errors.py
│     │        │  ├─ events.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ frame_buffer.py
│     │        │  ├─ settings.py
│     │        │  ├─ stream.py
│     │        │  ├─ utilities.py
│     │        │  └─ windows.py
│     │        ├─ h2-4.1.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ hpack
│     │        │  ├─ __init__.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ hpack.py
│     │        │  ├─ huffman.py
│     │        │  ├─ huffman_constants.py
│     │        │  ├─ huffman_table.py
│     │        │  ├─ py.typed
│     │        │  ├─ struct.py
│     │        │  └─ table.py
│     │        ├─ hpack-4.1.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ httpcore
│     │        │  ├─ __init__.py
│     │        │  ├─ _api.py
│     │        │  ├─ _async
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ connection.py
│     │        │  │  ├─ connection_pool.py
│     │        │  │  ├─ http11.py
│     │        │  │  ├─ http2.py
│     │        │  │  ├─ http_proxy.py
│     │        │  │  ├─ interfaces.py
│     │        │  │  └─ socks_proxy.py
│     │        │  ├─ _backends
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ anyio.py
│     │        │  │  ├─ auto.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ mock.py
│     │        │  │  ├─ sync.py
│     │        │  │  └─ trio.py
│     │        │  ├─ _exceptions.py
│     │        │  ├─ _models.py
│     │        │  ├─ _ssl.py
│     │        │  ├─ _sync
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ connection.py
│     │        │  │  ├─ connection_pool.py
│     │        │  │  ├─ http11.py
│     │        │  │  ├─ http2.py
│     │        │  │  ├─ http_proxy.py
│     │        │  │  ├─ interfaces.py
│     │        │  │  └─ socks_proxy.py
│     │        │  ├─ _synchronization.py
│     │        │  ├─ _trace.py
│     │        │  ├─ _utils.py
│     │        │  └─ py.typed
│     │        ├─ httpcore-1.0.9.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE.md
│     │        ├─ httptools
│     │        │  ├─ __init__.py
│     │        │  ├─ _version.py
│     │        │  └─ parser
│     │        │     ├─ __init__.py
│     │        │     ├─ cparser.pxd
│     │        │     ├─ errors.py
│     │        │     ├─ parser.cpython-312-darwin.so
│     │        │     ├─ parser.pyx
│     │        │     ├─ python.pxd
│     │        │     ├─ url_cparser.pxd
│     │        │     ├─ url_parser.cpython-312-darwin.so
│     │        │     └─ url_parser.pyx
│     │        ├─ httptools-0.6.4.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ httpx
│     │        │  ├─ __init__.py
│     │        │  ├─ __version__.py
│     │        │  ├─ _api.py
│     │        │  ├─ _auth.py
│     │        │  ├─ _client.py
│     │        │  ├─ _config.py
│     │        │  ├─ _content.py
│     │        │  ├─ _decoders.py
│     │        │  ├─ _exceptions.py
│     │        │  ├─ _main.py
│     │        │  ├─ _models.py
│     │        │  ├─ _multipart.py
│     │        │  ├─ _status_codes.py
│     │        │  ├─ _transports
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ asgi.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ default.py
│     │        │  │  ├─ mock.py
│     │        │  │  └─ wsgi.py
│     │        │  ├─ _types.py
│     │        │  ├─ _urlparse.py
│     │        │  ├─ _urls.py
│     │        │  ├─ _utils.py
│     │        │  └─ py.typed
│     │        ├─ httpx-0.28.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  └─ licenses
│     │        │     └─ LICENSE.md
│     │        ├─ hyperframe
│     │        │  ├─ __init__.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ flags.py
│     │        │  ├─ frame.py
│     │        │  └─ py.typed
│     │        ├─ hyperframe-6.1.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ idna
│     │        │  ├─ __init__.py
│     │        │  ├─ codec.py
│     │        │  ├─ compat.py
│     │        │  ├─ core.py
│     │        │  ├─ idnadata.py
│     │        │  ├─ intranges.py
│     │        │  ├─ package_data.py
│     │        │  ├─ py.typed
│     │        │  └─ uts46data.py
│     │        ├─ idna-3.10.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.md
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  └─ WHEEL
│     │        ├─ itsdangerous
│     │        │  ├─ __init__.py
│     │        │  ├─ _json.py
│     │        │  ├─ encoding.py
│     │        │  ├─ exc.py
│     │        │  ├─ py.typed
│     │        │  ├─ serializer.py
│     │        │  ├─ signer.py
│     │        │  ├─ timed.py
│     │        │  └─ url_safe.py
│     │        ├─ itsdangerous-2.2.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  └─ WHEEL
│     │        ├─ jinja2
│     │        │  ├─ __init__.py
│     │        │  ├─ _identifier.py
│     │        │  ├─ async_utils.py
│     │        │  ├─ bccache.py
│     │        │  ├─ compiler.py
│     │        │  ├─ constants.py
│     │        │  ├─ debug.py
│     │        │  ├─ defaults.py
│     │        │  ├─ environment.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ ext.py
│     │        │  ├─ filters.py
│     │        │  ├─ idtracking.py
│     │        │  ├─ lexer.py
│     │        │  ├─ loaders.py
│     │        │  ├─ meta.py
│     │        │  ├─ nativetypes.py
│     │        │  ├─ nodes.py
│     │        │  ├─ optimizer.py
│     │        │  ├─ parser.py
│     │        │  ├─ py.typed
│     │        │  ├─ runtime.py
│     │        │  ├─ sandbox.py
│     │        │  ├─ tests.py
│     │        │  ├─ utils.py
│     │        │  └─ visitor.py
│     │        ├─ jinja2-3.1.6.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  └─ licenses
│     │        │     └─ LICENSE.txt
│     │        ├─ joblib
│     │        │  ├─ __init__.py
│     │        │  ├─ _cloudpickle_wrapper.py
│     │        │  ├─ _dask.py
│     │        │  ├─ _memmapping_reducer.py
│     │        │  ├─ _multiprocessing_helpers.py
│     │        │  ├─ _parallel_backends.py
│     │        │  ├─ _store_backends.py
│     │        │  ├─ _utils.py
│     │        │  ├─ backports.py
│     │        │  ├─ compressor.py
│     │        │  ├─ disk.py
│     │        │  ├─ executor.py
│     │        │  ├─ externals
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ cloudpickle
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ cloudpickle.py
│     │        │  │  │  └─ cloudpickle_fast.py
│     │        │  │  └─ loky
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ _base.py
│     │        │  │     ├─ backend
│     │        │  │     │  ├─ __init__.py
│     │        │  │     │  ├─ _posix_reduction.py
│     │        │  │     │  ├─ _win_reduction.py
│     │        │  │     │  ├─ context.py
│     │        │  │     │  ├─ fork_exec.py
│     │        │  │     │  ├─ popen_loky_posix.py
│     │        │  │     │  ├─ popen_loky_win32.py
│     │        │  │     │  ├─ process.py
│     │        │  │     │  ├─ queues.py
│     │        │  │     │  ├─ reduction.py
│     │        │  │     │  ├─ resource_tracker.py
│     │        │  │     │  ├─ spawn.py
│     │        │  │     │  ├─ synchronize.py
│     │        │  │     │  └─ utils.py
│     │        │  │     ├─ cloudpickle_wrapper.py
│     │        │  │     ├─ initializers.py
│     │        │  │     ├─ process_executor.py
│     │        │  │     └─ reusable_executor.py
│     │        │  ├─ func_inspect.py
│     │        │  ├─ hashing.py
│     │        │  ├─ logger.py
│     │        │  ├─ memory.py
│     │        │  ├─ numpy_pickle.py
│     │        │  ├─ numpy_pickle_compat.py
│     │        │  ├─ numpy_pickle_utils.py
│     │        │  ├─ parallel.py
│     │        │  ├─ pool.py
│     │        │  ├─ test
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ common.py
│     │        │  │  ├─ test_backports.py
│     │        │  │  ├─ test_cloudpickle_wrapper.py
│     │        │  │  ├─ test_config.py
│     │        │  │  ├─ test_dask.py
│     │        │  │  ├─ test_disk.py
│     │        │  │  ├─ test_func_inspect.py
│     │        │  │  ├─ test_func_inspect_special_encoding.py
│     │        │  │  ├─ test_hashing.py
│     │        │  │  ├─ test_init.py
│     │        │  │  ├─ test_logger.py
│     │        │  │  ├─ test_memmapping.py
│     │        │  │  ├─ test_memory.py
│     │        │  │  ├─ test_memory_async.py
│     │        │  │  ├─ test_missing_multiprocessing.py
│     │        │  │  ├─ test_module.py
│     │        │  │  ├─ test_numpy_pickle.py
│     │        │  │  ├─ test_numpy_pickle_compat.py
│     │        │  │  ├─ test_numpy_pickle_utils.py
│     │        │  │  ├─ test_parallel.py
│     │        │  │  ├─ test_store_backends.py
│     │        │  │  ├─ test_testing.py
│     │        │  │  ├─ test_utils.py
│     │        │  │  └─ testutils.py
│     │        │  └─ testing.py
│     │        ├─ joblib-1.5.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE.txt
│     │        │  └─ top_level.txt
│     │        ├─ kaitaistruct-0.10.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ top_level.txt
│     │        │  └─ zip-safe
│     │        ├─ kaitaistruct.py
│     │        ├─ ldap3
│     │        │  ├─ __init__.py
│     │        │  ├─ abstract
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ attrDef.py
│     │        │  │  ├─ attribute.py
│     │        │  │  ├─ cursor.py
│     │        │  │  ├─ entry.py
│     │        │  │  └─ objectDef.py
│     │        │  ├─ core
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ connection.py
│     │        │  │  ├─ exceptions.py
│     │        │  │  ├─ pooling.py
│     │        │  │  ├─ rdns.py
│     │        │  │  ├─ results.py
│     │        │  │  ├─ server.py
│     │        │  │  ├─ timezone.py
│     │        │  │  ├─ tls.py
│     │        │  │  └─ usage.py
│     │        │  ├─ extend
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ microsoft
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ addMembersToGroups.py
│     │        │  │  │  ├─ dirSync.py
│     │        │  │  │  ├─ modifyPassword.py
│     │        │  │  │  ├─ persistentSearch.py
│     │        │  │  │  ├─ removeMembersFromGroups.py
│     │        │  │  │  └─ unlockAccount.py
│     │        │  │  ├─ novell
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ addMembersToGroups.py
│     │        │  │  │  ├─ checkGroupsMemberships.py
│     │        │  │  │  ├─ endTransaction.py
│     │        │  │  │  ├─ getBindDn.py
│     │        │  │  │  ├─ listReplicas.py
│     │        │  │  │  ├─ nmasGetUniversalPassword.py
│     │        │  │  │  ├─ nmasSetUniversalPassword.py
│     │        │  │  │  ├─ partition_entry_count.py
│     │        │  │  │  ├─ removeMembersFromGroups.py
│     │        │  │  │  ├─ replicaInfo.py
│     │        │  │  │  └─ startTransaction.py
│     │        │  │  ├─ operation.py
│     │        │  │  └─ standard
│     │        │  │     ├─ PagedSearch.py
│     │        │  │     ├─ PersistentSearch.py
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ modifyPassword.py
│     │        │  │     └─ whoAmI.py
│     │        │  ├─ operation
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ abandon.py
│     │        │  │  ├─ add.py
│     │        │  │  ├─ bind.py
│     │        │  │  ├─ compare.py
│     │        │  │  ├─ delete.py
│     │        │  │  ├─ extended.py
│     │        │  │  ├─ modify.py
│     │        │  │  ├─ modifyDn.py
│     │        │  │  ├─ search.py
│     │        │  │  └─ unbind.py
│     │        │  ├─ protocol
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ controls.py
│     │        │  │  ├─ convert.py
│     │        │  │  ├─ formatters
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ formatters.py
│     │        │  │  │  ├─ standard.py
│     │        │  │  │  └─ validators.py
│     │        │  │  ├─ microsoft.py
│     │        │  │  ├─ novell.py
│     │        │  │  ├─ oid.py
│     │        │  │  ├─ persistentSearch.py
│     │        │  │  ├─ rfc2696.py
│     │        │  │  ├─ rfc2849.py
│     │        │  │  ├─ rfc3062.py
│     │        │  │  ├─ rfc4511.py
│     │        │  │  ├─ rfc4512.py
│     │        │  │  ├─ rfc4527.py
│     │        │  │  ├─ sasl
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ digestMd5.py
│     │        │  │  │  ├─ external.py
│     │        │  │  │  ├─ kerberos.py
│     │        │  │  │  ├─ plain.py
│     │        │  │  │  └─ sasl.py
│     │        │  │  └─ schemas
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ ad2012R2.py
│     │        │  │     ├─ ds389.py
│     │        │  │     ├─ edir888.py
│     │        │  │     ├─ edir914.py
│     │        │  │     └─ slapd24.py
│     │        │  ├─ strategy
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ asyncStream.py
│     │        │  │  ├─ asynchronous.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ ldifProducer.py
│     │        │  │  ├─ mockAsync.py
│     │        │  │  ├─ mockBase.py
│     │        │  │  ├─ mockSync.py
│     │        │  │  ├─ restartable.py
│     │        │  │  ├─ reusable.py
│     │        │  │  ├─ safeRestartable.py
│     │        │  │  ├─ safeSync.py
│     │        │  │  └─ sync.py
│     │        │  ├─ utils
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ asn1.py
│     │        │  │  ├─ ciDict.py
│     │        │  │  ├─ config.py
│     │        │  │  ├─ conv.py
│     │        │  │  ├─ dn.py
│     │        │  │  ├─ hashed.py
│     │        │  │  ├─ log.py
│     │        │  │  ├─ ntlm.py
│     │        │  │  ├─ ordDict.py
│     │        │  │  ├─ port_validators.py
│     │        │  │  ├─ repr.py
│     │        │  │  ├─ tls_backport.py
│     │        │  │  └─ uri.py
│     │        │  └─ version.py
│     │        ├─ ldap3-2.9.1.dist-info
│     │        │  ├─ COPYING.LESSER.txt
│     │        │  ├─ COPYING.txt
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ lightgbm
│     │        │  ├─ VERSION.txt
│     │        │  ├─ __init__.py
│     │        │  ├─ basic.py
│     │        │  ├─ callback.py
│     │        │  ├─ compat.py
│     │        │  ├─ dask.py
│     │        │  ├─ engine.py
│     │        │  ├─ lib
│     │        │  │  └─ lib_lightgbm.dylib
│     │        │  ├─ libpath.py
│     │        │  ├─ plotting.py
│     │        │  ├─ py.typed
│     │        │  └─ sklearn.py
│     │        ├─ lightgbm-4.6.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ mako
│     │        │  ├─ __init__.py
│     │        │  ├─ _ast_util.py
│     │        │  ├─ ast.py
│     │        │  ├─ cache.py
│     │        │  ├─ cmd.py
│     │        │  ├─ codegen.py
│     │        │  ├─ compat.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ ext
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ autohandler.py
│     │        │  │  ├─ babelplugin.py
│     │        │  │  ├─ beaker_cache.py
│     │        │  │  ├─ extract.py
│     │        │  │  ├─ linguaplugin.py
│     │        │  │  ├─ preprocessors.py
│     │        │  │  ├─ pygmentplugin.py
│     │        │  │  └─ turbogears.py
│     │        │  ├─ filters.py
│     │        │  ├─ lexer.py
│     │        │  ├─ lookup.py
│     │        │  ├─ parsetree.py
│     │        │  ├─ pygen.py
│     │        │  ├─ pyparser.py
│     │        │  ├─ runtime.py
│     │        │  ├─ template.py
│     │        │  ├─ testing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _config.py
│     │        │  │  ├─ assertions.py
│     │        │  │  ├─ config.py
│     │        │  │  ├─ exclusions.py
│     │        │  │  ├─ fixtures.py
│     │        │  │  └─ helpers.py
│     │        │  └─ util.py
│     │        ├─ mako-1.3.10.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ markupsafe
│     │        │  ├─ __init__.py
│     │        │  ├─ _native.py
│     │        │  ├─ _speedups.c
│     │        │  ├─ _speedups.cpython-312-darwin.so
│     │        │  ├─ _speedups.pyi
│     │        │  └─ py.typed
│     │        ├─ mitmproxy
│     │        │  ├─ __init__.py
│     │        │  ├─ addonmanager.py
│     │        │  ├─ addons
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ anticache.py
│     │        │  │  ├─ anticomp.py
│     │        │  │  ├─ asgiapp.py
│     │        │  │  ├─ block.py
│     │        │  │  ├─ blocklist.py
│     │        │  │  ├─ browser.py
│     │        │  │  ├─ clientplayback.py
│     │        │  │  ├─ command_history.py
│     │        │  │  ├─ comment.py
│     │        │  │  ├─ core.py
│     │        │  │  ├─ cut.py
│     │        │  │  ├─ disable_h2c.py
│     │        │  │  ├─ dns_resolver.py
│     │        │  │  ├─ dumper.py
│     │        │  │  ├─ errorcheck.py
│     │        │  │  ├─ eventstore.py
│     │        │  │  ├─ export.py
│     │        │  │  ├─ intercept.py
│     │        │  │  ├─ keepserving.py
│     │        │  │  ├─ maplocal.py
│     │        │  │  ├─ mapremote.py
│     │        │  │  ├─ modifybody.py
│     │        │  │  ├─ modifyheaders.py
│     │        │  │  ├─ next_layer.py
│     │        │  │  ├─ onboarding.py
│     │        │  │  ├─ onboardingapp
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ static
│     │        │  │  │  │  ├─ bootstrap.min.css
│     │        │  │  │  │  ├─ images
│     │        │  │  │  │  │  ├─ favicon.ico
│     │        │  │  │  │  │  └─ mitmproxy-long.png
│     │        │  │  │  │  └─ mitmproxy.css
│     │        │  │  │  └─ templates
│     │        │  │  │     ├─ icons
│     │        │  │  │     │  ├─ android-brands.svg
│     │        │  │  │     │  ├─ apple-brands.svg
│     │        │  │  │     │  ├─ certificate-solid.svg
│     │        │  │  │     │  ├─ firefox-browser-brands.svg
│     │        │  │  │     │  ├─ linux-brands.svg
│     │        │  │  │     │  └─ windows-brands.svg
│     │        │  │  │     ├─ index.html
│     │        │  │  │     └─ layout.html
│     │        │  │  ├─ proxyauth.py
│     │        │  │  ├─ proxyserver.py
│     │        │  │  ├─ readfile.py
│     │        │  │  ├─ save.py
│     │        │  │  ├─ savehar.py
│     │        │  │  ├─ script.py
│     │        │  │  ├─ server_side_events.py
│     │        │  │  ├─ serverplayback.py
│     │        │  │  ├─ stickyauth.py
│     │        │  │  ├─ stickycookie.py
│     │        │  │  ├─ strip_dns_https_records.py
│     │        │  │  ├─ termlog.py
│     │        │  │  ├─ tlsconfig.py
│     │        │  │  ├─ update_alt_svc.py
│     │        │  │  ├─ upstream_auth.py
│     │        │  │  └─ view.py
│     │        │  ├─ certs.py
│     │        │  ├─ command.py
│     │        │  ├─ command_lexer.py
│     │        │  ├─ connection.py
│     │        │  ├─ contentviews
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _api.py
│     │        │  │  ├─ _compat.py
│     │        │  │  ├─ _registry.py
│     │        │  │  ├─ _utils.py
│     │        │  │  ├─ _view_css.py
│     │        │  │  ├─ _view_dns.py
│     │        │  │  ├─ _view_graphql.py
│     │        │  │  ├─ _view_http3.py
│     │        │  │  ├─ _view_image
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ image_parser.py
│     │        │  │  │  └─ view.py
│     │        │  │  ├─ _view_javascript.py
│     │        │  │  ├─ _view_json.py
│     │        │  │  ├─ _view_mqtt.py
│     │        │  │  ├─ _view_multipart.py
│     │        │  │  ├─ _view_query.py
│     │        │  │  ├─ _view_raw.py
│     │        │  │  ├─ _view_socketio.py
│     │        │  │  ├─ _view_urlencoded.py
│     │        │  │  ├─ _view_wbxml.py
│     │        │  │  ├─ _view_xml_html.py
│     │        │  │  └─ base.py
│     │        │  ├─ contrib
│     │        │  │  ├─ README.md
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ click
│     │        │  │  │  ├─ LICENSE.BSD-3
│     │        │  │  │  └─ __init__.py
│     │        │  │  ├─ imghdr.py
│     │        │  │  ├─ kaitaistruct
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ README.md
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ dtls_client_hello.ksy
│     │        │  │  │  ├─ dtls_client_hello.py
│     │        │  │  │  ├─ exif.py
│     │        │  │  │  ├─ gif.py
│     │        │  │  │  ├─ google_protobuf.py
│     │        │  │  │  ├─ ico.py
│     │        │  │  │  ├─ jpeg.py
│     │        │  │  │  ├─ make.sh
│     │        │  │  │  ├─ png.py
│     │        │  │  │  ├─ tls_client_hello.ksy
│     │        │  │  │  ├─ tls_client_hello.py
│     │        │  │  │  └─ vlq_base128_le.py
│     │        │  │  └─ wbxml
│     │        │  │     ├─ ASCommandResponse.py
│     │        │  │     ├─ ASWBXML.py
│     │        │  │     ├─ ASWBXMLByteQueue.py
│     │        │  │     ├─ ASWBXMLCodePage.py
│     │        │  │     ├─ GlobalTokens.py
│     │        │  │     ├─ InvalidDataException.py
│     │        │  │     └─ __init__.py
│     │        │  ├─ coretypes
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ bidi.py
│     │        │  │  ├─ multidict.py
│     │        │  │  └─ serializable.py
│     │        │  ├─ ctx.py
│     │        │  ├─ dns.py
│     │        │  ├─ eventsequence.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ flow.py
│     │        │  ├─ flowfilter.py
│     │        │  ├─ hooks.py
│     │        │  ├─ http.py
│     │        │  ├─ io
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ compat.py
│     │        │  │  ├─ har.py
│     │        │  │  ├─ io.py
│     │        │  │  └─ tnetstring.py
│     │        │  ├─ log.py
│     │        │  ├─ master.py
│     │        │  ├─ net
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ check.py
│     │        │  │  ├─ dns
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ classes.py
│     │        │  │  │  ├─ domain_names.py
│     │        │  │  │  ├─ https_records.py
│     │        │  │  │  ├─ op_codes.py
│     │        │  │  │  ├─ response_codes.py
│     │        │  │  │  └─ types.py
│     │        │  │  ├─ encoding.py
│     │        │  │  ├─ free_port.py
│     │        │  │  ├─ http
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ cookies.py
│     │        │  │  │  ├─ headers.py
│     │        │  │  │  ├─ http1
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ assemble.py
│     │        │  │  │  │  └─ read.py
│     │        │  │  │  ├─ multipart.py
│     │        │  │  │  ├─ status_codes.py
│     │        │  │  │  ├─ url.py
│     │        │  │  │  ├─ user_agents.py
│     │        │  │  │  └─ validate.py
│     │        │  │  ├─ local_ip.py
│     │        │  │  ├─ server_spec.py
│     │        │  │  └─ tls.py
│     │        │  ├─ options.py
│     │        │  ├─ optmanager.py
│     │        │  ├─ platform
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ linux.py
│     │        │  │  ├─ openbsd.py
│     │        │  │  ├─ osx.py
│     │        │  │  ├─ pf.py
│     │        │  │  └─ windows.py
│     │        │  ├─ proxy
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ commands.py
│     │        │  │  ├─ context.py
│     │        │  │  ├─ events.py
│     │        │  │  ├─ layer.py
│     │        │  │  ├─ layers
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ dns.py
│     │        │  │  │  ├─ http
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _base.py
│     │        │  │  │  │  ├─ _events.py
│     │        │  │  │  │  ├─ _hooks.py
│     │        │  │  │  │  ├─ _http1.py
│     │        │  │  │  │  ├─ _http2.py
│     │        │  │  │  │  ├─ _http3.py
│     │        │  │  │  │  ├─ _http_h2.py
│     │        │  │  │  │  ├─ _http_h3.py
│     │        │  │  │  │  └─ _upstream_proxy.py
│     │        │  │  │  ├─ modes.py
│     │        │  │  │  ├─ quic
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _client_hello_parser.py
│     │        │  │  │  │  ├─ _commands.py
│     │        │  │  │  │  ├─ _events.py
│     │        │  │  │  │  ├─ _hooks.py
│     │        │  │  │  │  ├─ _raw_layers.py
│     │        │  │  │  │  └─ _stream_layers.py
│     │        │  │  │  ├─ tcp.py
│     │        │  │  │  ├─ tls.py
│     │        │  │  │  ├─ udp.py
│     │        │  │  │  └─ websocket.py
│     │        │  │  ├─ mode_servers.py
│     │        │  │  ├─ mode_specs.py
│     │        │  │  ├─ server.py
│     │        │  │  ├─ server_hooks.py
│     │        │  │  ├─ tunnel.py
│     │        │  │  └─ utils.py
│     │        │  ├─ py.typed
│     │        │  ├─ script
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ concurrent.py
│     │        │  ├─ tcp.py
│     │        │  ├─ test
│     │        │  │  ├─ taddons.py
│     │        │  │  ├─ tflow.py
│     │        │  │  └─ tutils.py
│     │        │  ├─ tls.py
│     │        │  ├─ tools
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ cmdline.py
│     │        │  │  ├─ console
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ commander
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ commander.py
│     │        │  │  │  ├─ commandexecutor.py
│     │        │  │  │  ├─ commands.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ consoleaddons.py
│     │        │  │  │  ├─ defaultkeys.py
│     │        │  │  │  ├─ eventlog.py
│     │        │  │  │  ├─ flowdetailview.py
│     │        │  │  │  ├─ flowlist.py
│     │        │  │  │  ├─ flowview.py
│     │        │  │  │  ├─ grideditor
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ base.py
│     │        │  │  │  │  ├─ col_bytes.py
│     │        │  │  │  │  ├─ col_subgrid.py
│     │        │  │  │  │  ├─ col_text.py
│     │        │  │  │  │  ├─ col_viewany.py
│     │        │  │  │  │  └─ editors.py
│     │        │  │  │  ├─ help.py
│     │        │  │  │  ├─ keybindings.py
│     │        │  │  │  ├─ keymap.py
│     │        │  │  │  ├─ layoutwidget.py
│     │        │  │  │  ├─ master.py
│     │        │  │  │  ├─ options.py
│     │        │  │  │  ├─ overlay.py
│     │        │  │  │  ├─ palettes.py
│     │        │  │  │  ├─ quickhelp.py
│     │        │  │  │  ├─ searchable.py
│     │        │  │  │  ├─ signals.py
│     │        │  │  │  ├─ statusbar.py
│     │        │  │  │  ├─ tabs.py
│     │        │  │  │  └─ window.py
│     │        │  │  ├─ dump.py
│     │        │  │  ├─ main.py
│     │        │  │  └─ web
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ app.py
│     │        │  │     ├─ master.py
│     │        │  │     ├─ static
│     │        │  │     │  ├─ app.css
│     │        │  │     │  ├─ app.js
│     │        │  │     │  ├─ fonts
│     │        │  │     │  │  ├─ fontawesome-webfont.eot
│     │        │  │     │  │  ├─ fontawesome-webfont.svg
│     │        │  │     │  │  ├─ fontawesome-webfont.ttf
│     │        │  │     │  │  ├─ fontawesome-webfont.woff
│     │        │  │     │  │  └─ fontawesome-webfont.woff2
│     │        │  │     │  ├─ images
│     │        │  │     │  │  ├─ chrome-devtools
│     │        │  │     │  │  │  ├─ LICENSE
│     │        │  │     │  │  │  ├─ resourceCSSIcon.png
│     │        │  │     │  │  │  ├─ resourceDocumentIcon.png
│     │        │  │     │  │  │  ├─ resourceJSIcon.png
│     │        │  │     │  │  │  └─ resourcePlainIcon.png
│     │        │  │     │  │  ├─ favicon.ico
│     │        │  │     │  │  ├─ resourceDnsIcon.png
│     │        │  │     │  │  ├─ resourceExecutableIcon.png
│     │        │  │     │  │  ├─ resourceFlashIcon.png
│     │        │  │     │  │  ├─ resourceImageIcon.png
│     │        │  │     │  │  ├─ resourceJavaIcon.png
│     │        │  │     │  │  ├─ resourceNotModifiedIcon.png
│     │        │  │     │  │  ├─ resourceQuicIcon.png
│     │        │  │     │  │  ├─ resourceRedirectIcon.png
│     │        │  │     │  │  ├─ resourceTcpIcon.png
│     │        │  │     │  │  ├─ resourceUdpIcon.png
│     │        │  │     │  │  └─ resourceWebSocketIcon.png
│     │        │  │     │  ├─ static.js
│     │        │  │     │  ├─ vendor.css
│     │        │  │     │  └─ vendor.js
│     │        │  │     ├─ static_viewer.py
│     │        │  │     ├─ templates
│     │        │  │     │  ├─ index.html
│     │        │  │     │  └─ login.html
│     │        │  │     ├─ web_columns.py
│     │        │  │     └─ webaddons.py
│     │        │  ├─ types.py
│     │        │  ├─ udp.py
│     │        │  ├─ utils
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ arg_check.py
│     │        │  │  ├─ asyncio_utils.py
│     │        │  │  ├─ bits.py
│     │        │  │  ├─ data.py
│     │        │  │  ├─ debug.py
│     │        │  │  ├─ emoji.py
│     │        │  │  ├─ human.py
│     │        │  │  ├─ magisk.py
│     │        │  │  ├─ pyinstaller
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ hook-mitmproxy.addons.onboardingapp.py
│     │        │  │  │  ├─ hook-mitmproxy.py
│     │        │  │  │  └─ hook-mitmproxy.tools.web.py
│     │        │  │  ├─ signals.py
│     │        │  │  ├─ sliding_window.py
│     │        │  │  ├─ spec.py
│     │        │  │  ├─ strutils.py
│     │        │  │  ├─ typecheck.py
│     │        │  │  └─ vt_codes.py
│     │        │  ├─ version.py
│     │        │  └─ websocket.py
│     │        ├─ mitmproxy-12.1.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  └─ top_level.txt
│     │        ├─ mitmproxy_macos
│     │        │  ├─ Mitmproxy Redirector.app.tar
│     │        │  ├─ __init__.py
│     │        │  └─ macos-certificate-truster.app
│     │        │     └─ Contents
│     │        │        ├─ Info.plist
│     │        │        └─ Resources
│     │        │           └─ mitmproxy.icns
│     │        ├─ mitmproxy_macos-0.12.7.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  └─ WHEEL
│     │        ├─ mitmproxy_rs
│     │        │  ├─ __init__.py
│     │        │  ├─ __init__.pyi
│     │        │  ├─ _pyinstaller
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ hook-mitmproxy_linux.py
│     │        │  │  ├─ hook-mitmproxy_macos.py
│     │        │  │  ├─ hook-mitmproxy_rs.py
│     │        │  │  └─ hook-mitmproxy_windows.py
│     │        │  ├─ certs.pyi
│     │        │  ├─ contentviews.pyi
│     │        │  ├─ dns.pyi
│     │        │  ├─ local.pyi
│     │        │  ├─ mitmproxy_rs.abi3.so
│     │        │  ├─ process_info.pyi
│     │        │  ├─ py.typed
│     │        │  ├─ syntax_highlight.pyi
│     │        │  ├─ tun.pyi
│     │        │  ├─ udp.pyi
│     │        │  └─ wireguard.pyi
│     │        ├─ mitmproxy_rs-0.12.7.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ entry_points.txt
│     │        ├─ msgpack
│     │        │  ├─ __init__.py
│     │        │  ├─ _cmsgpack.cpython-312-darwin.so
│     │        │  ├─ exceptions.py
│     │        │  ├─ ext.py
│     │        │  └─ fallback.py
│     │        ├─ msgpack-1.1.0.dist-info
│     │        │  ├─ COPYING
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ multipart
│     │        │  ├─ __init__.py
│     │        │  ├─ decoders.py
│     │        │  ├─ exceptions.py
│     │        │  └─ multipart.py
│     │        ├─ numpy
│     │        │  ├─ __config__.py
│     │        │  ├─ __config__.pyi
│     │        │  ├─ __init__.cython-30.pxd
│     │        │  ├─ __init__.pxd
│     │        │  ├─ __init__.py
│     │        │  ├─ __init__.pyi
│     │        │  ├─ _array_api_info.py
│     │        │  ├─ _array_api_info.pyi
│     │        │  ├─ _configtool.py
│     │        │  ├─ _configtool.pyi
│     │        │  ├─ _core
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _add_newdocs.py
│     │        │  │  ├─ _add_newdocs.pyi
│     │        │  │  ├─ _add_newdocs_scalars.py
│     │        │  │  ├─ _add_newdocs_scalars.pyi
│     │        │  │  ├─ _asarray.py
│     │        │  │  ├─ _asarray.pyi
│     │        │  │  ├─ _dtype.py
│     │        │  │  ├─ _dtype.pyi
│     │        │  │  ├─ _dtype_ctypes.py
│     │        │  │  ├─ _dtype_ctypes.pyi
│     │        │  │  ├─ _exceptions.py
│     │        │  │  ├─ _exceptions.pyi
│     │        │  │  ├─ _internal.py
│     │        │  │  ├─ _internal.pyi
│     │        │  │  ├─ _machar.py
│     │        │  │  ├─ _machar.pyi
│     │        │  │  ├─ _methods.py
│     │        │  │  ├─ _methods.pyi
│     │        │  │  ├─ _multiarray_tests.cpython-312-darwin.so
│     │        │  │  ├─ _multiarray_umath.cpython-312-darwin.so
│     │        │  │  ├─ _operand_flag_tests.cpython-312-darwin.so
│     │        │  │  ├─ _rational_tests.cpython-312-darwin.so
│     │        │  │  ├─ _simd.cpython-312-darwin.so
│     │        │  │  ├─ _simd.pyi
│     │        │  │  ├─ _string_helpers.py
│     │        │  │  ├─ _string_helpers.pyi
│     │        │  │  ├─ _struct_ufunc_tests.cpython-312-darwin.so
│     │        │  │  ├─ _type_aliases.py
│     │        │  │  ├─ _type_aliases.pyi
│     │        │  │  ├─ _ufunc_config.py
│     │        │  │  ├─ _ufunc_config.pyi
│     │        │  │  ├─ _umath_tests.cpython-312-darwin.so
│     │        │  │  ├─ arrayprint.py
│     │        │  │  ├─ arrayprint.pyi
│     │        │  │  ├─ cversions.py
│     │        │  │  ├─ defchararray.py
│     │        │  │  ├─ defchararray.pyi
│     │        │  │  ├─ einsumfunc.py
│     │        │  │  ├─ einsumfunc.pyi
│     │        │  │  ├─ fromnumeric.py
│     │        │  │  ├─ fromnumeric.pyi
│     │        │  │  ├─ function_base.py
│     │        │  │  ├─ function_base.pyi
│     │        │  │  ├─ getlimits.py
│     │        │  │  ├─ getlimits.pyi
│     │        │  │  ├─ include
│     │        │  │  │  └─ numpy
│     │        │  │  │     ├─ __multiarray_api.c
│     │        │  │  │     ├─ __multiarray_api.h
│     │        │  │  │     ├─ __ufunc_api.c
│     │        │  │  │     ├─ __ufunc_api.h
│     │        │  │  │     ├─ _neighborhood_iterator_imp.h
│     │        │  │  │     ├─ _numpyconfig.h
│     │        │  │  │     ├─ _public_dtype_api_table.h
│     │        │  │  │     ├─ arrayobject.h
│     │        │  │  │     ├─ arrayscalars.h
│     │        │  │  │     ├─ dtype_api.h
│     │        │  │  │     ├─ halffloat.h
│     │        │  │  │     ├─ ndarrayobject.h
│     │        │  │  │     ├─ ndarraytypes.h
│     │        │  │  │     ├─ npy_2_compat.h
│     │        │  │  │     ├─ npy_2_complexcompat.h
│     │        │  │  │     ├─ npy_3kcompat.h
│     │        │  │  │     ├─ npy_common.h
│     │        │  │  │     ├─ npy_cpu.h
│     │        │  │  │     ├─ npy_endian.h
│     │        │  │  │     ├─ npy_math.h
│     │        │  │  │     ├─ npy_no_deprecated_api.h
│     │        │  │  │     ├─ npy_os.h
│     │        │  │  │     ├─ numpyconfig.h
│     │        │  │  │     ├─ random
│     │        │  │  │     │  ├─ LICENSE.txt
│     │        │  │  │     │  ├─ bitgen.h
│     │        │  │  │     │  ├─ distributions.h
│     │        │  │  │     │  └─ libdivide.h
│     │        │  │  │     ├─ ufuncobject.h
│     │        │  │  │     └─ utils.h
│     │        │  │  ├─ lib
│     │        │  │  │  ├─ libnpymath.a
│     │        │  │  │  ├─ npy-pkg-config
│     │        │  │  │  │  ├─ mlib.ini
│     │        │  │  │  │  └─ npymath.ini
│     │        │  │  │  └─ pkgconfig
│     │        │  │  │     └─ numpy.pc
│     │        │  │  ├─ memmap.py
│     │        │  │  ├─ memmap.pyi
│     │        │  │  ├─ multiarray.py
│     │        │  │  ├─ multiarray.pyi
│     │        │  │  ├─ numeric.py
│     │        │  │  ├─ numeric.pyi
│     │        │  │  ├─ numerictypes.py
│     │        │  │  ├─ numerictypes.pyi
│     │        │  │  ├─ overrides.py
│     │        │  │  ├─ overrides.pyi
│     │        │  │  ├─ printoptions.py
│     │        │  │  ├─ printoptions.pyi
│     │        │  │  ├─ records.py
│     │        │  │  ├─ records.pyi
│     │        │  │  ├─ shape_base.py
│     │        │  │  ├─ shape_base.pyi
│     │        │  │  ├─ strings.py
│     │        │  │  ├─ strings.pyi
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ _locales.py
│     │        │  │  │  ├─ _natype.py
│     │        │  │  │  ├─ examples
│     │        │  │  │  │  ├─ cython
│     │        │  │  │  │  │  ├─ checks.pyx
│     │        │  │  │  │  │  ├─ meson.build
│     │        │  │  │  │  │  └─ setup.py
│     │        │  │  │  │  └─ limited_api
│     │        │  │  │  │     ├─ limited_api1.c
│     │        │  │  │  │     ├─ limited_api2.pyx
│     │        │  │  │  │     ├─ limited_api_latest.c
│     │        │  │  │  │     ├─ meson.build
│     │        │  │  │  │     └─ setup.py
│     │        │  │  │  ├─ test__exceptions.py
│     │        │  │  │  ├─ test_abc.py
│     │        │  │  │  ├─ test_api.py
│     │        │  │  │  ├─ test_argparse.py
│     │        │  │  │  ├─ test_array_api_info.py
│     │        │  │  │  ├─ test_array_coercion.py
│     │        │  │  │  ├─ test_array_interface.py
│     │        │  │  │  ├─ test_arraymethod.py
│     │        │  │  │  ├─ test_arrayobject.py
│     │        │  │  │  ├─ test_arrayprint.py
│     │        │  │  │  ├─ test_casting_floatingpoint_errors.py
│     │        │  │  │  ├─ test_casting_unittests.py
│     │        │  │  │  ├─ test_conversion_utils.py
│     │        │  │  │  ├─ test_cpu_dispatcher.py
│     │        │  │  │  ├─ test_cpu_features.py
│     │        │  │  │  ├─ test_custom_dtypes.py
│     │        │  │  │  ├─ test_cython.py
│     │        │  │  │  ├─ test_datetime.py
│     │        │  │  │  ├─ test_defchararray.py
│     │        │  │  │  ├─ test_deprecations.py
│     │        │  │  │  ├─ test_dlpack.py
│     │        │  │  │  ├─ test_dtype.py
│     │        │  │  │  ├─ test_einsum.py
│     │        │  │  │  ├─ test_errstate.py
│     │        │  │  │  ├─ test_extint128.py
│     │        │  │  │  ├─ test_function_base.py
│     │        │  │  │  ├─ test_getlimits.py
│     │        │  │  │  ├─ test_half.py
│     │        │  │  │  ├─ test_hashtable.py
│     │        │  │  │  ├─ test_indexerrors.py
│     │        │  │  │  ├─ test_indexing.py
│     │        │  │  │  ├─ test_item_selection.py
│     │        │  │  │  ├─ test_limited_api.py
│     │        │  │  │  ├─ test_longdouble.py
│     │        │  │  │  ├─ test_machar.py
│     │        │  │  │  ├─ test_mem_overlap.py
│     │        │  │  │  ├─ test_mem_policy.py
│     │        │  │  │  ├─ test_memmap.py
│     │        │  │  │  ├─ test_multiarray.py
│     │        │  │  │  ├─ test_multithreading.py
│     │        │  │  │  ├─ test_nditer.py
│     │        │  │  │  ├─ test_nep50_promotions.py
│     │        │  │  │  ├─ test_numeric.py
│     │        │  │  │  ├─ test_numerictypes.py
│     │        │  │  │  ├─ test_overrides.py
│     │        │  │  │  ├─ test_print.py
│     │        │  │  │  ├─ test_protocols.py
│     │        │  │  │  ├─ test_records.py
│     │        │  │  │  ├─ test_regression.py
│     │        │  │  │  ├─ test_scalar_ctors.py
│     │        │  │  │  ├─ test_scalar_methods.py
│     │        │  │  │  ├─ test_scalarbuffer.py
│     │        │  │  │  ├─ test_scalarinherit.py
│     │        │  │  │  ├─ test_scalarmath.py
│     │        │  │  │  ├─ test_scalarprint.py
│     │        │  │  │  ├─ test_shape_base.py
│     │        │  │  │  ├─ test_simd.py
│     │        │  │  │  ├─ test_simd_module.py
│     │        │  │  │  ├─ test_stringdtype.py
│     │        │  │  │  ├─ test_strings.py
│     │        │  │  │  ├─ test_ufunc.py
│     │        │  │  │  ├─ test_umath.py
│     │        │  │  │  ├─ test_umath_accuracy.py
│     │        │  │  │  ├─ test_umath_complex.py
│     │        │  │  │  └─ test_unicode.py
│     │        │  │  ├─ umath.py
│     │        │  │  └─ umath.pyi
│     │        │  ├─ _distributor_init.py
│     │        │  ├─ _distributor_init.pyi
│     │        │  ├─ _expired_attrs_2_0.py
│     │        │  ├─ _expired_attrs_2_0.pyi
│     │        │  ├─ _globals.py
│     │        │  ├─ _globals.pyi
│     │        │  ├─ _pyinstaller
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ hook-numpy.py
│     │        │  │  ├─ hook-numpy.pyi
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ pyinstaller-smoke.py
│     │        │  │     └─ test_pyinstaller.py
│     │        │  ├─ _pytesttester.py
│     │        │  ├─ _pytesttester.pyi
│     │        │  ├─ _typing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _add_docstring.py
│     │        │  │  ├─ _array_like.py
│     │        │  │  ├─ _callable.pyi
│     │        │  │  ├─ _char_codes.py
│     │        │  │  ├─ _dtype_like.py
│     │        │  │  ├─ _extended_precision.py
│     │        │  │  ├─ _nbit.py
│     │        │  │  ├─ _nbit_base.py
│     │        │  │  ├─ _nbit_base.pyi
│     │        │  │  ├─ _nested_sequence.py
│     │        │  │  ├─ _scalars.py
│     │        │  │  ├─ _shape.py
│     │        │  │  ├─ _ufunc.py
│     │        │  │  └─ _ufunc.pyi
│     │        │  ├─ _utils
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _convertions.py
│     │        │  │  ├─ _convertions.pyi
│     │        │  │  ├─ _inspect.py
│     │        │  │  ├─ _inspect.pyi
│     │        │  │  ├─ _pep440.py
│     │        │  │  └─ _pep440.pyi
│     │        │  ├─ char
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ __init__.pyi
│     │        │  ├─ conftest.py
│     │        │  ├─ core
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _dtype.py
│     │        │  │  ├─ _dtype.pyi
│     │        │  │  ├─ _dtype_ctypes.py
│     │        │  │  ├─ _dtype_ctypes.pyi
│     │        │  │  ├─ _internal.py
│     │        │  │  ├─ _multiarray_umath.py
│     │        │  │  ├─ _utils.py
│     │        │  │  ├─ arrayprint.py
│     │        │  │  ├─ defchararray.py
│     │        │  │  ├─ einsumfunc.py
│     │        │  │  ├─ fromnumeric.py
│     │        │  │  ├─ function_base.py
│     │        │  │  ├─ getlimits.py
│     │        │  │  ├─ multiarray.py
│     │        │  │  ├─ numeric.py
│     │        │  │  ├─ numerictypes.py
│     │        │  │  ├─ overrides.py
│     │        │  │  ├─ overrides.pyi
│     │        │  │  ├─ records.py
│     │        │  │  ├─ shape_base.py
│     │        │  │  └─ umath.py
│     │        │  ├─ ctypeslib
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _ctypeslib.py
│     │        │  │  └─ _ctypeslib.pyi
│     │        │  ├─ doc
│     │        │  │  └─ ufuncs.py
│     │        │  ├─ dtypes.py
│     │        │  ├─ dtypes.pyi
│     │        │  ├─ exceptions.py
│     │        │  ├─ exceptions.pyi
│     │        │  ├─ f2py
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ __main__.py
│     │        │  │  ├─ __version__.py
│     │        │  │  ├─ __version__.pyi
│     │        │  │  ├─ _backends
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __init__.pyi
│     │        │  │  │  ├─ _backend.py
│     │        │  │  │  ├─ _backend.pyi
│     │        │  │  │  ├─ _distutils.py
│     │        │  │  │  ├─ _distutils.pyi
│     │        │  │  │  ├─ _meson.py
│     │        │  │  │  ├─ _meson.pyi
│     │        │  │  │  └─ meson.build.template
│     │        │  │  ├─ _isocbind.py
│     │        │  │  ├─ _isocbind.pyi
│     │        │  │  ├─ _src_pyf.py
│     │        │  │  ├─ _src_pyf.pyi
│     │        │  │  ├─ auxfuncs.py
│     │        │  │  ├─ auxfuncs.pyi
│     │        │  │  ├─ capi_maps.py
│     │        │  │  ├─ capi_maps.pyi
│     │        │  │  ├─ cb_rules.py
│     │        │  │  ├─ cb_rules.pyi
│     │        │  │  ├─ cfuncs.py
│     │        │  │  ├─ cfuncs.pyi
│     │        │  │  ├─ common_rules.py
│     │        │  │  ├─ common_rules.pyi
│     │        │  │  ├─ crackfortran.py
│     │        │  │  ├─ crackfortran.pyi
│     │        │  │  ├─ diagnose.py
│     │        │  │  ├─ diagnose.pyi
│     │        │  │  ├─ f2py2e.py
│     │        │  │  ├─ f2py2e.pyi
│     │        │  │  ├─ f90mod_rules.py
│     │        │  │  ├─ f90mod_rules.pyi
│     │        │  │  ├─ func2subr.py
│     │        │  │  ├─ func2subr.pyi
│     │        │  │  ├─ rules.py
│     │        │  │  ├─ rules.pyi
│     │        │  │  ├─ setup.cfg
│     │        │  │  ├─ src
│     │        │  │  │  ├─ fortranobject.c
│     │        │  │  │  └─ fortranobject.h
│     │        │  │  ├─ symbolic.py
│     │        │  │  ├─ symbolic.pyi
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ src
│     │        │  │  │  │  ├─ abstract_interface
│     │        │  │  │  │  │  ├─ foo.f90
│     │        │  │  │  │  │  └─ gh18403_mod.f90
│     │        │  │  │  │  ├─ array_from_pyobj
│     │        │  │  │  │  │  └─ wrapmodule.c
│     │        │  │  │  │  ├─ assumed_shape
│     │        │  │  │  │  │  ├─ .f2py_f2cmap
│     │        │  │  │  │  │  ├─ foo_free.f90
│     │        │  │  │  │  │  ├─ foo_mod.f90
│     │        │  │  │  │  │  ├─ foo_use.f90
│     │        │  │  │  │  │  └─ precision.f90
│     │        │  │  │  │  ├─ block_docstring
│     │        │  │  │  │  │  └─ foo.f
│     │        │  │  │  │  ├─ callback
│     │        │  │  │  │  │  ├─ foo.f
│     │        │  │  │  │  │  ├─ gh17797.f90
│     │        │  │  │  │  │  ├─ gh18335.f90
│     │        │  │  │  │  │  ├─ gh25211.f
│     │        │  │  │  │  │  ├─ gh25211.pyf
│     │        │  │  │  │  │  └─ gh26681.f90
│     │        │  │  │  │  ├─ cli
│     │        │  │  │  │  │  ├─ gh_22819.pyf
│     │        │  │  │  │  │  ├─ hi77.f
│     │        │  │  │  │  │  └─ hiworld.f90
│     │        │  │  │  │  ├─ common
│     │        │  │  │  │  │  ├─ block.f
│     │        │  │  │  │  │  └─ gh19161.f90
│     │        │  │  │  │  ├─ crackfortran
│     │        │  │  │  │  │  ├─ accesstype.f90
│     │        │  │  │  │  │  ├─ common_with_division.f
│     │        │  │  │  │  │  ├─ data_common.f
│     │        │  │  │  │  │  ├─ data_multiplier.f
│     │        │  │  │  │  │  ├─ data_stmts.f90
│     │        │  │  │  │  │  ├─ data_with_comments.f
│     │        │  │  │  │  │  ├─ foo_deps.f90
│     │        │  │  │  │  │  ├─ gh15035.f
│     │        │  │  │  │  │  ├─ gh17859.f
│     │        │  │  │  │  │  ├─ gh22648.pyf
│     │        │  │  │  │  │  ├─ gh23533.f
│     │        │  │  │  │  │  ├─ gh23598.f90
│     │        │  │  │  │  │  ├─ gh23598Warn.f90
│     │        │  │  │  │  │  ├─ gh23879.f90
│     │        │  │  │  │  │  ├─ gh27697.f90
│     │        │  │  │  │  │  ├─ gh2848.f90
│     │        │  │  │  │  │  ├─ operators.f90
│     │        │  │  │  │  │  ├─ privatemod.f90
│     │        │  │  │  │  │  ├─ publicmod.f90
│     │        │  │  │  │  │  ├─ pubprivmod.f90
│     │        │  │  │  │  │  └─ unicode_comment.f90
│     │        │  │  │  │  ├─ f2cmap
│     │        │  │  │  │  │  ├─ .f2py_f2cmap
│     │        │  │  │  │  │  └─ isoFortranEnvMap.f90
│     │        │  │  │  │  ├─ isocintrin
│     │        │  │  │  │  │  └─ isoCtests.f90
│     │        │  │  │  │  ├─ kind
│     │        │  │  │  │  │  └─ foo.f90
│     │        │  │  │  │  ├─ mixed
│     │        │  │  │  │  │  ├─ foo.f
│     │        │  │  │  │  │  ├─ foo_fixed.f90
│     │        │  │  │  │  │  └─ foo_free.f90
│     │        │  │  │  │  ├─ modules
│     │        │  │  │  │  │  ├─ gh25337
│     │        │  │  │  │  │  │  ├─ data.f90
│     │        │  │  │  │  │  │  └─ use_data.f90
│     │        │  │  │  │  │  ├─ gh26920
│     │        │  │  │  │  │  │  ├─ two_mods_with_no_public_entities.f90
│     │        │  │  │  │  │  │  └─ two_mods_with_one_public_routine.f90
│     │        │  │  │  │  │  ├─ module_data_docstring.f90
│     │        │  │  │  │  │  └─ use_modules.f90
│     │        │  │  │  │  ├─ negative_bounds
│     │        │  │  │  │  │  └─ issue_20853.f90
│     │        │  │  │  │  ├─ parameter
│     │        │  │  │  │  │  ├─ constant_array.f90
│     │        │  │  │  │  │  ├─ constant_both.f90
│     │        │  │  │  │  │  ├─ constant_compound.f90
│     │        │  │  │  │  │  ├─ constant_integer.f90
│     │        │  │  │  │  │  ├─ constant_non_compound.f90
│     │        │  │  │  │  │  └─ constant_real.f90
│     │        │  │  │  │  ├─ quoted_character
│     │        │  │  │  │  │  └─ foo.f
│     │        │  │  │  │  ├─ regression
│     │        │  │  │  │  │  ├─ AB.inc
│     │        │  │  │  │  │  ├─ assignOnlyModule.f90
│     │        │  │  │  │  │  ├─ datonly.f90
│     │        │  │  │  │  │  ├─ f77comments.f
│     │        │  │  │  │  │  ├─ f77fixedform.f95
│     │        │  │  │  │  │  ├─ f90continuation.f90
│     │        │  │  │  │  │  ├─ incfile.f90
│     │        │  │  │  │  │  ├─ inout.f90
│     │        │  │  │  │  │  ├─ lower_f2py_fortran.f90
│     │        │  │  │  │  │  └─ mod_derived_types.f90
│     │        │  │  │  │  ├─ return_character
│     │        │  │  │  │  │  ├─ foo77.f
│     │        │  │  │  │  │  └─ foo90.f90
│     │        │  │  │  │  ├─ return_complex
│     │        │  │  │  │  │  ├─ foo77.f
│     │        │  │  │  │  │  └─ foo90.f90
│     │        │  │  │  │  ├─ return_integer
│     │        │  │  │  │  │  ├─ foo77.f
│     │        │  │  │  │  │  └─ foo90.f90
│     │        │  │  │  │  ├─ return_logical
│     │        │  │  │  │  │  ├─ foo77.f
│     │        │  │  │  │  │  └─ foo90.f90
│     │        │  │  │  │  ├─ return_real
│     │        │  │  │  │  │  ├─ foo77.f
│     │        │  │  │  │  │  └─ foo90.f90
│     │        │  │  │  │  ├─ routines
│     │        │  │  │  │  │  ├─ funcfortranname.f
│     │        │  │  │  │  │  ├─ funcfortranname.pyf
│     │        │  │  │  │  │  ├─ subrout.f
│     │        │  │  │  │  │  └─ subrout.pyf
│     │        │  │  │  │  ├─ size
│     │        │  │  │  │  │  └─ foo.f90
│     │        │  │  │  │  ├─ string
│     │        │  │  │  │  │  ├─ char.f90
│     │        │  │  │  │  │  ├─ fixed_string.f90
│     │        │  │  │  │  │  ├─ gh24008.f
│     │        │  │  │  │  │  ├─ gh24662.f90
│     │        │  │  │  │  │  ├─ gh25286.f90
│     │        │  │  │  │  │  ├─ gh25286.pyf
│     │        │  │  │  │  │  ├─ gh25286_bc.pyf
│     │        │  │  │  │  │  ├─ scalar_string.f90
│     │        │  │  │  │  │  └─ string.f
│     │        │  │  │  │  └─ value_attrspec
│     │        │  │  │  │     └─ gh21665.f90
│     │        │  │  │  ├─ test_abstract_interface.py
│     │        │  │  │  ├─ test_array_from_pyobj.py
│     │        │  │  │  ├─ test_assumed_shape.py
│     │        │  │  │  ├─ test_block_docstring.py
│     │        │  │  │  ├─ test_callback.py
│     │        │  │  │  ├─ test_character.py
│     │        │  │  │  ├─ test_common.py
│     │        │  │  │  ├─ test_crackfortran.py
│     │        │  │  │  ├─ test_data.py
│     │        │  │  │  ├─ test_docs.py
│     │        │  │  │  ├─ test_f2cmap.py
│     │        │  │  │  ├─ test_f2py2e.py
│     │        │  │  │  ├─ test_isoc.py
│     │        │  │  │  ├─ test_kind.py
│     │        │  │  │  ├─ test_mixed.py
│     │        │  │  │  ├─ test_modules.py
│     │        │  │  │  ├─ test_parameter.py
│     │        │  │  │  ├─ test_pyf_src.py
│     │        │  │  │  ├─ test_quoted_character.py
│     │        │  │  │  ├─ test_regression.py
│     │        │  │  │  ├─ test_return_character.py
│     │        │  │  │  ├─ test_return_complex.py
│     │        │  │  │  ├─ test_return_integer.py
│     │        │  │  │  ├─ test_return_logical.py
│     │        │  │  │  ├─ test_return_real.py
│     │        │  │  │  ├─ test_routines.py
│     │        │  │  │  ├─ test_semicolon_split.py
│     │        │  │  │  ├─ test_size.py
│     │        │  │  │  ├─ test_string.py
│     │        │  │  │  ├─ test_symbolic.py
│     │        │  │  │  ├─ test_value_attrspec.py
│     │        │  │  │  └─ util.py
│     │        │  │  ├─ use_rules.py
│     │        │  │  └─ use_rules.pyi
│     │        │  ├─ fft
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _helper.py
│     │        │  │  ├─ _helper.pyi
│     │        │  │  ├─ _pocketfft.py
│     │        │  │  ├─ _pocketfft.pyi
│     │        │  │  ├─ _pocketfft_umath.cpython-312-darwin.so
│     │        │  │  ├─ helper.py
│     │        │  │  ├─ helper.pyi
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_helper.py
│     │        │  │     └─ test_pocketfft.py
│     │        │  ├─ lib
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _array_utils_impl.py
│     │        │  │  ├─ _array_utils_impl.pyi
│     │        │  │  ├─ _arraypad_impl.py
│     │        │  │  ├─ _arraypad_impl.pyi
│     │        │  │  ├─ _arraysetops_impl.py
│     │        │  │  ├─ _arraysetops_impl.pyi
│     │        │  │  ├─ _arrayterator_impl.py
│     │        │  │  ├─ _arrayterator_impl.pyi
│     │        │  │  ├─ _datasource.py
│     │        │  │  ├─ _datasource.pyi
│     │        │  │  ├─ _format_impl.py
│     │        │  │  ├─ _format_impl.pyi
│     │        │  │  ├─ _function_base_impl.py
│     │        │  │  ├─ _function_base_impl.pyi
│     │        │  │  ├─ _histograms_impl.py
│     │        │  │  ├─ _histograms_impl.pyi
│     │        │  │  ├─ _index_tricks_impl.py
│     │        │  │  ├─ _index_tricks_impl.pyi
│     │        │  │  ├─ _iotools.py
│     │        │  │  ├─ _iotools.pyi
│     │        │  │  ├─ _nanfunctions_impl.py
│     │        │  │  ├─ _nanfunctions_impl.pyi
│     │        │  │  ├─ _npyio_impl.py
│     │        │  │  ├─ _npyio_impl.pyi
│     │        │  │  ├─ _polynomial_impl.py
│     │        │  │  ├─ _polynomial_impl.pyi
│     │        │  │  ├─ _scimath_impl.py
│     │        │  │  ├─ _scimath_impl.pyi
│     │        │  │  ├─ _shape_base_impl.py
│     │        │  │  ├─ _shape_base_impl.pyi
│     │        │  │  ├─ _stride_tricks_impl.py
│     │        │  │  ├─ _stride_tricks_impl.pyi
│     │        │  │  ├─ _twodim_base_impl.py
│     │        │  │  ├─ _twodim_base_impl.pyi
│     │        │  │  ├─ _type_check_impl.py
│     │        │  │  ├─ _type_check_impl.pyi
│     │        │  │  ├─ _ufunclike_impl.py
│     │        │  │  ├─ _ufunclike_impl.pyi
│     │        │  │  ├─ _user_array_impl.py
│     │        │  │  ├─ _user_array_impl.pyi
│     │        │  │  ├─ _utils_impl.py
│     │        │  │  ├─ _utils_impl.pyi
│     │        │  │  ├─ _version.py
│     │        │  │  ├─ _version.pyi
│     │        │  │  ├─ array_utils.py
│     │        │  │  ├─ array_utils.pyi
│     │        │  │  ├─ format.py
│     │        │  │  ├─ format.pyi
│     │        │  │  ├─ introspect.py
│     │        │  │  ├─ introspect.pyi
│     │        │  │  ├─ mixins.py
│     │        │  │  ├─ mixins.pyi
│     │        │  │  ├─ npyio.py
│     │        │  │  ├─ npyio.pyi
│     │        │  │  ├─ recfunctions.py
│     │        │  │  ├─ recfunctions.pyi
│     │        │  │  ├─ scimath.py
│     │        │  │  ├─ scimath.pyi
│     │        │  │  ├─ stride_tricks.py
│     │        │  │  ├─ stride_tricks.pyi
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test__datasource.py
│     │        │  │  │  ├─ test__iotools.py
│     │        │  │  │  ├─ test__version.py
│     │        │  │  │  ├─ test_array_utils.py
│     │        │  │  │  ├─ test_arraypad.py
│     │        │  │  │  ├─ test_arraysetops.py
│     │        │  │  │  ├─ test_arrayterator.py
│     │        │  │  │  ├─ test_format.py
│     │        │  │  │  ├─ test_function_base.py
│     │        │  │  │  ├─ test_histograms.py
│     │        │  │  │  ├─ test_index_tricks.py
│     │        │  │  │  ├─ test_io.py
│     │        │  │  │  ├─ test_loadtxt.py
│     │        │  │  │  ├─ test_mixins.py
│     │        │  │  │  ├─ test_nanfunctions.py
│     │        │  │  │  ├─ test_packbits.py
│     │        │  │  │  ├─ test_polynomial.py
│     │        │  │  │  ├─ test_recfunctions.py
│     │        │  │  │  ├─ test_regression.py
│     │        │  │  │  ├─ test_shape_base.py
│     │        │  │  │  ├─ test_stride_tricks.py
│     │        │  │  │  ├─ test_twodim_base.py
│     │        │  │  │  ├─ test_type_check.py
│     │        │  │  │  ├─ test_ufunclike.py
│     │        │  │  │  └─ test_utils.py
│     │        │  │  ├─ user_array.py
│     │        │  │  └─ user_array.pyi
│     │        │  ├─ linalg
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _linalg.py
│     │        │  │  ├─ _linalg.pyi
│     │        │  │  ├─ _umath_linalg.cpython-312-darwin.so
│     │        │  │  ├─ _umath_linalg.pyi
│     │        │  │  ├─ lapack_lite.cpython-312-darwin.so
│     │        │  │  ├─ lapack_lite.pyi
│     │        │  │  ├─ linalg.py
│     │        │  │  ├─ linalg.pyi
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_deprecations.py
│     │        │  │     ├─ test_linalg.py
│     │        │  │     └─ test_regression.py
│     │        │  ├─ ma
│     │        │  │  ├─ API_CHANGES.txt
│     │        │  │  ├─ LICENSE
│     │        │  │  ├─ README.rst
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ core.py
│     │        │  │  ├─ core.pyi
│     │        │  │  ├─ extras.py
│     │        │  │  ├─ extras.pyi
│     │        │  │  ├─ mrecords.py
│     │        │  │  ├─ mrecords.pyi
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_arrayobject.py
│     │        │  │  │  ├─ test_core.py
│     │        │  │  │  ├─ test_deprecations.py
│     │        │  │  │  ├─ test_extras.py
│     │        │  │  │  ├─ test_mrecords.py
│     │        │  │  │  ├─ test_old_ma.py
│     │        │  │  │  ├─ test_regression.py
│     │        │  │  │  └─ test_subclassing.py
│     │        │  │  └─ testutils.py
│     │        │  ├─ matlib.py
│     │        │  ├─ matlib.pyi
│     │        │  ├─ matrixlib
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ defmatrix.py
│     │        │  │  ├─ defmatrix.pyi
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_defmatrix.py
│     │        │  │     ├─ test_interaction.py
│     │        │  │     ├─ test_masked_matrix.py
│     │        │  │     ├─ test_matrix_linalg.py
│     │        │  │     ├─ test_multiarray.py
│     │        │  │     ├─ test_numeric.py
│     │        │  │     └─ test_regression.py
│     │        │  ├─ polynomial
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _polybase.py
│     │        │  │  ├─ _polybase.pyi
│     │        │  │  ├─ _polytypes.pyi
│     │        │  │  ├─ chebyshev.py
│     │        │  │  ├─ chebyshev.pyi
│     │        │  │  ├─ hermite.py
│     │        │  │  ├─ hermite.pyi
│     │        │  │  ├─ hermite_e.py
│     │        │  │  ├─ hermite_e.pyi
│     │        │  │  ├─ laguerre.py
│     │        │  │  ├─ laguerre.pyi
│     │        │  │  ├─ legendre.py
│     │        │  │  ├─ legendre.pyi
│     │        │  │  ├─ polynomial.py
│     │        │  │  ├─ polynomial.pyi
│     │        │  │  ├─ polyutils.py
│     │        │  │  ├─ polyutils.pyi
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_chebyshev.py
│     │        │  │     ├─ test_classes.py
│     │        │  │     ├─ test_hermite.py
│     │        │  │     ├─ test_hermite_e.py
│     │        │  │     ├─ test_laguerre.py
│     │        │  │     ├─ test_legendre.py
│     │        │  │     ├─ test_polynomial.py
│     │        │  │     ├─ test_polyutils.py
│     │        │  │     ├─ test_printing.py
│     │        │  │     └─ test_symbol.py
│     │        │  ├─ py.typed
│     │        │  ├─ random
│     │        │  │  ├─ LICENSE.md
│     │        │  │  ├─ __init__.pxd
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _bounded_integers.cpython-312-darwin.so
│     │        │  │  ├─ _bounded_integers.pxd
│     │        │  │  ├─ _bounded_integers.pyi
│     │        │  │  ├─ _common.cpython-312-darwin.so
│     │        │  │  ├─ _common.pxd
│     │        │  │  ├─ _common.pyi
│     │        │  │  ├─ _examples
│     │        │  │  │  ├─ cffi
│     │        │  │  │  │  ├─ extending.py
│     │        │  │  │  │  └─ parse.py
│     │        │  │  │  ├─ cython
│     │        │  │  │  │  ├─ extending.pyx
│     │        │  │  │  │  ├─ extending_distributions.pyx
│     │        │  │  │  │  └─ meson.build
│     │        │  │  │  └─ numba
│     │        │  │  │     ├─ extending.py
│     │        │  │  │     └─ extending_distributions.py
│     │        │  │  ├─ _generator.cpython-312-darwin.so
│     │        │  │  ├─ _generator.pyi
│     │        │  │  ├─ _mt19937.cpython-312-darwin.so
│     │        │  │  ├─ _mt19937.pyi
│     │        │  │  ├─ _pcg64.cpython-312-darwin.so
│     │        │  │  ├─ _pcg64.pyi
│     │        │  │  ├─ _philox.cpython-312-darwin.so
│     │        │  │  ├─ _philox.pyi
│     │        │  │  ├─ _pickle.py
│     │        │  │  ├─ _pickle.pyi
│     │        │  │  ├─ _sfc64.cpython-312-darwin.so
│     │        │  │  ├─ _sfc64.pyi
│     │        │  │  ├─ bit_generator.cpython-312-darwin.so
│     │        │  │  ├─ bit_generator.pxd
│     │        │  │  ├─ bit_generator.pyi
│     │        │  │  ├─ c_distributions.pxd
│     │        │  │  ├─ lib
│     │        │  │  │  └─ libnpyrandom.a
│     │        │  │  ├─ mtrand.cpython-312-darwin.so
│     │        │  │  ├─ mtrand.pyi
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_direct.py
│     │        │  │     ├─ test_extending.py
│     │        │  │     ├─ test_generator_mt19937.py
│     │        │  │     ├─ test_generator_mt19937_regressions.py
│     │        │  │     ├─ test_random.py
│     │        │  │     ├─ test_randomstate.py
│     │        │  │     ├─ test_randomstate_regression.py
│     │        │  │     ├─ test_regression.py
│     │        │  │     ├─ test_seed_sequence.py
│     │        │  │     └─ test_smoke.py
│     │        │  ├─ rec
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ __init__.pyi
│     │        │  ├─ strings
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ __init__.pyi
│     │        │  ├─ testing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __init__.pyi
│     │        │  │  ├─ _private
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __init__.pyi
│     │        │  │  │  ├─ extbuild.py
│     │        │  │  │  ├─ extbuild.pyi
│     │        │  │  │  ├─ utils.py
│     │        │  │  │  └─ utils.pyi
│     │        │  │  ├─ overrides.py
│     │        │  │  ├─ overrides.pyi
│     │        │  │  ├─ print_coercion_tables.py
│     │        │  │  ├─ print_coercion_tables.pyi
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     └─ test_utils.py
│     │        │  ├─ tests
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ test__all__.py
│     │        │  │  ├─ test_configtool.py
│     │        │  │  ├─ test_ctypeslib.py
│     │        │  │  ├─ test_lazyloading.py
│     │        │  │  ├─ test_matlib.py
│     │        │  │  ├─ test_numpy_config.py
│     │        │  │  ├─ test_numpy_version.py
│     │        │  │  ├─ test_public_api.py
│     │        │  │  ├─ test_reloading.py
│     │        │  │  ├─ test_scripts.py
│     │        │  │  └─ test_warnings.py
│     │        │  ├─ typing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ mypy_plugin.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_isfile.py
│     │        │  │     ├─ test_runtime.py
│     │        │  │     └─ test_typing.py
│     │        │  ├─ version.py
│     │        │  └─ version.pyi
│     │        ├─ numpy-2.3.2.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  └─ entry_points.txt
│     │        ├─ pandas
│     │        │  ├─ __init__.py
│     │        │  ├─ _config
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ config.py
│     │        │  │  ├─ dates.py
│     │        │  │  ├─ display.py
│     │        │  │  └─ localization.py
│     │        │  ├─ _libs
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ algos.cpython-312-darwin.so
│     │        │  │  ├─ algos.pyi
│     │        │  │  ├─ arrays.cpython-312-darwin.so
│     │        │  │  ├─ arrays.pyi
│     │        │  │  ├─ byteswap.cpython-312-darwin.so
│     │        │  │  ├─ byteswap.pyi
│     │        │  │  ├─ groupby.cpython-312-darwin.so
│     │        │  │  ├─ groupby.pyi
│     │        │  │  ├─ hashing.cpython-312-darwin.so
│     │        │  │  ├─ hashing.pyi
│     │        │  │  ├─ hashtable.cpython-312-darwin.so
│     │        │  │  ├─ hashtable.pyi
│     │        │  │  ├─ index.cpython-312-darwin.so
│     │        │  │  ├─ index.pyi
│     │        │  │  ├─ indexing.cpython-312-darwin.so
│     │        │  │  ├─ indexing.pyi
│     │        │  │  ├─ internals.cpython-312-darwin.so
│     │        │  │  ├─ internals.pyi
│     │        │  │  ├─ interval.cpython-312-darwin.so
│     │        │  │  ├─ interval.pyi
│     │        │  │  ├─ join.cpython-312-darwin.so
│     │        │  │  ├─ join.pyi
│     │        │  │  ├─ json.cpython-312-darwin.so
│     │        │  │  ├─ json.pyi
│     │        │  │  ├─ lib.cpython-312-darwin.so
│     │        │  │  ├─ lib.pyi
│     │        │  │  ├─ missing.cpython-312-darwin.so
│     │        │  │  ├─ missing.pyi
│     │        │  │  ├─ ops.cpython-312-darwin.so
│     │        │  │  ├─ ops.pyi
│     │        │  │  ├─ ops_dispatch.cpython-312-darwin.so
│     │        │  │  ├─ ops_dispatch.pyi
│     │        │  │  ├─ pandas_datetime.cpython-312-darwin.so
│     │        │  │  ├─ pandas_parser.cpython-312-darwin.so
│     │        │  │  ├─ parsers.cpython-312-darwin.so
│     │        │  │  ├─ parsers.pyi
│     │        │  │  ├─ properties.cpython-312-darwin.so
│     │        │  │  ├─ properties.pyi
│     │        │  │  ├─ reshape.cpython-312-darwin.so
│     │        │  │  ├─ reshape.pyi
│     │        │  │  ├─ sas.cpython-312-darwin.so
│     │        │  │  ├─ sas.pyi
│     │        │  │  ├─ sparse.cpython-312-darwin.so
│     │        │  │  ├─ sparse.pyi
│     │        │  │  ├─ testing.cpython-312-darwin.so
│     │        │  │  ├─ testing.pyi
│     │        │  │  ├─ tslib.cpython-312-darwin.so
│     │        │  │  ├─ tslib.pyi
│     │        │  │  ├─ tslibs
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base.cpython-312-darwin.so
│     │        │  │  │  ├─ ccalendar.cpython-312-darwin.so
│     │        │  │  │  ├─ ccalendar.pyi
│     │        │  │  │  ├─ conversion.cpython-312-darwin.so
│     │        │  │  │  ├─ conversion.pyi
│     │        │  │  │  ├─ dtypes.cpython-312-darwin.so
│     │        │  │  │  ├─ dtypes.pyi
│     │        │  │  │  ├─ fields.cpython-312-darwin.so
│     │        │  │  │  ├─ fields.pyi
│     │        │  │  │  ├─ nattype.cpython-312-darwin.so
│     │        │  │  │  ├─ nattype.pyi
│     │        │  │  │  ├─ np_datetime.cpython-312-darwin.so
│     │        │  │  │  ├─ np_datetime.pyi
│     │        │  │  │  ├─ offsets.cpython-312-darwin.so
│     │        │  │  │  ├─ offsets.pyi
│     │        │  │  │  ├─ parsing.cpython-312-darwin.so
│     │        │  │  │  ├─ parsing.pyi
│     │        │  │  │  ├─ period.cpython-312-darwin.so
│     │        │  │  │  ├─ period.pyi
│     │        │  │  │  ├─ strptime.cpython-312-darwin.so
│     │        │  │  │  ├─ strptime.pyi
│     │        │  │  │  ├─ timedeltas.cpython-312-darwin.so
│     │        │  │  │  ├─ timedeltas.pyi
│     │        │  │  │  ├─ timestamps.cpython-312-darwin.so
│     │        │  │  │  ├─ timestamps.pyi
│     │        │  │  │  ├─ timezones.cpython-312-darwin.so
│     │        │  │  │  ├─ timezones.pyi
│     │        │  │  │  ├─ tzconversion.cpython-312-darwin.so
│     │        │  │  │  ├─ tzconversion.pyi
│     │        │  │  │  ├─ vectorized.cpython-312-darwin.so
│     │        │  │  │  └─ vectorized.pyi
│     │        │  │  ├─ window
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ aggregations.cpython-312-darwin.so
│     │        │  │  │  ├─ aggregations.pyi
│     │        │  │  │  ├─ indexers.cpython-312-darwin.so
│     │        │  │  │  └─ indexers.pyi
│     │        │  │  ├─ writers.cpython-312-darwin.so
│     │        │  │  └─ writers.pyi
│     │        │  ├─ _testing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _hypothesis.py
│     │        │  │  ├─ _io.py
│     │        │  │  ├─ _warnings.py
│     │        │  │  ├─ asserters.py
│     │        │  │  ├─ compat.py
│     │        │  │  └─ contexts.py
│     │        │  ├─ _typing.py
│     │        │  ├─ _version.py
│     │        │  ├─ _version_meson.py
│     │        │  ├─ api
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ extensions
│     │        │  │  │  └─ __init__.py
│     │        │  │  ├─ indexers
│     │        │  │  │  └─ __init__.py
│     │        │  │  ├─ interchange
│     │        │  │  │  └─ __init__.py
│     │        │  │  ├─ types
│     │        │  │  │  └─ __init__.py
│     │        │  │  └─ typing
│     │        │  │     └─ __init__.py
│     │        │  ├─ arrays
│     │        │  │  └─ __init__.py
│     │        │  ├─ compat
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _constants.py
│     │        │  │  ├─ _optional.py
│     │        │  │  ├─ compressors.py
│     │        │  │  ├─ numpy
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ function.py
│     │        │  │  ├─ pickle_compat.py
│     │        │  │  └─ pyarrow.py
│     │        │  ├─ conftest.py
│     │        │  ├─ core
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _numba
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ executor.py
│     │        │  │  │  ├─ extensions.py
│     │        │  │  │  └─ kernels
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ mean_.py
│     │        │  │  │     ├─ min_max_.py
│     │        │  │  │     ├─ shared.py
│     │        │  │  │     ├─ sum_.py
│     │        │  │  │     └─ var_.py
│     │        │  │  ├─ accessor.py
│     │        │  │  ├─ algorithms.py
│     │        │  │  ├─ api.py
│     │        │  │  ├─ apply.py
│     │        │  │  ├─ array_algos
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ datetimelike_accumulations.py
│     │        │  │  │  ├─ masked_accumulations.py
│     │        │  │  │  ├─ masked_reductions.py
│     │        │  │  │  ├─ putmask.py
│     │        │  │  │  ├─ quantile.py
│     │        │  │  │  ├─ replace.py
│     │        │  │  │  ├─ take.py
│     │        │  │  │  └─ transforms.py
│     │        │  │  ├─ arraylike.py
│     │        │  │  ├─ arrays
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _arrow_string_mixins.py
│     │        │  │  │  ├─ _mixins.py
│     │        │  │  │  ├─ _ranges.py
│     │        │  │  │  ├─ _utils.py
│     │        │  │  │  ├─ arrow
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _arrow_utils.py
│     │        │  │  │  │  ├─ accessors.py
│     │        │  │  │  │  ├─ array.py
│     │        │  │  │  │  └─ extension_types.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ boolean.py
│     │        │  │  │  ├─ categorical.py
│     │        │  │  │  ├─ datetimelike.py
│     │        │  │  │  ├─ datetimes.py
│     │        │  │  │  ├─ floating.py
│     │        │  │  │  ├─ integer.py
│     │        │  │  │  ├─ interval.py
│     │        │  │  │  ├─ masked.py
│     │        │  │  │  ├─ numeric.py
│     │        │  │  │  ├─ numpy_.py
│     │        │  │  │  ├─ period.py
│     │        │  │  │  ├─ sparse
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ accessor.py
│     │        │  │  │  │  ├─ array.py
│     │        │  │  │  │  └─ scipy_sparse.py
│     │        │  │  │  ├─ string_.py
│     │        │  │  │  ├─ string_arrow.py
│     │        │  │  │  └─ timedeltas.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ common.py
│     │        │  │  ├─ computation
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ align.py
│     │        │  │  │  ├─ api.py
│     │        │  │  │  ├─ check.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ engines.py
│     │        │  │  │  ├─ eval.py
│     │        │  │  │  ├─ expr.py
│     │        │  │  │  ├─ expressions.py
│     │        │  │  │  ├─ ops.py
│     │        │  │  │  ├─ parsing.py
│     │        │  │  │  ├─ pytables.py
│     │        │  │  │  └─ scope.py
│     │        │  │  ├─ config_init.py
│     │        │  │  ├─ construction.py
│     │        │  │  ├─ dtypes
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ api.py
│     │        │  │  │  ├─ astype.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ cast.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ concat.py
│     │        │  │  │  ├─ dtypes.py
│     │        │  │  │  ├─ generic.py
│     │        │  │  │  ├─ inference.py
│     │        │  │  │  └─ missing.py
│     │        │  │  ├─ flags.py
│     │        │  │  ├─ frame.py
│     │        │  │  ├─ generic.py
│     │        │  │  ├─ groupby
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ categorical.py
│     │        │  │  │  ├─ generic.py
│     │        │  │  │  ├─ groupby.py
│     │        │  │  │  ├─ grouper.py
│     │        │  │  │  ├─ indexing.py
│     │        │  │  │  ├─ numba_.py
│     │        │  │  │  └─ ops.py
│     │        │  │  ├─ indexers
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ objects.py
│     │        │  │  │  └─ utils.py
│     │        │  │  ├─ indexes
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ accessors.py
│     │        │  │  │  ├─ api.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ category.py
│     │        │  │  │  ├─ datetimelike.py
│     │        │  │  │  ├─ datetimes.py
│     │        │  │  │  ├─ extension.py
│     │        │  │  │  ├─ frozen.py
│     │        │  │  │  ├─ interval.py
│     │        │  │  │  ├─ multi.py
│     │        │  │  │  ├─ period.py
│     │        │  │  │  ├─ range.py
│     │        │  │  │  └─ timedeltas.py
│     │        │  │  ├─ indexing.py
│     │        │  │  ├─ interchange
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ buffer.py
│     │        │  │  │  ├─ column.py
│     │        │  │  │  ├─ dataframe.py
│     │        │  │  │  ├─ dataframe_protocol.py
│     │        │  │  │  ├─ from_dataframe.py
│     │        │  │  │  └─ utils.py
│     │        │  │  ├─ internals
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ api.py
│     │        │  │  │  ├─ array_manager.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ blocks.py
│     │        │  │  │  ├─ concat.py
│     │        │  │  │  ├─ construction.py
│     │        │  │  │  ├─ managers.py
│     │        │  │  │  └─ ops.py
│     │        │  │  ├─ methods
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ describe.py
│     │        │  │  │  ├─ selectn.py
│     │        │  │  │  └─ to_dict.py
│     │        │  │  ├─ missing.py
│     │        │  │  ├─ nanops.py
│     │        │  │  ├─ ops
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ array_ops.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ dispatch.py
│     │        │  │  │  ├─ docstrings.py
│     │        │  │  │  ├─ invalid.py
│     │        │  │  │  ├─ mask_ops.py
│     │        │  │  │  └─ missing.py
│     │        │  │  ├─ resample.py
│     │        │  │  ├─ reshape
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ api.py
│     │        │  │  │  ├─ concat.py
│     │        │  │  │  ├─ encoding.py
│     │        │  │  │  ├─ melt.py
│     │        │  │  │  ├─ merge.py
│     │        │  │  │  ├─ pivot.py
│     │        │  │  │  ├─ reshape.py
│     │        │  │  │  ├─ tile.py
│     │        │  │  │  └─ util.py
│     │        │  │  ├─ roperator.py
│     │        │  │  ├─ sample.py
│     │        │  │  ├─ series.py
│     │        │  │  ├─ shared_docs.py
│     │        │  │  ├─ sorting.py
│     │        │  │  ├─ sparse
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ api.py
│     │        │  │  ├─ strings
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ accessor.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  └─ object_array.py
│     │        │  │  ├─ tools
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ datetimes.py
│     │        │  │  │  ├─ numeric.py
│     │        │  │  │  ├─ timedeltas.py
│     │        │  │  │  └─ times.py
│     │        │  │  ├─ util
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ hashing.py
│     │        │  │  │  └─ numba_.py
│     │        │  │  └─ window
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ common.py
│     │        │  │     ├─ doc.py
│     │        │  │     ├─ ewm.py
│     │        │  │     ├─ expanding.py
│     │        │  │     ├─ numba_.py
│     │        │  │     ├─ online.py
│     │        │  │     └─ rolling.py
│     │        │  ├─ errors
│     │        │  │  └─ __init__.py
│     │        │  ├─ io
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _util.py
│     │        │  │  ├─ api.py
│     │        │  │  ├─ clipboard
│     │        │  │  │  └─ __init__.py
│     │        │  │  ├─ clipboards.py
│     │        │  │  ├─ common.py
│     │        │  │  ├─ excel
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _base.py
│     │        │  │  │  ├─ _calamine.py
│     │        │  │  │  ├─ _odfreader.py
│     │        │  │  │  ├─ _odswriter.py
│     │        │  │  │  ├─ _openpyxl.py
│     │        │  │  │  ├─ _pyxlsb.py
│     │        │  │  │  ├─ _util.py
│     │        │  │  │  ├─ _xlrd.py
│     │        │  │  │  └─ _xlsxwriter.py
│     │        │  │  ├─ feather_format.py
│     │        │  │  ├─ formats
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _color_data.py
│     │        │  │  │  ├─ console.py
│     │        │  │  │  ├─ css.py
│     │        │  │  │  ├─ csvs.py
│     │        │  │  │  ├─ excel.py
│     │        │  │  │  ├─ format.py
│     │        │  │  │  ├─ html.py
│     │        │  │  │  ├─ info.py
│     │        │  │  │  ├─ printing.py
│     │        │  │  │  ├─ string.py
│     │        │  │  │  ├─ style.py
│     │        │  │  │  ├─ style_render.py
│     │        │  │  │  ├─ templates
│     │        │  │  │  │  ├─ html.tpl
│     │        │  │  │  │  ├─ html_style.tpl
│     │        │  │  │  │  ├─ html_table.tpl
│     │        │  │  │  │  ├─ latex.tpl
│     │        │  │  │  │  ├─ latex_longtable.tpl
│     │        │  │  │  │  ├─ latex_table.tpl
│     │        │  │  │  │  └─ string.tpl
│     │        │  │  │  └─ xml.py
│     │        │  │  ├─ gbq.py
│     │        │  │  ├─ html.py
│     │        │  │  ├─ json
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _json.py
│     │        │  │  │  ├─ _normalize.py
│     │        │  │  │  └─ _table_schema.py
│     │        │  │  ├─ orc.py
│     │        │  │  ├─ parquet.py
│     │        │  │  ├─ parsers
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ arrow_parser_wrapper.py
│     │        │  │  │  ├─ base_parser.py
│     │        │  │  │  ├─ c_parser_wrapper.py
│     │        │  │  │  ├─ python_parser.py
│     │        │  │  │  └─ readers.py
│     │        │  │  ├─ pickle.py
│     │        │  │  ├─ pytables.py
│     │        │  │  ├─ sas
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ sas7bdat.py
│     │        │  │  │  ├─ sas_constants.py
│     │        │  │  │  ├─ sas_xport.py
│     │        │  │  │  └─ sasreader.py
│     │        │  │  ├─ spss.py
│     │        │  │  ├─ sql.py
│     │        │  │  ├─ stata.py
│     │        │  │  └─ xml.py
│     │        │  ├─ plotting
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _core.py
│     │        │  │  ├─ _matplotlib
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ boxplot.py
│     │        │  │  │  ├─ converter.py
│     │        │  │  │  ├─ core.py
│     │        │  │  │  ├─ groupby.py
│     │        │  │  │  ├─ hist.py
│     │        │  │  │  ├─ misc.py
│     │        │  │  │  ├─ style.py
│     │        │  │  │  ├─ timeseries.py
│     │        │  │  │  └─ tools.py
│     │        │  │  └─ _misc.py
│     │        │  ├─ pyproject.toml
│     │        │  ├─ testing.py
│     │        │  ├─ tests
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ api
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_api.py
│     │        │  │  │  └─ test_types.py
│     │        │  │  ├─ apply
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ test_frame_apply.py
│     │        │  │  │  ├─ test_frame_apply_relabeling.py
│     │        │  │  │  ├─ test_frame_transform.py
│     │        │  │  │  ├─ test_invalid_arg.py
│     │        │  │  │  ├─ test_numba.py
│     │        │  │  │  ├─ test_series_apply.py
│     │        │  │  │  ├─ test_series_apply_relabeling.py
│     │        │  │  │  ├─ test_series_transform.py
│     │        │  │  │  └─ test_str.py
│     │        │  │  ├─ arithmetic
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ test_array_ops.py
│     │        │  │  │  ├─ test_categorical.py
│     │        │  │  │  ├─ test_datetime64.py
│     │        │  │  │  ├─ test_interval.py
│     │        │  │  │  ├─ test_numeric.py
│     │        │  │  │  ├─ test_object.py
│     │        │  │  │  ├─ test_period.py
│     │        │  │  │  └─ test_timedelta64.py
│     │        │  │  ├─ arrays
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ boolean
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_comparison.py
│     │        │  │  │  │  ├─ test_construction.py
│     │        │  │  │  │  ├─ test_function.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_logical.py
│     │        │  │  │  │  ├─ test_ops.py
│     │        │  │  │  │  ├─ test_reduction.py
│     │        │  │  │  │  └─ test_repr.py
│     │        │  │  │  ├─ categorical
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_algos.py
│     │        │  │  │  │  ├─ test_analytics.py
│     │        │  │  │  │  ├─ test_api.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_dtypes.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_map.py
│     │        │  │  │  │  ├─ test_missing.py
│     │        │  │  │  │  ├─ test_operators.py
│     │        │  │  │  │  ├─ test_replace.py
│     │        │  │  │  │  ├─ test_repr.py
│     │        │  │  │  │  ├─ test_sorting.py
│     │        │  │  │  │  ├─ test_subclass.py
│     │        │  │  │  │  ├─ test_take.py
│     │        │  │  │  │  └─ test_warnings.py
│     │        │  │  │  ├─ datetimes
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_cumulative.py
│     │        │  │  │  │  └─ test_reductions.py
│     │        │  │  │  ├─ floating
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ conftest.py
│     │        │  │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_comparison.py
│     │        │  │  │  │  ├─ test_concat.py
│     │        │  │  │  │  ├─ test_construction.py
│     │        │  │  │  │  ├─ test_contains.py
│     │        │  │  │  │  ├─ test_function.py
│     │        │  │  │  │  ├─ test_repr.py
│     │        │  │  │  │  └─ test_to_numpy.py
│     │        │  │  │  ├─ integer
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ conftest.py
│     │        │  │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  │  ├─ test_comparison.py
│     │        │  │  │  │  ├─ test_concat.py
│     │        │  │  │  │  ├─ test_construction.py
│     │        │  │  │  │  ├─ test_dtypes.py
│     │        │  │  │  │  ├─ test_function.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_reduction.py
│     │        │  │  │  │  └─ test_repr.py
│     │        │  │  │  ├─ interval
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_formats.py
│     │        │  │  │  │  ├─ test_interval.py
│     │        │  │  │  │  ├─ test_interval_pyarrow.py
│     │        │  │  │  │  └─ test_overlaps.py
│     │        │  │  │  ├─ masked
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  │  ├─ test_arrow_compat.py
│     │        │  │  │  │  ├─ test_function.py
│     │        │  │  │  │  └─ test_indexing.py
│     │        │  │  │  ├─ masked_shared.py
│     │        │  │  │  ├─ numpy_
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  └─ test_numpy.py
│     │        │  │  │  ├─ period
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_arrow_compat.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  └─ test_reductions.py
│     │        │  │  │  ├─ sparse
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_accessor.py
│     │        │  │  │  │  ├─ test_arithmetics.py
│     │        │  │  │  │  ├─ test_array.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_combine_concat.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_dtype.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_libsparse.py
│     │        │  │  │  │  ├─ test_reductions.py
│     │        │  │  │  │  └─ test_unary.py
│     │        │  │  │  ├─ string_
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_concat.py
│     │        │  │  │  │  ├─ test_string.py
│     │        │  │  │  │  └─ test_string_arrow.py
│     │        │  │  │  ├─ test_array.py
│     │        │  │  │  ├─ test_datetimelike.py
│     │        │  │  │  ├─ test_datetimes.py
│     │        │  │  │  ├─ test_ndarray_backed.py
│     │        │  │  │  ├─ test_period.py
│     │        │  │  │  ├─ test_timedeltas.py
│     │        │  │  │  └─ timedeltas
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_constructors.py
│     │        │  │  │     ├─ test_cumulative.py
│     │        │  │  │     └─ test_reductions.py
│     │        │  │  ├─ base
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ test_constructors.py
│     │        │  │  │  ├─ test_conversion.py
│     │        │  │  │  ├─ test_fillna.py
│     │        │  │  │  ├─ test_misc.py
│     │        │  │  │  ├─ test_transpose.py
│     │        │  │  │  ├─ test_unique.py
│     │        │  │  │  └─ test_value_counts.py
│     │        │  │  ├─ computation
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_compat.py
│     │        │  │  │  └─ test_eval.py
│     │        │  │  ├─ config
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_config.py
│     │        │  │  │  └─ test_localization.py
│     │        │  │  ├─ construction
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ test_extract_array.py
│     │        │  │  ├─ copy_view
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ index
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_datetimeindex.py
│     │        │  │  │  │  ├─ test_index.py
│     │        │  │  │  │  ├─ test_periodindex.py
│     │        │  │  │  │  └─ test_timedeltaindex.py
│     │        │  │  │  ├─ test_array.py
│     │        │  │  │  ├─ test_astype.py
│     │        │  │  │  ├─ test_chained_assignment_deprecation.py
│     │        │  │  │  ├─ test_clip.py
│     │        │  │  │  ├─ test_constructors.py
│     │        │  │  │  ├─ test_core_functionalities.py
│     │        │  │  │  ├─ test_functions.py
│     │        │  │  │  ├─ test_indexing.py
│     │        │  │  │  ├─ test_internals.py
│     │        │  │  │  ├─ test_interp_fillna.py
│     │        │  │  │  ├─ test_methods.py
│     │        │  │  │  ├─ test_replace.py
│     │        │  │  │  ├─ test_setitem.py
│     │        │  │  │  ├─ test_util.py
│     │        │  │  │  └─ util.py
│     │        │  │  ├─ dtypes
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ cast
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_can_hold_element.py
│     │        │  │  │  │  ├─ test_construct_from_scalar.py
│     │        │  │  │  │  ├─ test_construct_ndarray.py
│     │        │  │  │  │  ├─ test_construct_object_arr.py
│     │        │  │  │  │  ├─ test_dict_compat.py
│     │        │  │  │  │  ├─ test_downcast.py
│     │        │  │  │  │  ├─ test_find_common_type.py
│     │        │  │  │  │  ├─ test_infer_datetimelike.py
│     │        │  │  │  │  ├─ test_infer_dtype.py
│     │        │  │  │  │  ├─ test_maybe_box_native.py
│     │        │  │  │  │  └─ test_promote.py
│     │        │  │  │  ├─ test_common.py
│     │        │  │  │  ├─ test_concat.py
│     │        │  │  │  ├─ test_dtypes.py
│     │        │  │  │  ├─ test_generic.py
│     │        │  │  │  ├─ test_inference.py
│     │        │  │  │  └─ test_missing.py
│     │        │  │  ├─ extension
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ array_with_attr
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ array.py
│     │        │  │  │  │  └─ test_array_with_attr.py
│     │        │  │  │  ├─ base
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ accumulate.py
│     │        │  │  │  │  ├─ base.py
│     │        │  │  │  │  ├─ casting.py
│     │        │  │  │  │  ├─ constructors.py
│     │        │  │  │  │  ├─ dim2.py
│     │        │  │  │  │  ├─ dtype.py
│     │        │  │  │  │  ├─ getitem.py
│     │        │  │  │  │  ├─ groupby.py
│     │        │  │  │  │  ├─ index.py
│     │        │  │  │  │  ├─ interface.py
│     │        │  │  │  │  ├─ io.py
│     │        │  │  │  │  ├─ methods.py
│     │        │  │  │  │  ├─ missing.py
│     │        │  │  │  │  ├─ ops.py
│     │        │  │  │  │  ├─ printing.py
│     │        │  │  │  │  ├─ reduce.py
│     │        │  │  │  │  ├─ reshaping.py
│     │        │  │  │  │  └─ setitem.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ date
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ array.py
│     │        │  │  │  ├─ decimal
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ array.py
│     │        │  │  │  │  └─ test_decimal.py
│     │        │  │  │  ├─ json
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ array.py
│     │        │  │  │  │  └─ test_json.py
│     │        │  │  │  ├─ list
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ array.py
│     │        │  │  │  │  └─ test_list.py
│     │        │  │  │  ├─ test_arrow.py
│     │        │  │  │  ├─ test_categorical.py
│     │        │  │  │  ├─ test_common.py
│     │        │  │  │  ├─ test_datetime.py
│     │        │  │  │  ├─ test_extension.py
│     │        │  │  │  ├─ test_interval.py
│     │        │  │  │  ├─ test_masked.py
│     │        │  │  │  ├─ test_numpy.py
│     │        │  │  │  ├─ test_period.py
│     │        │  │  │  ├─ test_sparse.py
│     │        │  │  │  └─ test_string.py
│     │        │  │  ├─ frame
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ constructors
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_from_dict.py
│     │        │  │  │  │  └─ test_from_records.py
│     │        │  │  │  ├─ indexing
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_coercion.py
│     │        │  │  │  │  ├─ test_delitem.py
│     │        │  │  │  │  ├─ test_get.py
│     │        │  │  │  │  ├─ test_get_value.py
│     │        │  │  │  │  ├─ test_getitem.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_insert.py
│     │        │  │  │  │  ├─ test_mask.py
│     │        │  │  │  │  ├─ test_set_value.py
│     │        │  │  │  │  ├─ test_setitem.py
│     │        │  │  │  │  ├─ test_take.py
│     │        │  │  │  │  ├─ test_where.py
│     │        │  │  │  │  └─ test_xs.py
│     │        │  │  │  ├─ methods
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_add_prefix_suffix.py
│     │        │  │  │  │  ├─ test_align.py
│     │        │  │  │  │  ├─ test_asfreq.py
│     │        │  │  │  │  ├─ test_asof.py
│     │        │  │  │  │  ├─ test_assign.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_at_time.py
│     │        │  │  │  │  ├─ test_between_time.py
│     │        │  │  │  │  ├─ test_clip.py
│     │        │  │  │  │  ├─ test_combine.py
│     │        │  │  │  │  ├─ test_combine_first.py
│     │        │  │  │  │  ├─ test_compare.py
│     │        │  │  │  │  ├─ test_convert_dtypes.py
│     │        │  │  │  │  ├─ test_copy.py
│     │        │  │  │  │  ├─ test_count.py
│     │        │  │  │  │  ├─ test_cov_corr.py
│     │        │  │  │  │  ├─ test_describe.py
│     │        │  │  │  │  ├─ test_diff.py
│     │        │  │  │  │  ├─ test_dot.py
│     │        │  │  │  │  ├─ test_drop.py
│     │        │  │  │  │  ├─ test_drop_duplicates.py
│     │        │  │  │  │  ├─ test_droplevel.py
│     │        │  │  │  │  ├─ test_dropna.py
│     │        │  │  │  │  ├─ test_dtypes.py
│     │        │  │  │  │  ├─ test_duplicated.py
│     │        │  │  │  │  ├─ test_equals.py
│     │        │  │  │  │  ├─ test_explode.py
│     │        │  │  │  │  ├─ test_fillna.py
│     │        │  │  │  │  ├─ test_filter.py
│     │        │  │  │  │  ├─ test_first_and_last.py
│     │        │  │  │  │  ├─ test_first_valid_index.py
│     │        │  │  │  │  ├─ test_get_numeric_data.py
│     │        │  │  │  │  ├─ test_head_tail.py
│     │        │  │  │  │  ├─ test_infer_objects.py
│     │        │  │  │  │  ├─ test_info.py
│     │        │  │  │  │  ├─ test_interpolate.py
│     │        │  │  │  │  ├─ test_is_homogeneous_dtype.py
│     │        │  │  │  │  ├─ test_isetitem.py
│     │        │  │  │  │  ├─ test_isin.py
│     │        │  │  │  │  ├─ test_iterrows.py
│     │        │  │  │  │  ├─ test_join.py
│     │        │  │  │  │  ├─ test_map.py
│     │        │  │  │  │  ├─ test_matmul.py
│     │        │  │  │  │  ├─ test_nlargest.py
│     │        │  │  │  │  ├─ test_pct_change.py
│     │        │  │  │  │  ├─ test_pipe.py
│     │        │  │  │  │  ├─ test_pop.py
│     │        │  │  │  │  ├─ test_quantile.py
│     │        │  │  │  │  ├─ test_rank.py
│     │        │  │  │  │  ├─ test_reindex.py
│     │        │  │  │  │  ├─ test_reindex_like.py
│     │        │  │  │  │  ├─ test_rename.py
│     │        │  │  │  │  ├─ test_rename_axis.py
│     │        │  │  │  │  ├─ test_reorder_levels.py
│     │        │  │  │  │  ├─ test_replace.py
│     │        │  │  │  │  ├─ test_reset_index.py
│     │        │  │  │  │  ├─ test_round.py
│     │        │  │  │  │  ├─ test_sample.py
│     │        │  │  │  │  ├─ test_select_dtypes.py
│     │        │  │  │  │  ├─ test_set_axis.py
│     │        │  │  │  │  ├─ test_set_index.py
│     │        │  │  │  │  ├─ test_shift.py
│     │        │  │  │  │  ├─ test_size.py
│     │        │  │  │  │  ├─ test_sort_index.py
│     │        │  │  │  │  ├─ test_sort_values.py
│     │        │  │  │  │  ├─ test_swapaxes.py
│     │        │  │  │  │  ├─ test_swaplevel.py
│     │        │  │  │  │  ├─ test_to_csv.py
│     │        │  │  │  │  ├─ test_to_dict.py
│     │        │  │  │  │  ├─ test_to_dict_of_blocks.py
│     │        │  │  │  │  ├─ test_to_numpy.py
│     │        │  │  │  │  ├─ test_to_period.py
│     │        │  │  │  │  ├─ test_to_records.py
│     │        │  │  │  │  ├─ test_to_timestamp.py
│     │        │  │  │  │  ├─ test_transpose.py
│     │        │  │  │  │  ├─ test_truncate.py
│     │        │  │  │  │  ├─ test_tz_convert.py
│     │        │  │  │  │  ├─ test_tz_localize.py
│     │        │  │  │  │  ├─ test_update.py
│     │        │  │  │  │  ├─ test_value_counts.py
│     │        │  │  │  │  └─ test_values.py
│     │        │  │  │  ├─ test_alter_axes.py
│     │        │  │  │  ├─ test_api.py
│     │        │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  ├─ test_arrow_interface.py
│     │        │  │  │  ├─ test_block_internals.py
│     │        │  │  │  ├─ test_constructors.py
│     │        │  │  │  ├─ test_cumulative.py
│     │        │  │  │  ├─ test_iteration.py
│     │        │  │  │  ├─ test_logical_ops.py
│     │        │  │  │  ├─ test_nonunique_indexes.py
│     │        │  │  │  ├─ test_npfuncs.py
│     │        │  │  │  ├─ test_query_eval.py
│     │        │  │  │  ├─ test_reductions.py
│     │        │  │  │  ├─ test_repr.py
│     │        │  │  │  ├─ test_stack_unstack.py
│     │        │  │  │  ├─ test_subclass.py
│     │        │  │  │  ├─ test_ufunc.py
│     │        │  │  │  ├─ test_unary.py
│     │        │  │  │  └─ test_validate.py
│     │        │  │  ├─ generic
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_duplicate_labels.py
│     │        │  │  │  ├─ test_finalize.py
│     │        │  │  │  ├─ test_frame.py
│     │        │  │  │  ├─ test_generic.py
│     │        │  │  │  ├─ test_label_or_level_utils.py
│     │        │  │  │  ├─ test_series.py
│     │        │  │  │  └─ test_to_xarray.py
│     │        │  │  ├─ groupby
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ aggregate
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_aggregate.py
│     │        │  │  │  │  ├─ test_cython.py
│     │        │  │  │  │  ├─ test_numba.py
│     │        │  │  │  │  └─ test_other.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ methods
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_corrwith.py
│     │        │  │  │  │  ├─ test_describe.py
│     │        │  │  │  │  ├─ test_groupby_shift_diff.py
│     │        │  │  │  │  ├─ test_is_monotonic.py
│     │        │  │  │  │  ├─ test_nlargest_nsmallest.py
│     │        │  │  │  │  ├─ test_nth.py
│     │        │  │  │  │  ├─ test_quantile.py
│     │        │  │  │  │  ├─ test_rank.py
│     │        │  │  │  │  ├─ test_sample.py
│     │        │  │  │  │  ├─ test_size.py
│     │        │  │  │  │  ├─ test_skew.py
│     │        │  │  │  │  └─ test_value_counts.py
│     │        │  │  │  ├─ test_all_methods.py
│     │        │  │  │  ├─ test_api.py
│     │        │  │  │  ├─ test_apply.py
│     │        │  │  │  ├─ test_apply_mutate.py
│     │        │  │  │  ├─ test_bin_groupby.py
│     │        │  │  │  ├─ test_categorical.py
│     │        │  │  │  ├─ test_counting.py
│     │        │  │  │  ├─ test_cumulative.py
│     │        │  │  │  ├─ test_filters.py
│     │        │  │  │  ├─ test_groupby.py
│     │        │  │  │  ├─ test_groupby_dropna.py
│     │        │  │  │  ├─ test_groupby_subclass.py
│     │        │  │  │  ├─ test_grouping.py
│     │        │  │  │  ├─ test_index_as_string.py
│     │        │  │  │  ├─ test_indexing.py
│     │        │  │  │  ├─ test_libgroupby.py
│     │        │  │  │  ├─ test_missing.py
│     │        │  │  │  ├─ test_numba.py
│     │        │  │  │  ├─ test_numeric_only.py
│     │        │  │  │  ├─ test_pipe.py
│     │        │  │  │  ├─ test_raises.py
│     │        │  │  │  ├─ test_reductions.py
│     │        │  │  │  ├─ test_timegrouper.py
│     │        │  │  │  └─ transform
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_numba.py
│     │        │  │  │     └─ test_transform.py
│     │        │  │  ├─ indexes
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base_class
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_formats.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_pickle.py
│     │        │  │  │  │  ├─ test_reshape.py
│     │        │  │  │  │  ├─ test_setops.py
│     │        │  │  │  │  └─ test_where.py
│     │        │  │  │  ├─ categorical
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_append.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_category.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_equals.py
│     │        │  │  │  │  ├─ test_fillna.py
│     │        │  │  │  │  ├─ test_formats.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_map.py
│     │        │  │  │  │  ├─ test_reindex.py
│     │        │  │  │  │  └─ test_setops.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ datetimelike_
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_drop_duplicates.py
│     │        │  │  │  │  ├─ test_equals.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_is_monotonic.py
│     │        │  │  │  │  ├─ test_nat.py
│     │        │  │  │  │  ├─ test_sort_values.py
│     │        │  │  │  │  └─ test_value_counts.py
│     │        │  │  │  ├─ datetimes
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ methods
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ test_asof.py
│     │        │  │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  │  ├─ test_delete.py
│     │        │  │  │  │  │  ├─ test_factorize.py
│     │        │  │  │  │  │  ├─ test_fillna.py
│     │        │  │  │  │  │  ├─ test_insert.py
│     │        │  │  │  │  │  ├─ test_isocalendar.py
│     │        │  │  │  │  │  ├─ test_map.py
│     │        │  │  │  │  │  ├─ test_normalize.py
│     │        │  │  │  │  │  ├─ test_repeat.py
│     │        │  │  │  │  │  ├─ test_resolution.py
│     │        │  │  │  │  │  ├─ test_round.py
│     │        │  │  │  │  │  ├─ test_shift.py
│     │        │  │  │  │  │  ├─ test_snap.py
│     │        │  │  │  │  │  ├─ test_to_frame.py
│     │        │  │  │  │  │  ├─ test_to_julian_date.py
│     │        │  │  │  │  │  ├─ test_to_period.py
│     │        │  │  │  │  │  ├─ test_to_pydatetime.py
│     │        │  │  │  │  │  ├─ test_to_series.py
│     │        │  │  │  │  │  ├─ test_tz_convert.py
│     │        │  │  │  │  │  ├─ test_tz_localize.py
│     │        │  │  │  │  │  └─ test_unique.py
│     │        │  │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_date_range.py
│     │        │  │  │  │  ├─ test_datetime.py
│     │        │  │  │  │  ├─ test_formats.py
│     │        │  │  │  │  ├─ test_freq_attr.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_iter.py
│     │        │  │  │  │  ├─ test_join.py
│     │        │  │  │  │  ├─ test_npfuncs.py
│     │        │  │  │  │  ├─ test_ops.py
│     │        │  │  │  │  ├─ test_partial_slicing.py
│     │        │  │  │  │  ├─ test_pickle.py
│     │        │  │  │  │  ├─ test_reindex.py
│     │        │  │  │  │  ├─ test_scalar_compat.py
│     │        │  │  │  │  ├─ test_setops.py
│     │        │  │  │  │  └─ test_timezones.py
│     │        │  │  │  ├─ interval
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_equals.py
│     │        │  │  │  │  ├─ test_formats.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_interval.py
│     │        │  │  │  │  ├─ test_interval_range.py
│     │        │  │  │  │  ├─ test_interval_tree.py
│     │        │  │  │  │  ├─ test_join.py
│     │        │  │  │  │  ├─ test_pickle.py
│     │        │  │  │  │  └─ test_setops.py
│     │        │  │  │  ├─ multi
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ conftest.py
│     │        │  │  │  │  ├─ test_analytics.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_compat.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_conversion.py
│     │        │  │  │  │  ├─ test_copy.py
│     │        │  │  │  │  ├─ test_drop.py
│     │        │  │  │  │  ├─ test_duplicates.py
│     │        │  │  │  │  ├─ test_equivalence.py
│     │        │  │  │  │  ├─ test_formats.py
│     │        │  │  │  │  ├─ test_get_level_values.py
│     │        │  │  │  │  ├─ test_get_set.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_integrity.py
│     │        │  │  │  │  ├─ test_isin.py
│     │        │  │  │  │  ├─ test_join.py
│     │        │  │  │  │  ├─ test_lexsort.py
│     │        │  │  │  │  ├─ test_missing.py
│     │        │  │  │  │  ├─ test_monotonic.py
│     │        │  │  │  │  ├─ test_names.py
│     │        │  │  │  │  ├─ test_partial_indexing.py
│     │        │  │  │  │  ├─ test_pickle.py
│     │        │  │  │  │  ├─ test_reindex.py
│     │        │  │  │  │  ├─ test_reshape.py
│     │        │  │  │  │  ├─ test_setops.py
│     │        │  │  │  │  ├─ test_sorting.py
│     │        │  │  │  │  └─ test_take.py
│     │        │  │  │  ├─ numeric
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_join.py
│     │        │  │  │  │  ├─ test_numeric.py
│     │        │  │  │  │  └─ test_setops.py
│     │        │  │  │  ├─ object
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  └─ test_indexing.py
│     │        │  │  │  ├─ period
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ methods
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ test_asfreq.py
│     │        │  │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  │  ├─ test_factorize.py
│     │        │  │  │  │  │  ├─ test_fillna.py
│     │        │  │  │  │  │  ├─ test_insert.py
│     │        │  │  │  │  │  ├─ test_is_full.py
│     │        │  │  │  │  │  ├─ test_repeat.py
│     │        │  │  │  │  │  ├─ test_shift.py
│     │        │  │  │  │  │  └─ test_to_timestamp.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_formats.py
│     │        │  │  │  │  ├─ test_freq_attr.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_join.py
│     │        │  │  │  │  ├─ test_monotonic.py
│     │        │  │  │  │  ├─ test_partial_slicing.py
│     │        │  │  │  │  ├─ test_period.py
│     │        │  │  │  │  ├─ test_period_range.py
│     │        │  │  │  │  ├─ test_pickle.py
│     │        │  │  │  │  ├─ test_resolution.py
│     │        │  │  │  │  ├─ test_scalar_compat.py
│     │        │  │  │  │  ├─ test_searchsorted.py
│     │        │  │  │  │  ├─ test_setops.py
│     │        │  │  │  │  └─ test_tools.py
│     │        │  │  │  ├─ ranges
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_join.py
│     │        │  │  │  │  ├─ test_range.py
│     │        │  │  │  │  └─ test_setops.py
│     │        │  │  │  ├─ string
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  └─ test_indexing.py
│     │        │  │  │  ├─ test_any_index.py
│     │        │  │  │  ├─ test_base.py
│     │        │  │  │  ├─ test_common.py
│     │        │  │  │  ├─ test_datetimelike.py
│     │        │  │  │  ├─ test_engines.py
│     │        │  │  │  ├─ test_frozen.py
│     │        │  │  │  ├─ test_index_new.py
│     │        │  │  │  ├─ test_indexing.py
│     │        │  │  │  ├─ test_numpy_compat.py
│     │        │  │  │  ├─ test_old_base.py
│     │        │  │  │  ├─ test_setops.py
│     │        │  │  │  ├─ test_subclass.py
│     │        │  │  │  └─ timedeltas
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ methods
│     │        │  │  │     │  ├─ __init__.py
│     │        │  │  │     │  ├─ test_astype.py
│     │        │  │  │     │  ├─ test_factorize.py
│     │        │  │  │     │  ├─ test_fillna.py
│     │        │  │  │     │  ├─ test_insert.py
│     │        │  │  │     │  ├─ test_repeat.py
│     │        │  │  │     │  └─ test_shift.py
│     │        │  │  │     ├─ test_arithmetic.py
│     │        │  │  │     ├─ test_constructors.py
│     │        │  │  │     ├─ test_delete.py
│     │        │  │  │     ├─ test_formats.py
│     │        │  │  │     ├─ test_freq_attr.py
│     │        │  │  │     ├─ test_indexing.py
│     │        │  │  │     ├─ test_join.py
│     │        │  │  │     ├─ test_ops.py
│     │        │  │  │     ├─ test_pickle.py
│     │        │  │  │     ├─ test_scalar_compat.py
│     │        │  │  │     ├─ test_searchsorted.py
│     │        │  │  │     ├─ test_setops.py
│     │        │  │  │     ├─ test_timedelta.py
│     │        │  │  │     └─ test_timedelta_range.py
│     │        │  │  ├─ indexing
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ interval
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_interval.py
│     │        │  │  │  │  └─ test_interval_new.py
│     │        │  │  │  ├─ multiindex
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_chaining_and_caching.py
│     │        │  │  │  │  ├─ test_datetime.py
│     │        │  │  │  │  ├─ test_getitem.py
│     │        │  │  │  │  ├─ test_iloc.py
│     │        │  │  │  │  ├─ test_indexing_slow.py
│     │        │  │  │  │  ├─ test_loc.py
│     │        │  │  │  │  ├─ test_multiindex.py
│     │        │  │  │  │  ├─ test_partial.py
│     │        │  │  │  │  ├─ test_setitem.py
│     │        │  │  │  │  ├─ test_slice.py
│     │        │  │  │  │  └─ test_sorted.py
│     │        │  │  │  ├─ test_at.py
│     │        │  │  │  ├─ test_categorical.py
│     │        │  │  │  ├─ test_chaining_and_caching.py
│     │        │  │  │  ├─ test_check_indexer.py
│     │        │  │  │  ├─ test_coercion.py
│     │        │  │  │  ├─ test_datetime.py
│     │        │  │  │  ├─ test_floats.py
│     │        │  │  │  ├─ test_iat.py
│     │        │  │  │  ├─ test_iloc.py
│     │        │  │  │  ├─ test_indexers.py
│     │        │  │  │  ├─ test_indexing.py
│     │        │  │  │  ├─ test_loc.py
│     │        │  │  │  ├─ test_na_indexing.py
│     │        │  │  │  ├─ test_partial.py
│     │        │  │  │  └─ test_scalar.py
│     │        │  │  ├─ interchange
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_impl.py
│     │        │  │  │  ├─ test_spec_conformance.py
│     │        │  │  │  └─ test_utils.py
│     │        │  │  ├─ internals
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_api.py
│     │        │  │  │  ├─ test_internals.py
│     │        │  │  │  └─ test_managers.py
│     │        │  │  ├─ io
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ excel
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_odf.py
│     │        │  │  │  │  ├─ test_odswriter.py
│     │        │  │  │  │  ├─ test_openpyxl.py
│     │        │  │  │  │  ├─ test_readers.py
│     │        │  │  │  │  ├─ test_style.py
│     │        │  │  │  │  ├─ test_writers.py
│     │        │  │  │  │  ├─ test_xlrd.py
│     │        │  │  │  │  └─ test_xlsxwriter.py
│     │        │  │  │  ├─ formats
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ style
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ test_bar.py
│     │        │  │  │  │  │  ├─ test_exceptions.py
│     │        │  │  │  │  │  ├─ test_format.py
│     │        │  │  │  │  │  ├─ test_highlight.py
│     │        │  │  │  │  │  ├─ test_html.py
│     │        │  │  │  │  │  ├─ test_matplotlib.py
│     │        │  │  │  │  │  ├─ test_non_unique.py
│     │        │  │  │  │  │  ├─ test_style.py
│     │        │  │  │  │  │  ├─ test_to_latex.py
│     │        │  │  │  │  │  ├─ test_to_string.py
│     │        │  │  │  │  │  └─ test_tooltip.py
│     │        │  │  │  │  ├─ test_console.py
│     │        │  │  │  │  ├─ test_css.py
│     │        │  │  │  │  ├─ test_eng_formatting.py
│     │        │  │  │  │  ├─ test_format.py
│     │        │  │  │  │  ├─ test_ipython_compat.py
│     │        │  │  │  │  ├─ test_printing.py
│     │        │  │  │  │  ├─ test_to_csv.py
│     │        │  │  │  │  ├─ test_to_excel.py
│     │        │  │  │  │  ├─ test_to_html.py
│     │        │  │  │  │  ├─ test_to_latex.py
│     │        │  │  │  │  ├─ test_to_markdown.py
│     │        │  │  │  │  └─ test_to_string.py
│     │        │  │  │  ├─ generate_legacy_storage_files.py
│     │        │  │  │  ├─ json
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ conftest.py
│     │        │  │  │  │  ├─ test_compression.py
│     │        │  │  │  │  ├─ test_deprecated_kwargs.py
│     │        │  │  │  │  ├─ test_json_table_schema.py
│     │        │  │  │  │  ├─ test_json_table_schema_ext_dtype.py
│     │        │  │  │  │  ├─ test_normalize.py
│     │        │  │  │  │  ├─ test_pandas.py
│     │        │  │  │  │  ├─ test_readlines.py
│     │        │  │  │  │  └─ test_ujson.py
│     │        │  │  │  ├─ parser
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ common
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ test_chunksize.py
│     │        │  │  │  │  │  ├─ test_common_basic.py
│     │        │  │  │  │  │  ├─ test_data_list.py
│     │        │  │  │  │  │  ├─ test_decimal.py
│     │        │  │  │  │  │  ├─ test_file_buffer_url.py
│     │        │  │  │  │  │  ├─ test_float.py
│     │        │  │  │  │  │  ├─ test_index.py
│     │        │  │  │  │  │  ├─ test_inf.py
│     │        │  │  │  │  │  ├─ test_ints.py
│     │        │  │  │  │  │  ├─ test_iterator.py
│     │        │  │  │  │  │  ├─ test_read_errors.py
│     │        │  │  │  │  │  └─ test_verbose.py
│     │        │  │  │  │  ├─ conftest.py
│     │        │  │  │  │  ├─ dtypes
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ test_categorical.py
│     │        │  │  │  │  │  ├─ test_dtypes_basic.py
│     │        │  │  │  │  │  └─ test_empty.py
│     │        │  │  │  │  ├─ test_c_parser_only.py
│     │        │  │  │  │  ├─ test_comment.py
│     │        │  │  │  │  ├─ test_compression.py
│     │        │  │  │  │  ├─ test_concatenate_chunks.py
│     │        │  │  │  │  ├─ test_converters.py
│     │        │  │  │  │  ├─ test_dialect.py
│     │        │  │  │  │  ├─ test_encoding.py
│     │        │  │  │  │  ├─ test_header.py
│     │        │  │  │  │  ├─ test_index_col.py
│     │        │  │  │  │  ├─ test_mangle_dupes.py
│     │        │  │  │  │  ├─ test_multi_thread.py
│     │        │  │  │  │  ├─ test_na_values.py
│     │        │  │  │  │  ├─ test_network.py
│     │        │  │  │  │  ├─ test_parse_dates.py
│     │        │  │  │  │  ├─ test_python_parser_only.py
│     │        │  │  │  │  ├─ test_quoting.py
│     │        │  │  │  │  ├─ test_read_fwf.py
│     │        │  │  │  │  ├─ test_skiprows.py
│     │        │  │  │  │  ├─ test_textreader.py
│     │        │  │  │  │  ├─ test_unsupported.py
│     │        │  │  │  │  ├─ test_upcast.py
│     │        │  │  │  │  └─ usecols
│     │        │  │  │  │     ├─ __init__.py
│     │        │  │  │  │     ├─ test_parse_dates.py
│     │        │  │  │  │     ├─ test_strings.py
│     │        │  │  │  │     └─ test_usecols_basic.py
│     │        │  │  │  ├─ pytables
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ common.py
│     │        │  │  │  │  ├─ conftest.py
│     │        │  │  │  │  ├─ test_append.py
│     │        │  │  │  │  ├─ test_categorical.py
│     │        │  │  │  │  ├─ test_compat.py
│     │        │  │  │  │  ├─ test_complex.py
│     │        │  │  │  │  ├─ test_errors.py
│     │        │  │  │  │  ├─ test_file_handling.py
│     │        │  │  │  │  ├─ test_keys.py
│     │        │  │  │  │  ├─ test_put.py
│     │        │  │  │  │  ├─ test_pytables_missing.py
│     │        │  │  │  │  ├─ test_read.py
│     │        │  │  │  │  ├─ test_retain_attributes.py
│     │        │  │  │  │  ├─ test_round_trip.py
│     │        │  │  │  │  ├─ test_select.py
│     │        │  │  │  │  ├─ test_store.py
│     │        │  │  │  │  ├─ test_subclass.py
│     │        │  │  │  │  ├─ test_time_series.py
│     │        │  │  │  │  └─ test_timezones.py
│     │        │  │  │  ├─ sas
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_byteswap.py
│     │        │  │  │  │  ├─ test_sas.py
│     │        │  │  │  │  ├─ test_sas7bdat.py
│     │        │  │  │  │  └─ test_xport.py
│     │        │  │  │  ├─ test_clipboard.py
│     │        │  │  │  ├─ test_common.py
│     │        │  │  │  ├─ test_compression.py
│     │        │  │  │  ├─ test_feather.py
│     │        │  │  │  ├─ test_fsspec.py
│     │        │  │  │  ├─ test_gbq.py
│     │        │  │  │  ├─ test_gcs.py
│     │        │  │  │  ├─ test_html.py
│     │        │  │  │  ├─ test_http_headers.py
│     │        │  │  │  ├─ test_orc.py
│     │        │  │  │  ├─ test_parquet.py
│     │        │  │  │  ├─ test_pickle.py
│     │        │  │  │  ├─ test_s3.py
│     │        │  │  │  ├─ test_spss.py
│     │        │  │  │  ├─ test_sql.py
│     │        │  │  │  ├─ test_stata.py
│     │        │  │  │  └─ xml
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ conftest.py
│     │        │  │  │     ├─ test_to_xml.py
│     │        │  │  │     ├─ test_xml.py
│     │        │  │  │     └─ test_xml_dtypes.py
│     │        │  │  ├─ libs
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_hashtable.py
│     │        │  │  │  ├─ test_join.py
│     │        │  │  │  ├─ test_lib.py
│     │        │  │  │  └─ test_libalgos.py
│     │        │  │  ├─ plotting
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ frame
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_frame.py
│     │        │  │  │  │  ├─ test_frame_color.py
│     │        │  │  │  │  ├─ test_frame_groupby.py
│     │        │  │  │  │  ├─ test_frame_legend.py
│     │        │  │  │  │  ├─ test_frame_subplots.py
│     │        │  │  │  │  └─ test_hist_box_by.py
│     │        │  │  │  ├─ test_backend.py
│     │        │  │  │  ├─ test_boxplot_method.py
│     │        │  │  │  ├─ test_common.py
│     │        │  │  │  ├─ test_converter.py
│     │        │  │  │  ├─ test_datetimelike.py
│     │        │  │  │  ├─ test_groupby.py
│     │        │  │  │  ├─ test_hist_method.py
│     │        │  │  │  ├─ test_misc.py
│     │        │  │  │  ├─ test_series.py
│     │        │  │  │  └─ test_style.py
│     │        │  │  ├─ reductions
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_reductions.py
│     │        │  │  │  └─ test_stat_reductions.py
│     │        │  │  ├─ resample
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ test_base.py
│     │        │  │  │  ├─ test_datetime_index.py
│     │        │  │  │  ├─ test_period_index.py
│     │        │  │  │  ├─ test_resample_api.py
│     │        │  │  │  ├─ test_resampler_grouper.py
│     │        │  │  │  ├─ test_time_grouper.py
│     │        │  │  │  └─ test_timedelta.py
│     │        │  │  ├─ reshape
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ concat
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ conftest.py
│     │        │  │  │  │  ├─ test_append.py
│     │        │  │  │  │  ├─ test_append_common.py
│     │        │  │  │  │  ├─ test_categorical.py
│     │        │  │  │  │  ├─ test_concat.py
│     │        │  │  │  │  ├─ test_dataframe.py
│     │        │  │  │  │  ├─ test_datetimes.py
│     │        │  │  │  │  ├─ test_empty.py
│     │        │  │  │  │  ├─ test_index.py
│     │        │  │  │  │  ├─ test_invalid.py
│     │        │  │  │  │  ├─ test_series.py
│     │        │  │  │  │  └─ test_sort.py
│     │        │  │  │  ├─ merge
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_join.py
│     │        │  │  │  │  ├─ test_merge.py
│     │        │  │  │  │  ├─ test_merge_asof.py
│     │        │  │  │  │  ├─ test_merge_cross.py
│     │        │  │  │  │  ├─ test_merge_index_as_string.py
│     │        │  │  │  │  ├─ test_merge_ordered.py
│     │        │  │  │  │  └─ test_multi.py
│     │        │  │  │  ├─ test_crosstab.py
│     │        │  │  │  ├─ test_cut.py
│     │        │  │  │  ├─ test_from_dummies.py
│     │        │  │  │  ├─ test_get_dummies.py
│     │        │  │  │  ├─ test_melt.py
│     │        │  │  │  ├─ test_pivot.py
│     │        │  │  │  ├─ test_pivot_multilevel.py
│     │        │  │  │  ├─ test_qcut.py
│     │        │  │  │  ├─ test_union_categoricals.py
│     │        │  │  │  └─ test_util.py
│     │        │  │  ├─ scalar
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ interval
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_contains.py
│     │        │  │  │  │  ├─ test_formats.py
│     │        │  │  │  │  ├─ test_interval.py
│     │        │  │  │  │  └─ test_overlaps.py
│     │        │  │  │  ├─ period
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  │  ├─ test_asfreq.py
│     │        │  │  │  │  └─ test_period.py
│     │        │  │  │  ├─ test_na_scalar.py
│     │        │  │  │  ├─ test_nat.py
│     │        │  │  │  ├─ timedelta
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ methods
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ test_as_unit.py
│     │        │  │  │  │  │  └─ test_round.py
│     │        │  │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  │  ├─ test_constructors.py
│     │        │  │  │  │  ├─ test_formats.py
│     │        │  │  │  │  └─ test_timedelta.py
│     │        │  │  │  └─ timestamp
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ methods
│     │        │  │  │     │  ├─ __init__.py
│     │        │  │  │     │  ├─ test_as_unit.py
│     │        │  │  │     │  ├─ test_normalize.py
│     │        │  │  │     │  ├─ test_replace.py
│     │        │  │  │     │  ├─ test_round.py
│     │        │  │  │     │  ├─ test_timestamp_method.py
│     │        │  │  │     │  ├─ test_to_julian_date.py
│     │        │  │  │     │  ├─ test_to_pydatetime.py
│     │        │  │  │     │  ├─ test_tz_convert.py
│     │        │  │  │     │  └─ test_tz_localize.py
│     │        │  │  │     ├─ test_arithmetic.py
│     │        │  │  │     ├─ test_comparisons.py
│     │        │  │  │     ├─ test_constructors.py
│     │        │  │  │     ├─ test_formats.py
│     │        │  │  │     ├─ test_timestamp.py
│     │        │  │  │     └─ test_timezones.py
│     │        │  │  ├─ series
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ accessors
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_cat_accessor.py
│     │        │  │  │  │  ├─ test_dt_accessor.py
│     │        │  │  │  │  ├─ test_list_accessor.py
│     │        │  │  │  │  ├─ test_sparse_accessor.py
│     │        │  │  │  │  ├─ test_str_accessor.py
│     │        │  │  │  │  └─ test_struct_accessor.py
│     │        │  │  │  ├─ indexing
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_datetime.py
│     │        │  │  │  │  ├─ test_delitem.py
│     │        │  │  │  │  ├─ test_get.py
│     │        │  │  │  │  ├─ test_getitem.py
│     │        │  │  │  │  ├─ test_indexing.py
│     │        │  │  │  │  ├─ test_mask.py
│     │        │  │  │  │  ├─ test_set_value.py
│     │        │  │  │  │  ├─ test_setitem.py
│     │        │  │  │  │  ├─ test_take.py
│     │        │  │  │  │  ├─ test_where.py
│     │        │  │  │  │  └─ test_xs.py
│     │        │  │  │  ├─ methods
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_add_prefix_suffix.py
│     │        │  │  │  │  ├─ test_align.py
│     │        │  │  │  │  ├─ test_argsort.py
│     │        │  │  │  │  ├─ test_asof.py
│     │        │  │  │  │  ├─ test_astype.py
│     │        │  │  │  │  ├─ test_autocorr.py
│     │        │  │  │  │  ├─ test_between.py
│     │        │  │  │  │  ├─ test_case_when.py
│     │        │  │  │  │  ├─ test_clip.py
│     │        │  │  │  │  ├─ test_combine.py
│     │        │  │  │  │  ├─ test_combine_first.py
│     │        │  │  │  │  ├─ test_compare.py
│     │        │  │  │  │  ├─ test_convert_dtypes.py
│     │        │  │  │  │  ├─ test_copy.py
│     │        │  │  │  │  ├─ test_count.py
│     │        │  │  │  │  ├─ test_cov_corr.py
│     │        │  │  │  │  ├─ test_describe.py
│     │        │  │  │  │  ├─ test_diff.py
│     │        │  │  │  │  ├─ test_drop.py
│     │        │  │  │  │  ├─ test_drop_duplicates.py
│     │        │  │  │  │  ├─ test_dropna.py
│     │        │  │  │  │  ├─ test_dtypes.py
│     │        │  │  │  │  ├─ test_duplicated.py
│     │        │  │  │  │  ├─ test_equals.py
│     │        │  │  │  │  ├─ test_explode.py
│     │        │  │  │  │  ├─ test_fillna.py
│     │        │  │  │  │  ├─ test_get_numeric_data.py
│     │        │  │  │  │  ├─ test_head_tail.py
│     │        │  │  │  │  ├─ test_infer_objects.py
│     │        │  │  │  │  ├─ test_info.py
│     │        │  │  │  │  ├─ test_interpolate.py
│     │        │  │  │  │  ├─ test_is_monotonic.py
│     │        │  │  │  │  ├─ test_is_unique.py
│     │        │  │  │  │  ├─ test_isin.py
│     │        │  │  │  │  ├─ test_isna.py
│     │        │  │  │  │  ├─ test_item.py
│     │        │  │  │  │  ├─ test_map.py
│     │        │  │  │  │  ├─ test_matmul.py
│     │        │  │  │  │  ├─ test_nlargest.py
│     │        │  │  │  │  ├─ test_nunique.py
│     │        │  │  │  │  ├─ test_pct_change.py
│     │        │  │  │  │  ├─ test_pop.py
│     │        │  │  │  │  ├─ test_quantile.py
│     │        │  │  │  │  ├─ test_rank.py
│     │        │  │  │  │  ├─ test_reindex.py
│     │        │  │  │  │  ├─ test_reindex_like.py
│     │        │  │  │  │  ├─ test_rename.py
│     │        │  │  │  │  ├─ test_rename_axis.py
│     │        │  │  │  │  ├─ test_repeat.py
│     │        │  │  │  │  ├─ test_replace.py
│     │        │  │  │  │  ├─ test_reset_index.py
│     │        │  │  │  │  ├─ test_round.py
│     │        │  │  │  │  ├─ test_searchsorted.py
│     │        │  │  │  │  ├─ test_set_name.py
│     │        │  │  │  │  ├─ test_size.py
│     │        │  │  │  │  ├─ test_sort_index.py
│     │        │  │  │  │  ├─ test_sort_values.py
│     │        │  │  │  │  ├─ test_to_csv.py
│     │        │  │  │  │  ├─ test_to_dict.py
│     │        │  │  │  │  ├─ test_to_frame.py
│     │        │  │  │  │  ├─ test_to_numpy.py
│     │        │  │  │  │  ├─ test_tolist.py
│     │        │  │  │  │  ├─ test_truncate.py
│     │        │  │  │  │  ├─ test_tz_localize.py
│     │        │  │  │  │  ├─ test_unique.py
│     │        │  │  │  │  ├─ test_unstack.py
│     │        │  │  │  │  ├─ test_update.py
│     │        │  │  │  │  ├─ test_value_counts.py
│     │        │  │  │  │  ├─ test_values.py
│     │        │  │  │  │  └─ test_view.py
│     │        │  │  │  ├─ test_api.py
│     │        │  │  │  ├─ test_arithmetic.py
│     │        │  │  │  ├─ test_constructors.py
│     │        │  │  │  ├─ test_cumulative.py
│     │        │  │  │  ├─ test_formats.py
│     │        │  │  │  ├─ test_iteration.py
│     │        │  │  │  ├─ test_logical_ops.py
│     │        │  │  │  ├─ test_missing.py
│     │        │  │  │  ├─ test_npfuncs.py
│     │        │  │  │  ├─ test_reductions.py
│     │        │  │  │  ├─ test_subclass.py
│     │        │  │  │  ├─ test_ufunc.py
│     │        │  │  │  ├─ test_unary.py
│     │        │  │  │  └─ test_validate.py
│     │        │  │  ├─ strings
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ test_api.py
│     │        │  │  │  ├─ test_case_justify.py
│     │        │  │  │  ├─ test_cat.py
│     │        │  │  │  ├─ test_extract.py
│     │        │  │  │  ├─ test_find_replace.py
│     │        │  │  │  ├─ test_get_dummies.py
│     │        │  │  │  ├─ test_split_partition.py
│     │        │  │  │  ├─ test_string_array.py
│     │        │  │  │  └─ test_strings.py
│     │        │  │  ├─ test_aggregation.py
│     │        │  │  ├─ test_algos.py
│     │        │  │  ├─ test_common.py
│     │        │  │  ├─ test_downstream.py
│     │        │  │  ├─ test_errors.py
│     │        │  │  ├─ test_expressions.py
│     │        │  │  ├─ test_flags.py
│     │        │  │  ├─ test_multilevel.py
│     │        │  │  ├─ test_nanops.py
│     │        │  │  ├─ test_optional_dependency.py
│     │        │  │  ├─ test_register_accessor.py
│     │        │  │  ├─ test_sorting.py
│     │        │  │  ├─ test_take.py
│     │        │  │  ├─ tools
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_to_datetime.py
│     │        │  │  │  ├─ test_to_numeric.py
│     │        │  │  │  ├─ test_to_time.py
│     │        │  │  │  └─ test_to_timedelta.py
│     │        │  │  ├─ tseries
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ frequencies
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_freq_code.py
│     │        │  │  │  │  ├─ test_frequencies.py
│     │        │  │  │  │  └─ test_inference.py
│     │        │  │  │  ├─ holiday
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_calendar.py
│     │        │  │  │  │  ├─ test_federal.py
│     │        │  │  │  │  ├─ test_holiday.py
│     │        │  │  │  │  └─ test_observance.py
│     │        │  │  │  └─ offsets
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ common.py
│     │        │  │  │     ├─ test_business_day.py
│     │        │  │  │     ├─ test_business_hour.py
│     │        │  │  │     ├─ test_business_month.py
│     │        │  │  │     ├─ test_business_quarter.py
│     │        │  │  │     ├─ test_business_year.py
│     │        │  │  │     ├─ test_common.py
│     │        │  │  │     ├─ test_custom_business_day.py
│     │        │  │  │     ├─ test_custom_business_hour.py
│     │        │  │  │     ├─ test_custom_business_month.py
│     │        │  │  │     ├─ test_dst.py
│     │        │  │  │     ├─ test_easter.py
│     │        │  │  │     ├─ test_fiscal.py
│     │        │  │  │     ├─ test_index.py
│     │        │  │  │     ├─ test_month.py
│     │        │  │  │     ├─ test_offsets.py
│     │        │  │  │     ├─ test_offsets_properties.py
│     │        │  │  │     ├─ test_quarter.py
│     │        │  │  │     ├─ test_ticks.py
│     │        │  │  │     ├─ test_week.py
│     │        │  │  │     └─ test_year.py
│     │        │  │  ├─ tslibs
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_api.py
│     │        │  │  │  ├─ test_array_to_datetime.py
│     │        │  │  │  ├─ test_ccalendar.py
│     │        │  │  │  ├─ test_conversion.py
│     │        │  │  │  ├─ test_fields.py
│     │        │  │  │  ├─ test_libfrequencies.py
│     │        │  │  │  ├─ test_liboffsets.py
│     │        │  │  │  ├─ test_np_datetime.py
│     │        │  │  │  ├─ test_npy_units.py
│     │        │  │  │  ├─ test_parse_iso8601.py
│     │        │  │  │  ├─ test_parsing.py
│     │        │  │  │  ├─ test_period.py
│     │        │  │  │  ├─ test_resolution.py
│     │        │  │  │  ├─ test_strptime.py
│     │        │  │  │  ├─ test_timedeltas.py
│     │        │  │  │  ├─ test_timezones.py
│     │        │  │  │  ├─ test_to_offset.py
│     │        │  │  │  └─ test_tzconversion.py
│     │        │  │  ├─ util
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ conftest.py
│     │        │  │  │  ├─ test_assert_almost_equal.py
│     │        │  │  │  ├─ test_assert_attr_equal.py
│     │        │  │  │  ├─ test_assert_categorical_equal.py
│     │        │  │  │  ├─ test_assert_extension_array_equal.py
│     │        │  │  │  ├─ test_assert_frame_equal.py
│     │        │  │  │  ├─ test_assert_index_equal.py
│     │        │  │  │  ├─ test_assert_interval_array_equal.py
│     │        │  │  │  ├─ test_assert_numpy_array_equal.py
│     │        │  │  │  ├─ test_assert_produces_warning.py
│     │        │  │  │  ├─ test_assert_series_equal.py
│     │        │  │  │  ├─ test_deprecate.py
│     │        │  │  │  ├─ test_deprecate_kwarg.py
│     │        │  │  │  ├─ test_deprecate_nonkeyword_arguments.py
│     │        │  │  │  ├─ test_doc.py
│     │        │  │  │  ├─ test_hashing.py
│     │        │  │  │  ├─ test_numba.py
│     │        │  │  │  ├─ test_rewrite_warning.py
│     │        │  │  │  ├─ test_shares_memory.py
│     │        │  │  │  ├─ test_show_versions.py
│     │        │  │  │  ├─ test_util.py
│     │        │  │  │  ├─ test_validate_args.py
│     │        │  │  │  ├─ test_validate_args_and_kwargs.py
│     │        │  │  │  ├─ test_validate_inclusive.py
│     │        │  │  │  └─ test_validate_kwargs.py
│     │        │  │  └─ window
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ conftest.py
│     │        │  │     ├─ moments
│     │        │  │     │  ├─ __init__.py
│     │        │  │     │  ├─ conftest.py
│     │        │  │     │  ├─ test_moments_consistency_ewm.py
│     │        │  │     │  ├─ test_moments_consistency_expanding.py
│     │        │  │     │  └─ test_moments_consistency_rolling.py
│     │        │  │     ├─ test_api.py
│     │        │  │     ├─ test_apply.py
│     │        │  │     ├─ test_base_indexer.py
│     │        │  │     ├─ test_cython_aggregations.py
│     │        │  │     ├─ test_dtypes.py
│     │        │  │     ├─ test_ewm.py
│     │        │  │     ├─ test_expanding.py
│     │        │  │     ├─ test_groupby.py
│     │        │  │     ├─ test_numba.py
│     │        │  │     ├─ test_online.py
│     │        │  │     ├─ test_pairwise.py
│     │        │  │     ├─ test_rolling.py
│     │        │  │     ├─ test_rolling_functions.py
│     │        │  │     ├─ test_rolling_quantile.py
│     │        │  │     ├─ test_rolling_skew_kurt.py
│     │        │  │     ├─ test_timeseries_window.py
│     │        │  │     └─ test_win_type.py
│     │        │  ├─ tseries
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ api.py
│     │        │  │  ├─ frequencies.py
│     │        │  │  ├─ holiday.py
│     │        │  │  └─ offsets.py
│     │        │  └─ util
│     │        │     ├─ __init__.py
│     │        │     ├─ _decorators.py
│     │        │     ├─ _doctools.py
│     │        │     ├─ _exceptions.py
│     │        │     ├─ _print_versions.py
│     │        │     ├─ _test_decorators.py
│     │        │     ├─ _tester.py
│     │        │     ├─ _validators.py
│     │        │     └─ version
│     │        │        └─ __init__.py
│     │        ├─ pandas-2.3.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  └─ entry_points.txt
│     │        ├─ passlib
│     │        │  ├─ __init__.py
│     │        │  ├─ apache.py
│     │        │  ├─ apps.py
│     │        │  ├─ context.py
│     │        │  ├─ crypto
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _blowfish
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _gen_files.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  └─ unrolled.py
│     │        │  │  ├─ _md4.py
│     │        │  │  ├─ des.py
│     │        │  │  ├─ digest.py
│     │        │  │  └─ scrypt
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ _builtin.py
│     │        │  │     ├─ _gen_files.py
│     │        │  │     └─ _salsa.py
│     │        │  ├─ exc.py
│     │        │  ├─ ext
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ django
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ models.py
│     │        │  │     └─ utils.py
│     │        │  ├─ handlers
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ argon2.py
│     │        │  │  ├─ bcrypt.py
│     │        │  │  ├─ cisco.py
│     │        │  │  ├─ des_crypt.py
│     │        │  │  ├─ digests.py
│     │        │  │  ├─ django.py
│     │        │  │  ├─ fshp.py
│     │        │  │  ├─ ldap_digests.py
│     │        │  │  ├─ md5_crypt.py
│     │        │  │  ├─ misc.py
│     │        │  │  ├─ mssql.py
│     │        │  │  ├─ mysql.py
│     │        │  │  ├─ oracle.py
│     │        │  │  ├─ pbkdf2.py
│     │        │  │  ├─ phpass.py
│     │        │  │  ├─ postgres.py
│     │        │  │  ├─ roundup.py
│     │        │  │  ├─ scram.py
│     │        │  │  ├─ scrypt.py
│     │        │  │  ├─ sha1_crypt.py
│     │        │  │  ├─ sha2_crypt.py
│     │        │  │  ├─ sun_md5_crypt.py
│     │        │  │  └─ windows.py
│     │        │  ├─ hash.py
│     │        │  ├─ hosts.py
│     │        │  ├─ ifc.py
│     │        │  ├─ pwd.py
│     │        │  ├─ registry.py
│     │        │  ├─ tests
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __main__.py
│     │        │  │  ├─ _test_bad_register.py
│     │        │  │  ├─ backports.py
│     │        │  │  ├─ sample1.cfg
│     │        │  │  ├─ sample1b.cfg
│     │        │  │  ├─ sample1c.cfg
│     │        │  │  ├─ sample_config_1s.cfg
│     │        │  │  ├─ test_apache.py
│     │        │  │  ├─ test_apps.py
│     │        │  │  ├─ test_context.py
│     │        │  │  ├─ test_context_deprecated.py
│     │        │  │  ├─ test_crypto_builtin_md4.py
│     │        │  │  ├─ test_crypto_des.py
│     │        │  │  ├─ test_crypto_digest.py
│     │        │  │  ├─ test_crypto_scrypt.py
│     │        │  │  ├─ test_ext_django.py
│     │        │  │  ├─ test_ext_django_source.py
│     │        │  │  ├─ test_handlers.py
│     │        │  │  ├─ test_handlers_argon2.py
│     │        │  │  ├─ test_handlers_bcrypt.py
│     │        │  │  ├─ test_handlers_cisco.py
│     │        │  │  ├─ test_handlers_django.py
│     │        │  │  ├─ test_handlers_pbkdf2.py
│     │        │  │  ├─ test_handlers_scrypt.py
│     │        │  │  ├─ test_hosts.py
│     │        │  │  ├─ test_pwd.py
│     │        │  │  ├─ test_registry.py
│     │        │  │  ├─ test_totp.py
│     │        │  │  ├─ test_utils.py
│     │        │  │  ├─ test_utils_handlers.py
│     │        │  │  ├─ test_utils_md4.py
│     │        │  │  ├─ test_utils_pbkdf2.py
│     │        │  │  ├─ test_win32.py
│     │        │  │  ├─ tox_support.py
│     │        │  │  └─ utils.py
│     │        │  ├─ totp.py
│     │        │  ├─ utils
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ binary.py
│     │        │  │  ├─ compat
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ _ordered_dict.py
│     │        │  │  ├─ decor.py
│     │        │  │  ├─ des.py
│     │        │  │  ├─ handlers.py
│     │        │  │  ├─ md4.py
│     │        │  │  └─ pbkdf2.py
│     │        │  └─ win32.py
│     │        ├─ passlib-1.7.4.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ top_level.txt
│     │        │  └─ zip-safe
│     │        ├─ pip
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ __pip-runner__.py
│     │        │  ├─ _internal
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ build_env.py
│     │        │  │  ├─ cache.py
│     │        │  │  ├─ cli
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ autocompletion.py
│     │        │  │  │  ├─ base_command.py
│     │        │  │  │  ├─ cmdoptions.py
│     │        │  │  │  ├─ command_context.py
│     │        │  │  │  ├─ index_command.py
│     │        │  │  │  ├─ main.py
│     │        │  │  │  ├─ main_parser.py
│     │        │  │  │  ├─ parser.py
│     │        │  │  │  ├─ progress_bars.py
│     │        │  │  │  ├─ req_command.py
│     │        │  │  │  ├─ spinners.py
│     │        │  │  │  └─ status_codes.py
│     │        │  │  ├─ commands
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ cache.py
│     │        │  │  │  ├─ check.py
│     │        │  │  │  ├─ completion.py
│     │        │  │  │  ├─ configuration.py
│     │        │  │  │  ├─ debug.py
│     │        │  │  │  ├─ download.py
│     │        │  │  │  ├─ freeze.py
│     │        │  │  │  ├─ hash.py
│     │        │  │  │  ├─ help.py
│     │        │  │  │  ├─ index.py
│     │        │  │  │  ├─ inspect.py
│     │        │  │  │  ├─ install.py
│     │        │  │  │  ├─ list.py
│     │        │  │  │  ├─ lock.py
│     │        │  │  │  ├─ search.py
│     │        │  │  │  ├─ show.py
│     │        │  │  │  ├─ uninstall.py
│     │        │  │  │  └─ wheel.py
│     │        │  │  ├─ configuration.py
│     │        │  │  ├─ distributions
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ installed.py
│     │        │  │  │  ├─ sdist.py
│     │        │  │  │  └─ wheel.py
│     │        │  │  ├─ exceptions.py
│     │        │  │  ├─ index
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ collector.py
│     │        │  │  │  ├─ package_finder.py
│     │        │  │  │  └─ sources.py
│     │        │  │  ├─ locations
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _distutils.py
│     │        │  │  │  ├─ _sysconfig.py
│     │        │  │  │  └─ base.py
│     │        │  │  ├─ main.py
│     │        │  │  ├─ models
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ candidate.py
│     │        │  │  │  ├─ direct_url.py
│     │        │  │  │  ├─ format_control.py
│     │        │  │  │  ├─ index.py
│     │        │  │  │  ├─ installation_report.py
│     │        │  │  │  ├─ link.py
│     │        │  │  │  ├─ pylock.py
│     │        │  │  │  ├─ scheme.py
│     │        │  │  │  ├─ search_scope.py
│     │        │  │  │  ├─ selection_prefs.py
│     │        │  │  │  ├─ target_python.py
│     │        │  │  │  └─ wheel.py
│     │        │  │  ├─ network
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ auth.py
│     │        │  │  │  ├─ cache.py
│     │        │  │  │  ├─ download.py
│     │        │  │  │  ├─ lazy_wheel.py
│     │        │  │  │  ├─ session.py
│     │        │  │  │  ├─ utils.py
│     │        │  │  │  └─ xmlrpc.py
│     │        │  │  ├─ operations
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ build
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ build_tracker.py
│     │        │  │  │  │  ├─ metadata.py
│     │        │  │  │  │  ├─ metadata_editable.py
│     │        │  │  │  │  ├─ metadata_legacy.py
│     │        │  │  │  │  ├─ wheel.py
│     │        │  │  │  │  ├─ wheel_editable.py
│     │        │  │  │  │  └─ wheel_legacy.py
│     │        │  │  │  ├─ check.py
│     │        │  │  │  ├─ freeze.py
│     │        │  │  │  ├─ install
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ editable_legacy.py
│     │        │  │  │  │  └─ wheel.py
│     │        │  │  │  └─ prepare.py
│     │        │  │  ├─ pyproject.py
│     │        │  │  ├─ req
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ constructors.py
│     │        │  │  │  ├─ req_dependency_group.py
│     │        │  │  │  ├─ req_file.py
│     │        │  │  │  ├─ req_install.py
│     │        │  │  │  ├─ req_set.py
│     │        │  │  │  └─ req_uninstall.py
│     │        │  │  ├─ resolution
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ legacy
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ resolver.py
│     │        │  │  │  └─ resolvelib
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ base.py
│     │        │  │  │     ├─ candidates.py
│     │        │  │  │     ├─ factory.py
│     │        │  │  │     ├─ found_candidates.py
│     │        │  │  │     ├─ provider.py
│     │        │  │  │     ├─ reporter.py
│     │        │  │  │     ├─ requirements.py
│     │        │  │  │     └─ resolver.py
│     │        │  │  ├─ self_outdated_check.py
│     │        │  │  ├─ utils
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _jaraco_text.py
│     │        │  │  │  ├─ _log.py
│     │        │  │  │  ├─ appdirs.py
│     │        │  │  │  ├─ compat.py
│     │        │  │  │  ├─ compatibility_tags.py
│     │        │  │  │  ├─ datetime.py
│     │        │  │  │  ├─ deprecation.py
│     │        │  │  │  ├─ direct_url_helpers.py
│     │        │  │  │  ├─ egg_link.py
│     │        │  │  │  ├─ entrypoints.py
│     │        │  │  │  ├─ filesystem.py
│     │        │  │  │  ├─ filetypes.py
│     │        │  │  │  ├─ glibc.py
│     │        │  │  │  ├─ hashes.py
│     │        │  │  │  ├─ logging.py
│     │        │  │  │  ├─ misc.py
│     │        │  │  │  ├─ packaging.py
│     │        │  │  │  ├─ retry.py
│     │        │  │  │  ├─ setuptools_build.py
│     │        │  │  │  ├─ subprocess.py
│     │        │  │  │  ├─ temp_dir.py
│     │        │  │  │  ├─ unpacking.py
│     │        │  │  │  ├─ urls.py
│     │        │  │  │  ├─ virtualenv.py
│     │        │  │  │  └─ wheel.py
│     │        │  │  ├─ vcs
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ bazaar.py
│     │        │  │  │  ├─ git.py
│     │        │  │  │  ├─ mercurial.py
│     │        │  │  │  ├─ subversion.py
│     │        │  │  │  └─ versioncontrol.py
│     │        │  │  └─ wheel_builder.py
│     │        │  ├─ _vendor
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ cachecontrol
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _cmd.py
│     │        │  │  │  ├─ adapter.py
│     │        │  │  │  ├─ cache.py
│     │        │  │  │  ├─ caches
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ file_cache.py
│     │        │  │  │  │  └─ redis_cache.py
│     │        │  │  │  ├─ controller.py
│     │        │  │  │  ├─ filewrapper.py
│     │        │  │  │  ├─ heuristics.py
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  ├─ serialize.py
│     │        │  │  │  └─ wrapper.py
│     │        │  │  ├─ certifi
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __main__.py
│     │        │  │  │  ├─ cacert.pem
│     │        │  │  │  ├─ core.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ dependency_groups
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __main__.py
│     │        │  │  │  ├─ _implementation.py
│     │        │  │  │  ├─ _lint_dependency_groups.py
│     │        │  │  │  ├─ _pip_wrapper.py
│     │        │  │  │  ├─ _toml_compat.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ distlib
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ compat.py
│     │        │  │  │  ├─ resources.py
│     │        │  │  │  ├─ scripts.py
│     │        │  │  │  ├─ t32.exe
│     │        │  │  │  ├─ t64-arm.exe
│     │        │  │  │  ├─ t64.exe
│     │        │  │  │  ├─ util.py
│     │        │  │  │  ├─ w32.exe
│     │        │  │  │  ├─ w64-arm.exe
│     │        │  │  │  └─ w64.exe
│     │        │  │  ├─ distro
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __main__.py
│     │        │  │  │  ├─ distro.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ idna
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ codec.py
│     │        │  │  │  ├─ compat.py
│     │        │  │  │  ├─ core.py
│     │        │  │  │  ├─ idnadata.py
│     │        │  │  │  ├─ intranges.py
│     │        │  │  │  ├─ package_data.py
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  └─ uts46data.py
│     │        │  │  ├─ msgpack
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ exceptions.py
│     │        │  │  │  ├─ ext.py
│     │        │  │  │  └─ fallback.py
│     │        │  │  ├─ packaging
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _elffile.py
│     │        │  │  │  ├─ _manylinux.py
│     │        │  │  │  ├─ _musllinux.py
│     │        │  │  │  ├─ _parser.py
│     │        │  │  │  ├─ _structures.py
│     │        │  │  │  ├─ _tokenizer.py
│     │        │  │  │  ├─ licenses
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ _spdx.py
│     │        │  │  │  ├─ markers.py
│     │        │  │  │  ├─ metadata.py
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  ├─ requirements.py
│     │        │  │  │  ├─ specifiers.py
│     │        │  │  │  ├─ tags.py
│     │        │  │  │  ├─ utils.py
│     │        │  │  │  └─ version.py
│     │        │  │  ├─ pkg_resources
│     │        │  │  │  └─ __init__.py
│     │        │  │  ├─ platformdirs
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __main__.py
│     │        │  │  │  ├─ android.py
│     │        │  │  │  ├─ api.py
│     │        │  │  │  ├─ macos.py
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  ├─ unix.py
│     │        │  │  │  ├─ version.py
│     │        │  │  │  └─ windows.py
│     │        │  │  ├─ pygments
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __main__.py
│     │        │  │  │  ├─ console.py
│     │        │  │  │  ├─ filter.py
│     │        │  │  │  ├─ filters
│     │        │  │  │  │  └─ __init__.py
│     │        │  │  │  ├─ formatter.py
│     │        │  │  │  ├─ formatters
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ _mapping.py
│     │        │  │  │  ├─ lexer.py
│     │        │  │  │  ├─ lexers
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _mapping.py
│     │        │  │  │  │  └─ python.py
│     │        │  │  │  ├─ modeline.py
│     │        │  │  │  ├─ plugin.py
│     │        │  │  │  ├─ regexopt.py
│     │        │  │  │  ├─ scanner.py
│     │        │  │  │  ├─ sphinxext.py
│     │        │  │  │  ├─ style.py
│     │        │  │  │  ├─ styles
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ _mapping.py
│     │        │  │  │  ├─ token.py
│     │        │  │  │  ├─ unistring.py
│     │        │  │  │  └─ util.py
│     │        │  │  ├─ pyproject_hooks
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _impl.py
│     │        │  │  │  ├─ _in_process
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ _in_process.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ requests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __version__.py
│     │        │  │  │  ├─ _internal_utils.py
│     │        │  │  │  ├─ adapters.py
│     │        │  │  │  ├─ api.py
│     │        │  │  │  ├─ auth.py
│     │        │  │  │  ├─ certs.py
│     │        │  │  │  ├─ compat.py
│     │        │  │  │  ├─ cookies.py
│     │        │  │  │  ├─ exceptions.py
│     │        │  │  │  ├─ help.py
│     │        │  │  │  ├─ hooks.py
│     │        │  │  │  ├─ models.py
│     │        │  │  │  ├─ packages.py
│     │        │  │  │  ├─ sessions.py
│     │        │  │  │  ├─ status_codes.py
│     │        │  │  │  ├─ structures.py
│     │        │  │  │  └─ utils.py
│     │        │  │  ├─ resolvelib
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ providers.py
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  ├─ reporters.py
│     │        │  │  │  ├─ resolvers
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ abstract.py
│     │        │  │  │  │  ├─ criterion.py
│     │        │  │  │  │  ├─ exceptions.py
│     │        │  │  │  │  └─ resolution.py
│     │        │  │  │  └─ structs.py
│     │        │  │  ├─ rich
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __main__.py
│     │        │  │  │  ├─ _cell_widths.py
│     │        │  │  │  ├─ _emoji_codes.py
│     │        │  │  │  ├─ _emoji_replace.py
│     │        │  │  │  ├─ _export_format.py
│     │        │  │  │  ├─ _extension.py
│     │        │  │  │  ├─ _fileno.py
│     │        │  │  │  ├─ _inspect.py
│     │        │  │  │  ├─ _log_render.py
│     │        │  │  │  ├─ _loop.py
│     │        │  │  │  ├─ _null_file.py
│     │        │  │  │  ├─ _palettes.py
│     │        │  │  │  ├─ _pick.py
│     │        │  │  │  ├─ _ratio.py
│     │        │  │  │  ├─ _spinners.py
│     │        │  │  │  ├─ _stack.py
│     │        │  │  │  ├─ _timer.py
│     │        │  │  │  ├─ _win32_console.py
│     │        │  │  │  ├─ _windows.py
│     │        │  │  │  ├─ _windows_renderer.py
│     │        │  │  │  ├─ _wrap.py
│     │        │  │  │  ├─ abc.py
│     │        │  │  │  ├─ align.py
│     │        │  │  │  ├─ ansi.py
│     │        │  │  │  ├─ bar.py
│     │        │  │  │  ├─ box.py
│     │        │  │  │  ├─ cells.py
│     │        │  │  │  ├─ color.py
│     │        │  │  │  ├─ color_triplet.py
│     │        │  │  │  ├─ columns.py
│     │        │  │  │  ├─ console.py
│     │        │  │  │  ├─ constrain.py
│     │        │  │  │  ├─ containers.py
│     │        │  │  │  ├─ control.py
│     │        │  │  │  ├─ default_styles.py
│     │        │  │  │  ├─ diagnose.py
│     │        │  │  │  ├─ emoji.py
│     │        │  │  │  ├─ errors.py
│     │        │  │  │  ├─ file_proxy.py
│     │        │  │  │  ├─ filesize.py
│     │        │  │  │  ├─ highlighter.py
│     │        │  │  │  ├─ json.py
│     │        │  │  │  ├─ jupyter.py
│     │        │  │  │  ├─ layout.py
│     │        │  │  │  ├─ live.py
│     │        │  │  │  ├─ live_render.py
│     │        │  │  │  ├─ logging.py
│     │        │  │  │  ├─ markup.py
│     │        │  │  │  ├─ measure.py
│     │        │  │  │  ├─ padding.py
│     │        │  │  │  ├─ pager.py
│     │        │  │  │  ├─ palette.py
│     │        │  │  │  ├─ panel.py
│     │        │  │  │  ├─ pretty.py
│     │        │  │  │  ├─ progress.py
│     │        │  │  │  ├─ progress_bar.py
│     │        │  │  │  ├─ prompt.py
│     │        │  │  │  ├─ protocol.py
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  ├─ region.py
│     │        │  │  │  ├─ repr.py
│     │        │  │  │  ├─ rule.py
│     │        │  │  │  ├─ scope.py
│     │        │  │  │  ├─ screen.py
│     │        │  │  │  ├─ segment.py
│     │        │  │  │  ├─ spinner.py
│     │        │  │  │  ├─ status.py
│     │        │  │  │  ├─ style.py
│     │        │  │  │  ├─ styled.py
│     │        │  │  │  ├─ syntax.py
│     │        │  │  │  ├─ table.py
│     │        │  │  │  ├─ terminal_theme.py
│     │        │  │  │  ├─ text.py
│     │        │  │  │  ├─ theme.py
│     │        │  │  │  ├─ themes.py
│     │        │  │  │  ├─ traceback.py
│     │        │  │  │  └─ tree.py
│     │        │  │  ├─ tomli
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _parser.py
│     │        │  │  │  ├─ _re.py
│     │        │  │  │  ├─ _types.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ tomli_w
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _writer.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ truststore
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _api.py
│     │        │  │  │  ├─ _macos.py
│     │        │  │  │  ├─ _openssl.py
│     │        │  │  │  ├─ _ssl_constants.py
│     │        │  │  │  ├─ _windows.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ urllib3
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _collections.py
│     │        │  │  │  ├─ _version.py
│     │        │  │  │  ├─ connection.py
│     │        │  │  │  ├─ connectionpool.py
│     │        │  │  │  ├─ contrib
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _appengine_environ.py
│     │        │  │  │  │  ├─ _securetransport
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ bindings.py
│     │        │  │  │  │  │  └─ low_level.py
│     │        │  │  │  │  ├─ appengine.py
│     │        │  │  │  │  ├─ ntlmpool.py
│     │        │  │  │  │  ├─ pyopenssl.py
│     │        │  │  │  │  ├─ securetransport.py
│     │        │  │  │  │  └─ socks.py
│     │        │  │  │  ├─ exceptions.py
│     │        │  │  │  ├─ fields.py
│     │        │  │  │  ├─ filepost.py
│     │        │  │  │  ├─ packages
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ backports
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ makefile.py
│     │        │  │  │  │  │  └─ weakref_finalize.py
│     │        │  │  │  │  └─ six.py
│     │        │  │  │  ├─ poolmanager.py
│     │        │  │  │  ├─ request.py
│     │        │  │  │  ├─ response.py
│     │        │  │  │  └─ util
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ connection.py
│     │        │  │  │     ├─ proxy.py
│     │        │  │  │     ├─ queue.py
│     │        │  │  │     ├─ request.py
│     │        │  │  │     ├─ response.py
│     │        │  │  │     ├─ retry.py
│     │        │  │  │     ├─ ssl_.py
│     │        │  │  │     ├─ ssl_match_hostname.py
│     │        │  │  │     ├─ ssltransport.py
│     │        │  │  │     ├─ timeout.py
│     │        │  │  │     ├─ url.py
│     │        │  │  │     └─ wait.py
│     │        │  │  └─ vendor.txt
│     │        │  └─ py.typed
│     │        ├─ pip-25.2.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  ├─ licenses
│     │        │  │  ├─ AUTHORS.txt
│     │        │  │  ├─ LICENSE.txt
│     │        │  │  └─ src
│     │        │  │     └─ pip
│     │        │  │        └─ _vendor
│     │        │  │           ├─ cachecontrol
│     │        │  │           │  └─ LICENSE.txt
│     │        │  │           ├─ certifi
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ dependency_groups
│     │        │  │           │  └─ LICENSE.txt
│     │        │  │           ├─ distlib
│     │        │  │           │  └─ LICENSE.txt
│     │        │  │           ├─ distro
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ idna
│     │        │  │           │  └─ LICENSE.md
│     │        │  │           ├─ msgpack
│     │        │  │           │  └─ COPYING
│     │        │  │           ├─ packaging
│     │        │  │           │  ├─ LICENSE
│     │        │  │           │  ├─ LICENSE.APACHE
│     │        │  │           │  └─ LICENSE.BSD
│     │        │  │           ├─ pkg_resources
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ platformdirs
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ pygments
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ pyproject_hooks
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ requests
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ resolvelib
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ rich
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ tomli
│     │        │  │           │  ├─ LICENSE
│     │        │  │           │  └─ LICENSE-HEADER
│     │        │  │           ├─ tomli_w
│     │        │  │           │  └─ LICENSE
│     │        │  │           ├─ truststore
│     │        │  │           │  └─ LICENSE
│     │        │  │           └─ urllib3
│     │        │  │              └─ LICENSE.txt
│     │        │  └─ top_level.txt
│     │        ├─ pkg_resources
│     │        │  ├─ __init__.py
│     │        │  ├─ api_tests.txt
│     │        │  ├─ py.typed
│     │        │  └─ tests
│     │        │     ├─ __init__.py
│     │        │     ├─ test_find_distributions.py
│     │        │     ├─ test_integration_zope_interface.py
│     │        │     ├─ test_markers.py
│     │        │     ├─ test_pkg_resources.py
│     │        │     ├─ test_resources.py
│     │        │     └─ test_working_set.py
│     │        ├─ playwright
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ _impl
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __pyinstaller
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ hook-playwright.async_api.py
│     │        │  │  │  └─ hook-playwright.sync_api.py
│     │        │  │  ├─ _accessibility.py
│     │        │  │  ├─ _api_structures.py
│     │        │  │  ├─ _artifact.py
│     │        │  │  ├─ _assertions.py
│     │        │  │  ├─ _async_base.py
│     │        │  │  ├─ _browser.py
│     │        │  │  ├─ _browser_context.py
│     │        │  │  ├─ _browser_type.py
│     │        │  │  ├─ _cdp_session.py
│     │        │  │  ├─ _clock.py
│     │        │  │  ├─ _connection.py
│     │        │  │  ├─ _console_message.py
│     │        │  │  ├─ _dialog.py
│     │        │  │  ├─ _download.py
│     │        │  │  ├─ _driver.py
│     │        │  │  ├─ _element_handle.py
│     │        │  │  ├─ _errors.py
│     │        │  │  ├─ _event_context_manager.py
│     │        │  │  ├─ _fetch.py
│     │        │  │  ├─ _file_chooser.py
│     │        │  │  ├─ _frame.py
│     │        │  │  ├─ _glob.py
│     │        │  │  ├─ _greenlets.py
│     │        │  │  ├─ _har_router.py
│     │        │  │  ├─ _helper.py
│     │        │  │  ├─ _impl_to_api_mapping.py
│     │        │  │  ├─ _input.py
│     │        │  │  ├─ _js_handle.py
│     │        │  │  ├─ _json_pipe.py
│     │        │  │  ├─ _local_utils.py
│     │        │  │  ├─ _locator.py
│     │        │  │  ├─ _map.py
│     │        │  │  ├─ _network.py
│     │        │  │  ├─ _object_factory.py
│     │        │  │  ├─ _page.py
│     │        │  │  ├─ _path_utils.py
│     │        │  │  ├─ _playwright.py
│     │        │  │  ├─ _selectors.py
│     │        │  │  ├─ _set_input_files_helpers.py
│     │        │  │  ├─ _str_utils.py
│     │        │  │  ├─ _stream.py
│     │        │  │  ├─ _sync_base.py
│     │        │  │  ├─ _tracing.py
│     │        │  │  ├─ _transport.py
│     │        │  │  ├─ _video.py
│     │        │  │  ├─ _waiter.py
│     │        │  │  ├─ _web_error.py
│     │        │  │  └─ _writable_stream.py
│     │        │  ├─ _repo_version.py
│     │        │  ├─ async_api
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _context_manager.py
│     │        │  │  └─ _generated.py
│     │        │  ├─ driver
│     │        │  │  ├─ LICENSE
│     │        │  │  ├─ README.md
│     │        │  │  ├─ node
│     │        │  │  └─ package
│     │        │  │     ├─ README.md
│     │        │  │     ├─ ThirdPartyNotices.txt
│     │        │  │     ├─ api.json
│     │        │  │     ├─ bin
│     │        │  │     │  ├─ install_media_pack.ps1
│     │        │  │     │  ├─ reinstall_chrome_beta_linux.sh
│     │        │  │     │  ├─ reinstall_chrome_beta_mac.sh
│     │        │  │     │  ├─ reinstall_chrome_beta_win.ps1
│     │        │  │     │  ├─ reinstall_chrome_stable_linux.sh
│     │        │  │     │  ├─ reinstall_chrome_stable_mac.sh
│     │        │  │     │  ├─ reinstall_chrome_stable_win.ps1
│     │        │  │     │  ├─ reinstall_msedge_beta_linux.sh
│     │        │  │     │  ├─ reinstall_msedge_beta_mac.sh
│     │        │  │     │  ├─ reinstall_msedge_beta_win.ps1
│     │        │  │     │  ├─ reinstall_msedge_dev_linux.sh
│     │        │  │     │  ├─ reinstall_msedge_dev_mac.sh
│     │        │  │     │  ├─ reinstall_msedge_dev_win.ps1
│     │        │  │     │  ├─ reinstall_msedge_stable_linux.sh
│     │        │  │     │  ├─ reinstall_msedge_stable_mac.sh
│     │        │  │     │  └─ reinstall_msedge_stable_win.ps1
│     │        │  │     ├─ browsers.json
│     │        │  │     ├─ cli.js
│     │        │  │     ├─ index.d.ts
│     │        │  │     ├─ index.js
│     │        │  │     ├─ index.mjs
│     │        │  │     ├─ lib
│     │        │  │     │  ├─ androidServerImpl.js
│     │        │  │     │  ├─ browserServerImpl.js
│     │        │  │     │  ├─ cli
│     │        │  │     │  │  ├─ driver.js
│     │        │  │     │  │  ├─ program.js
│     │        │  │     │  │  └─ programWithTestStub.js
│     │        │  │     │  ├─ client
│     │        │  │     │  │  ├─ accessibility.js
│     │        │  │     │  │  ├─ android.js
│     │        │  │     │  │  ├─ api.js
│     │        │  │     │  │  ├─ artifact.js
│     │        │  │     │  │  ├─ browser.js
│     │        │  │     │  │  ├─ browserContext.js
│     │        │  │     │  │  ├─ browserType.js
│     │        │  │     │  │  ├─ cdpSession.js
│     │        │  │     │  │  ├─ channelOwner.js
│     │        │  │     │  │  ├─ clientHelper.js
│     │        │  │     │  │  ├─ clientInstrumentation.js
│     │        │  │     │  │  ├─ clientStackTrace.js
│     │        │  │     │  │  ├─ clock.js
│     │        │  │     │  │  ├─ connection.js
│     │        │  │     │  │  ├─ consoleMessage.js
│     │        │  │     │  │  ├─ coverage.js
│     │        │  │     │  │  ├─ dialog.js
│     │        │  │     │  │  ├─ download.js
│     │        │  │     │  │  ├─ electron.js
│     │        │  │     │  │  ├─ elementHandle.js
│     │        │  │     │  │  ├─ errors.js
│     │        │  │     │  │  ├─ eventEmitter.js
│     │        │  │     │  │  ├─ events.js
│     │        │  │     │  │  ├─ fetch.js
│     │        │  │     │  │  ├─ fileChooser.js
│     │        │  │     │  │  ├─ fileUtils.js
│     │        │  │     │  │  ├─ frame.js
│     │        │  │     │  │  ├─ harRouter.js
│     │        │  │     │  │  ├─ input.js
│     │        │  │     │  │  ├─ jsHandle.js
│     │        │  │     │  │  ├─ jsonPipe.js
│     │        │  │     │  │  ├─ localUtils.js
│     │        │  │     │  │  ├─ locator.js
│     │        │  │     │  │  ├─ network.js
│     │        │  │     │  │  ├─ page.js
│     │        │  │     │  │  ├─ platform.js
│     │        │  │     │  │  ├─ playwright.js
│     │        │  │     │  │  ├─ selectors.js
│     │        │  │     │  │  ├─ stream.js
│     │        │  │     │  │  ├─ timeoutSettings.js
│     │        │  │     │  │  ├─ tracing.js
│     │        │  │     │  │  ├─ types.js
│     │        │  │     │  │  ├─ video.js
│     │        │  │     │  │  ├─ waiter.js
│     │        │  │     │  │  ├─ webError.js
│     │        │  │     │  │  ├─ webSocket.js
│     │        │  │     │  │  ├─ worker.js
│     │        │  │     │  │  └─ writableStream.js
│     │        │  │     │  ├─ generated
│     │        │  │     │  │  ├─ bindingsControllerSource.js
│     │        │  │     │  │  ├─ clockSource.js
│     │        │  │     │  │  ├─ injectedScriptSource.js
│     │        │  │     │  │  ├─ pollingRecorderSource.js
│     │        │  │     │  │  ├─ storageScriptSource.js
│     │        │  │     │  │  ├─ utilityScriptSource.js
│     │        │  │     │  │  └─ webSocketMockSource.js
│     │        │  │     │  ├─ inProcessFactory.js
│     │        │  │     │  ├─ inprocess.js
│     │        │  │     │  ├─ outofprocess.js
│     │        │  │     │  ├─ protocol
│     │        │  │     │  │  ├─ serializers.js
│     │        │  │     │  │  ├─ validator.js
│     │        │  │     │  │  └─ validatorPrimitives.js
│     │        │  │     │  ├─ remote
│     │        │  │     │  │  ├─ playwrightConnection.js
│     │        │  │     │  │  └─ playwrightServer.js
│     │        │  │     │  ├─ server
│     │        │  │     │  │  ├─ accessibility.js
│     │        │  │     │  │  ├─ android
│     │        │  │     │  │  │  ├─ android.js
│     │        │  │     │  │  │  └─ backendAdb.js
│     │        │  │     │  │  ├─ artifact.js
│     │        │  │     │  │  ├─ bidi
│     │        │  │     │  │  │  ├─ bidiBrowser.js
│     │        │  │     │  │  │  ├─ bidiChromium.js
│     │        │  │     │  │  │  ├─ bidiConnection.js
│     │        │  │     │  │  │  ├─ bidiExecutionContext.js
│     │        │  │     │  │  │  ├─ bidiFirefox.js
│     │        │  │     │  │  │  ├─ bidiInput.js
│     │        │  │     │  │  │  ├─ bidiNetworkManager.js
│     │        │  │     │  │  │  ├─ bidiOverCdp.js
│     │        │  │     │  │  │  ├─ bidiPage.js
│     │        │  │     │  │  │  ├─ bidiPdf.js
│     │        │  │     │  │  │  └─ third_party
│     │        │  │     │  │  │     ├─ bidiCommands.d.js
│     │        │  │     │  │  │     ├─ bidiDeserializer.js
│     │        │  │     │  │  │     ├─ bidiKeyboard.js
│     │        │  │     │  │  │     ├─ bidiProtocol.js
│     │        │  │     │  │  │     ├─ bidiProtocolCore.js
│     │        │  │     │  │  │     ├─ bidiProtocolPermissions.js
│     │        │  │     │  │  │     ├─ bidiSerializer.js
│     │        │  │     │  │  │     └─ firefoxPrefs.js
│     │        │  │     │  │  ├─ browser.js
│     │        │  │     │  │  ├─ browserContext.js
│     │        │  │     │  │  ├─ browserType.js
│     │        │  │     │  │  ├─ callLog.js
│     │        │  │     │  │  ├─ chromium
│     │        │  │     │  │  │  ├─ appIcon.png
│     │        │  │     │  │  │  ├─ chromium.js
│     │        │  │     │  │  │  ├─ chromiumSwitches.js
│     │        │  │     │  │  │  ├─ crAccessibility.js
│     │        │  │     │  │  │  ├─ crBrowser.js
│     │        │  │     │  │  │  ├─ crConnection.js
│     │        │  │     │  │  │  ├─ crCoverage.js
│     │        │  │     │  │  │  ├─ crDevTools.js
│     │        │  │     │  │  │  ├─ crDragDrop.js
│     │        │  │     │  │  │  ├─ crExecutionContext.js
│     │        │  │     │  │  │  ├─ crInput.js
│     │        │  │     │  │  │  ├─ crNetworkManager.js
│     │        │  │     │  │  │  ├─ crPage.js
│     │        │  │     │  │  │  ├─ crPdf.js
│     │        │  │     │  │  │  ├─ crProtocolHelper.js
│     │        │  │     │  │  │  ├─ crServiceWorker.js
│     │        │  │     │  │  │  ├─ defaultFontFamilies.js
│     │        │  │     │  │  │  ├─ protocol.d.js
│     │        │  │     │  │  │  └─ videoRecorder.js
│     │        │  │     │  │  ├─ clock.js
│     │        │  │     │  │  ├─ codegen
│     │        │  │     │  │  │  ├─ csharp.js
│     │        │  │     │  │  │  ├─ java.js
│     │        │  │     │  │  │  ├─ javascript.js
│     │        │  │     │  │  │  ├─ jsonl.js
│     │        │  │     │  │  │  ├─ language.js
│     │        │  │     │  │  │  ├─ languages.js
│     │        │  │     │  │  │  ├─ python.js
│     │        │  │     │  │  │  └─ types.js
│     │        │  │     │  │  ├─ console.js
│     │        │  │     │  │  ├─ cookieStore.js
│     │        │  │     │  │  ├─ debugController.js
│     │        │  │     │  │  ├─ debugger.js
│     │        │  │     │  │  ├─ deviceDescriptors.js
│     │        │  │     │  │  ├─ deviceDescriptorsSource.json
│     │        │  │     │  │  ├─ dialog.js
│     │        │  │     │  │  ├─ dispatchers
│     │        │  │     │  │  │  ├─ androidDispatcher.js
│     │        │  │     │  │  │  ├─ artifactDispatcher.js
│     │        │  │     │  │  │  ├─ browserContextDispatcher.js
│     │        │  │     │  │  │  ├─ browserDispatcher.js
│     │        │  │     │  │  │  ├─ browserTypeDispatcher.js
│     │        │  │     │  │  │  ├─ cdpSessionDispatcher.js
│     │        │  │     │  │  │  ├─ debugControllerDispatcher.js
│     │        │  │     │  │  │  ├─ dialogDispatcher.js
│     │        │  │     │  │  │  ├─ dispatcher.js
│     │        │  │     │  │  │  ├─ electronDispatcher.js
│     │        │  │     │  │  │  ├─ elementHandlerDispatcher.js
│     │        │  │     │  │  │  ├─ frameDispatcher.js
│     │        │  │     │  │  │  ├─ jsHandleDispatcher.js
│     │        │  │     │  │  │  ├─ jsonPipeDispatcher.js
│     │        │  │     │  │  │  ├─ localUtilsDispatcher.js
│     │        │  │     │  │  │  ├─ networkDispatchers.js
│     │        │  │     │  │  │  ├─ pageDispatcher.js
│     │        │  │     │  │  │  ├─ playwrightDispatcher.js
│     │        │  │     │  │  │  ├─ streamDispatcher.js
│     │        │  │     │  │  │  ├─ tracingDispatcher.js
│     │        │  │     │  │  │  ├─ webSocketRouteDispatcher.js
│     │        │  │     │  │  │  └─ writableStreamDispatcher.js
│     │        │  │     │  │  ├─ dom.js
│     │        │  │     │  │  ├─ download.js
│     │        │  │     │  │  ├─ electron
│     │        │  │     │  │  │  ├─ electron.js
│     │        │  │     │  │  │  └─ loader.js
│     │        │  │     │  │  ├─ errors.js
│     │        │  │     │  │  ├─ fetch.js
│     │        │  │     │  │  ├─ fileChooser.js
│     │        │  │     │  │  ├─ fileUploadUtils.js
│     │        │  │     │  │  ├─ firefox
│     │        │  │     │  │  │  ├─ ffAccessibility.js
│     │        │  │     │  │  │  ├─ ffBrowser.js
│     │        │  │     │  │  │  ├─ ffConnection.js
│     │        │  │     │  │  │  ├─ ffExecutionContext.js
│     │        │  │     │  │  │  ├─ ffInput.js
│     │        │  │     │  │  │  ├─ ffNetworkManager.js
│     │        │  │     │  │  │  ├─ ffPage.js
│     │        │  │     │  │  │  ├─ firefox.js
│     │        │  │     │  │  │  └─ protocol.d.js
│     │        │  │     │  │  ├─ formData.js
│     │        │  │     │  │  ├─ frameSelectors.js
│     │        │  │     │  │  ├─ frames.js
│     │        │  │     │  │  ├─ har
│     │        │  │     │  │  │  ├─ harRecorder.js
│     │        │  │     │  │  │  └─ harTracer.js
│     │        │  │     │  │  ├─ harBackend.js
│     │        │  │     │  │  ├─ helper.js
│     │        │  │     │  │  ├─ index.js
│     │        │  │     │  │  ├─ input.js
│     │        │  │     │  │  ├─ instrumentation.js
│     │        │  │     │  │  ├─ javascript.js
│     │        │  │     │  │  ├─ launchApp.js
│     │        │  │     │  │  ├─ localUtils.js
│     │        │  │     │  │  ├─ macEditingCommands.js
│     │        │  │     │  │  ├─ network.js
│     │        │  │     │  │  ├─ page.js
│     │        │  │     │  │  ├─ pipeTransport.js
│     │        │  │     │  │  ├─ playwright.js
│     │        │  │     │  │  ├─ progress.js
│     │        │  │     │  │  ├─ protocolError.js
│     │        │  │     │  │  ├─ recorder
│     │        │  │     │  │  │  ├─ chat.js
│     │        │  │     │  │  │  ├─ contextRecorder.js
│     │        │  │     │  │  │  ├─ recorderApp.js
│     │        │  │     │  │  │  ├─ recorderCollection.js
│     │        │  │     │  │  │  ├─ recorderFrontend.js
│     │        │  │     │  │  │  ├─ recorderRunner.js
│     │        │  │     │  │  │  ├─ recorderUtils.js
│     │        │  │     │  │  │  └─ throttledFile.js
│     │        │  │     │  │  ├─ recorder.js
│     │        │  │     │  │  ├─ registry
│     │        │  │     │  │  │  ├─ browserFetcher.js
│     │        │  │     │  │  │  ├─ dependencies.js
│     │        │  │     │  │  │  ├─ index.js
│     │        │  │     │  │  │  ├─ nativeDeps.js
│     │        │  │     │  │  │  └─ oopDownloadBrowserMain.js
│     │        │  │     │  │  ├─ screenshotter.js
│     │        │  │     │  │  ├─ selectors.js
│     │        │  │     │  │  ├─ socksClientCertificatesInterceptor.js
│     │        │  │     │  │  ├─ socksInterceptor.js
│     │        │  │     │  │  ├─ trace
│     │        │  │     │  │  │  ├─ recorder
│     │        │  │     │  │  │  │  ├─ snapshotter.js
│     │        │  │     │  │  │  │  ├─ snapshotterInjected.js
│     │        │  │     │  │  │  │  └─ tracing.js
│     │        │  │     │  │  │  ├─ test
│     │        │  │     │  │  │  │  └─ inMemorySnapshotter.js
│     │        │  │     │  │  │  └─ viewer
│     │        │  │     │  │  │     └─ traceViewer.js
│     │        │  │     │  │  ├─ transport.js
│     │        │  │     │  │  ├─ types.js
│     │        │  │     │  │  ├─ usKeyboardLayout.js
│     │        │  │     │  │  ├─ utils
│     │        │  │     │  │  │  ├─ ascii.js
│     │        │  │     │  │  │  ├─ comparators.js
│     │        │  │     │  │  │  ├─ crypto.js
│     │        │  │     │  │  │  ├─ debug.js
│     │        │  │     │  │  │  ├─ debugLogger.js
│     │        │  │     │  │  │  ├─ env.js
│     │        │  │     │  │  │  ├─ eventsHelper.js
│     │        │  │     │  │  │  ├─ expectUtils.js
│     │        │  │     │  │  │  ├─ fileUtils.js
│     │        │  │     │  │  │  ├─ happyEyeballs.js
│     │        │  │     │  │  │  ├─ hostPlatform.js
│     │        │  │     │  │  │  ├─ httpServer.js
│     │        │  │     │  │  │  ├─ image_tools
│     │        │  │     │  │  │  │  ├─ colorUtils.js
│     │        │  │     │  │  │  │  ├─ compare.js
│     │        │  │     │  │  │  │  ├─ imageChannel.js
│     │        │  │     │  │  │  │  └─ stats.js
│     │        │  │     │  │  │  ├─ linuxUtils.js
│     │        │  │     │  │  │  ├─ network.js
│     │        │  │     │  │  │  ├─ nodePlatform.js
│     │        │  │     │  │  │  ├─ pipeTransport.js
│     │        │  │     │  │  │  ├─ processLauncher.js
│     │        │  │     │  │  │  ├─ profiler.js
│     │        │  │     │  │  │  ├─ socksProxy.js
│     │        │  │     │  │  │  ├─ spawnAsync.js
│     │        │  │     │  │  │  ├─ task.js
│     │        │  │     │  │  │  ├─ userAgent.js
│     │        │  │     │  │  │  ├─ wsServer.js
│     │        │  │     │  │  │  ├─ zipFile.js
│     │        │  │     │  │  │  └─ zones.js
│     │        │  │     │  │  └─ webkit
│     │        │  │     │  │     ├─ protocol.d.js
│     │        │  │     │  │     ├─ webkit.js
│     │        │  │     │  │     ├─ wkAccessibility.js
│     │        │  │     │  │     ├─ wkBrowser.js
│     │        │  │     │  │     ├─ wkConnection.js
│     │        │  │     │  │     ├─ wkExecutionContext.js
│     │        │  │     │  │     ├─ wkInput.js
│     │        │  │     │  │     ├─ wkInterceptableRequest.js
│     │        │  │     │  │     ├─ wkPage.js
│     │        │  │     │  │     ├─ wkProvisionalPage.js
│     │        │  │     │  │     └─ wkWorkers.js
│     │        │  │     │  ├─ third_party
│     │        │  │     │  │  └─ pixelmatch.js
│     │        │  │     │  ├─ utils
│     │        │  │     │  │  └─ isomorphic
│     │        │  │     │  │     ├─ ariaSnapshot.js
│     │        │  │     │  │     ├─ assert.js
│     │        │  │     │  │     ├─ colors.js
│     │        │  │     │  │     ├─ cssParser.js
│     │        │  │     │  │     ├─ cssTokenizer.js
│     │        │  │     │  │     ├─ headers.js
│     │        │  │     │  │     ├─ locatorGenerators.js
│     │        │  │     │  │     ├─ locatorParser.js
│     │        │  │     │  │     ├─ locatorUtils.js
│     │        │  │     │  │     ├─ manualPromise.js
│     │        │  │     │  │     ├─ mimeType.js
│     │        │  │     │  │     ├─ multimap.js
│     │        │  │     │  │     ├─ protocolFormatter.js
│     │        │  │     │  │     ├─ protocolMetainfo.js
│     │        │  │     │  │     ├─ rtti.js
│     │        │  │     │  │     ├─ selectorParser.js
│     │        │  │     │  │     ├─ semaphore.js
│     │        │  │     │  │     ├─ stackTrace.js
│     │        │  │     │  │     ├─ stringUtils.js
│     │        │  │     │  │     ├─ time.js
│     │        │  │     │  │     ├─ timeoutRunner.js
│     │        │  │     │  │     ├─ traceUtils.js
│     │        │  │     │  │     ├─ types.js
│     │        │  │     │  │     ├─ urlMatch.js
│     │        │  │     │  │     └─ utilityScriptSerializers.js
│     │        │  │     │  ├─ utils.js
│     │        │  │     │  ├─ utilsBundle.js
│     │        │  │     │  ├─ utilsBundleImpl
│     │        │  │     │  │  ├─ index.js
│     │        │  │     │  │  └─ xdg-open
│     │        │  │     │  ├─ vite
│     │        │  │     │  │  ├─ htmlReport
│     │        │  │     │  │  │  └─ index.html
│     │        │  │     │  │  ├─ recorder
│     │        │  │     │  │  │  ├─ assets
│     │        │  │     │  │  │  │  ├─ codeMirrorModule-C3UTv-Ge.css
│     │        │  │     │  │  │  │  ├─ codeMirrorModule-DRsk21vu.js
│     │        │  │     │  │  │  │  ├─ codicon-DCmgc-ay.ttf
│     │        │  │     │  │  │  │  ├─ index-YwXrOGhp.js
│     │        │  │     │  │  │  │  └─ index-eHBmevrY.css
│     │        │  │     │  │  │  ├─ index.html
│     │        │  │     │  │  │  └─ playwright-logo.svg
│     │        │  │     │  │  └─ traceViewer
│     │        │  │     │  │     ├─ assets
│     │        │  │     │  │     │  ├─ codeMirrorModule-DECADVLv.js
│     │        │  │     │  │     │  ├─ defaultSettingsView-Cjl_e5YM.js
│     │        │  │     │  │     │  └─ xtermModule-BoAIEibi.js
│     │        │  │     │  │     ├─ codeMirrorModule.C3UTv-Ge.css
│     │        │  │     │  │     ├─ codicon.DCmgc-ay.ttf
│     │        │  │     │  │     ├─ defaultSettingsView.NYBT19Ch.css
│     │        │  │     │  │     ├─ index.BjQ9je-p.js
│     │        │  │     │  │     ├─ index.CFOW-Ezb.css
│     │        │  │     │  │     ├─ index.html
│     │        │  │     │  │     ├─ playwright-logo.svg
│     │        │  │     │  │     ├─ snapshot.html
│     │        │  │     │  │     ├─ sw.bundle.js
│     │        │  │     │  │     ├─ uiMode.BatfzHMG.css
│     │        │  │     │  │     ├─ uiMode.D5wwC2E1.js
│     │        │  │     │  │     ├─ uiMode.html
│     │        │  │     │  │     └─ xtermModule.Beg8tuEN.css
│     │        │  │     │  ├─ zipBundle.js
│     │        │  │     │  └─ zipBundleImpl.js
│     │        │  │     ├─ package.json
│     │        │  │     ├─ protocol.yml
│     │        │  │     └─ types
│     │        │  │        ├─ protocol.d.ts
│     │        │  │        ├─ structs.d.ts
│     │        │  │        └─ types.d.ts
│     │        │  ├─ py.typed
│     │        │  └─ sync_api
│     │        │     ├─ __init__.py
│     │        │     ├─ _context_manager.py
│     │        │     └─ _generated.py
│     │        ├─ playwright-1.53.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ publicsuffix2
│     │        │  ├─ __init__.py
│     │        │  ├─ mpl-2.0.LICENSE
│     │        │  ├─ public_suffix_list.ABOUT
│     │        │  └─ public_suffix_list.dat
│     │        ├─ publicsuffix2-2.20191221.dist-info
│     │        │  ├─ AUTHORS.rst
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ pyOpenSSL-25.0.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ pyasn1
│     │        │  ├─ __init__.py
│     │        │  ├─ codec
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ ber
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ decoder.py
│     │        │  │  │  ├─ encoder.py
│     │        │  │  │  └─ eoo.py
│     │        │  │  ├─ cer
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ decoder.py
│     │        │  │  │  └─ encoder.py
│     │        │  │  ├─ der
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ decoder.py
│     │        │  │  │  └─ encoder.py
│     │        │  │  ├─ native
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ decoder.py
│     │        │  │  │  └─ encoder.py
│     │        │  │  └─ streaming.py
│     │        │  ├─ compat
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ integer.py
│     │        │  ├─ debug.py
│     │        │  ├─ error.py
│     │        │  └─ type
│     │        │     ├─ __init__.py
│     │        │     ├─ base.py
│     │        │     ├─ char.py
│     │        │     ├─ constraint.py
│     │        │     ├─ error.py
│     │        │     ├─ namedtype.py
│     │        │     ├─ namedval.py
│     │        │     ├─ opentype.py
│     │        │     ├─ tag.py
│     │        │     ├─ tagmap.py
│     │        │     ├─ univ.py
│     │        │     └─ useful.py
│     │        ├─ pyasn1-0.6.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.rst
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ top_level.txt
│     │        │  └─ zip-safe
│     │        ├─ pyasn1_modules
│     │        │  ├─ __init__.py
│     │        │  ├─ pem.py
│     │        │  ├─ rfc1155.py
│     │        │  ├─ rfc1157.py
│     │        │  ├─ rfc1901.py
│     │        │  ├─ rfc1902.py
│     │        │  ├─ rfc1905.py
│     │        │  ├─ rfc2251.py
│     │        │  ├─ rfc2314.py
│     │        │  ├─ rfc2315.py
│     │        │  ├─ rfc2437.py
│     │        │  ├─ rfc2459.py
│     │        │  ├─ rfc2511.py
│     │        │  ├─ rfc2560.py
│     │        │  ├─ rfc2631.py
│     │        │  ├─ rfc2634.py
│     │        │  ├─ rfc2876.py
│     │        │  ├─ rfc2985.py
│     │        │  ├─ rfc2986.py
│     │        │  ├─ rfc3058.py
│     │        │  ├─ rfc3114.py
│     │        │  ├─ rfc3125.py
│     │        │  ├─ rfc3161.py
│     │        │  ├─ rfc3274.py
│     │        │  ├─ rfc3279.py
│     │        │  ├─ rfc3280.py
│     │        │  ├─ rfc3281.py
│     │        │  ├─ rfc3370.py
│     │        │  ├─ rfc3412.py
│     │        │  ├─ rfc3414.py
│     │        │  ├─ rfc3447.py
│     │        │  ├─ rfc3537.py
│     │        │  ├─ rfc3560.py
│     │        │  ├─ rfc3565.py
│     │        │  ├─ rfc3657.py
│     │        │  ├─ rfc3709.py
│     │        │  ├─ rfc3739.py
│     │        │  ├─ rfc3770.py
│     │        │  ├─ rfc3779.py
│     │        │  ├─ rfc3820.py
│     │        │  ├─ rfc3852.py
│     │        │  ├─ rfc4010.py
│     │        │  ├─ rfc4043.py
│     │        │  ├─ rfc4055.py
│     │        │  ├─ rfc4073.py
│     │        │  ├─ rfc4108.py
│     │        │  ├─ rfc4210.py
│     │        │  ├─ rfc4211.py
│     │        │  ├─ rfc4334.py
│     │        │  ├─ rfc4357.py
│     │        │  ├─ rfc4387.py
│     │        │  ├─ rfc4476.py
│     │        │  ├─ rfc4490.py
│     │        │  ├─ rfc4491.py
│     │        │  ├─ rfc4683.py
│     │        │  ├─ rfc4985.py
│     │        │  ├─ rfc5035.py
│     │        │  ├─ rfc5083.py
│     │        │  ├─ rfc5084.py
│     │        │  ├─ rfc5126.py
│     │        │  ├─ rfc5208.py
│     │        │  ├─ rfc5275.py
│     │        │  ├─ rfc5280.py
│     │        │  ├─ rfc5480.py
│     │        │  ├─ rfc5636.py
│     │        │  ├─ rfc5639.py
│     │        │  ├─ rfc5649.py
│     │        │  ├─ rfc5652.py
│     │        │  ├─ rfc5697.py
│     │        │  ├─ rfc5751.py
│     │        │  ├─ rfc5752.py
│     │        │  ├─ rfc5753.py
│     │        │  ├─ rfc5755.py
│     │        │  ├─ rfc5913.py
│     │        │  ├─ rfc5914.py
│     │        │  ├─ rfc5915.py
│     │        │  ├─ rfc5916.py
│     │        │  ├─ rfc5917.py
│     │        │  ├─ rfc5924.py
│     │        │  ├─ rfc5934.py
│     │        │  ├─ rfc5940.py
│     │        │  ├─ rfc5958.py
│     │        │  ├─ rfc5990.py
│     │        │  ├─ rfc6010.py
│     │        │  ├─ rfc6019.py
│     │        │  ├─ rfc6031.py
│     │        │  ├─ rfc6032.py
│     │        │  ├─ rfc6120.py
│     │        │  ├─ rfc6170.py
│     │        │  ├─ rfc6187.py
│     │        │  ├─ rfc6210.py
│     │        │  ├─ rfc6211.py
│     │        │  ├─ rfc6402.py
│     │        │  ├─ rfc6482.py
│     │        │  ├─ rfc6486.py
│     │        │  ├─ rfc6487.py
│     │        │  ├─ rfc6664.py
│     │        │  ├─ rfc6955.py
│     │        │  ├─ rfc6960.py
│     │        │  ├─ rfc7030.py
│     │        │  ├─ rfc7191.py
│     │        │  ├─ rfc7229.py
│     │        │  ├─ rfc7292.py
│     │        │  ├─ rfc7296.py
│     │        │  ├─ rfc7508.py
│     │        │  ├─ rfc7585.py
│     │        │  ├─ rfc7633.py
│     │        │  ├─ rfc7773.py
│     │        │  ├─ rfc7894.py
│     │        │  ├─ rfc7906.py
│     │        │  ├─ rfc7914.py
│     │        │  ├─ rfc8017.py
│     │        │  ├─ rfc8018.py
│     │        │  ├─ rfc8103.py
│     │        │  ├─ rfc8209.py
│     │        │  ├─ rfc8226.py
│     │        │  ├─ rfc8358.py
│     │        │  ├─ rfc8360.py
│     │        │  ├─ rfc8398.py
│     │        │  ├─ rfc8410.py
│     │        │  ├─ rfc8418.py
│     │        │  ├─ rfc8419.py
│     │        │  ├─ rfc8479.py
│     │        │  ├─ rfc8494.py
│     │        │  ├─ rfc8520.py
│     │        │  ├─ rfc8619.py
│     │        │  ├─ rfc8649.py
│     │        │  ├─ rfc8692.py
│     │        │  ├─ rfc8696.py
│     │        │  ├─ rfc8702.py
│     │        │  ├─ rfc8708.py
│     │        │  └─ rfc8769.py
│     │        ├─ pyasn1_modules-0.4.2.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE.txt
│     │        │  ├─ top_level.txt
│     │        │  └─ zip-safe
│     │        ├─ pycparser
│     │        │  ├─ __init__.py
│     │        │  ├─ _ast_gen.py
│     │        │  ├─ _build_tables.py
│     │        │  ├─ _c_ast.cfg
│     │        │  ├─ ast_transforms.py
│     │        │  ├─ c_ast.py
│     │        │  ├─ c_generator.py
│     │        │  ├─ c_lexer.py
│     │        │  ├─ c_parser.py
│     │        │  ├─ lextab.py
│     │        │  ├─ ply
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ cpp.py
│     │        │  │  ├─ ctokens.py
│     │        │  │  ├─ lex.py
│     │        │  │  ├─ yacc.py
│     │        │  │  └─ ygen.py
│     │        │  ├─ plyparser.py
│     │        │  └─ yacctab.py
│     │        ├─ pycparser-2.22.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ pydantic
│     │        │  ├─ __init__.py
│     │        │  ├─ _internal
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _config.py
│     │        │  │  ├─ _core_metadata.py
│     │        │  │  ├─ _core_utils.py
│     │        │  │  ├─ _dataclasses.py
│     │        │  │  ├─ _decorators.py
│     │        │  │  ├─ _decorators_v1.py
│     │        │  │  ├─ _discriminated_union.py
│     │        │  │  ├─ _docs_extraction.py
│     │        │  │  ├─ _fields.py
│     │        │  │  ├─ _forward_ref.py
│     │        │  │  ├─ _generate_schema.py
│     │        │  │  ├─ _generics.py
│     │        │  │  ├─ _git.py
│     │        │  │  ├─ _import_utils.py
│     │        │  │  ├─ _internal_dataclass.py
│     │        │  │  ├─ _known_annotated_metadata.py
│     │        │  │  ├─ _mock_val_ser.py
│     │        │  │  ├─ _model_construction.py
│     │        │  │  ├─ _namespace_utils.py
│     │        │  │  ├─ _repr.py
│     │        │  │  ├─ _schema_gather.py
│     │        │  │  ├─ _schema_generation_shared.py
│     │        │  │  ├─ _serializers.py
│     │        │  │  ├─ _signature.py
│     │        │  │  ├─ _typing_extra.py
│     │        │  │  ├─ _utils.py
│     │        │  │  ├─ _validate_call.py
│     │        │  │  └─ _validators.py
│     │        │  ├─ _migration.py
│     │        │  ├─ alias_generators.py
│     │        │  ├─ aliases.py
│     │        │  ├─ annotated_handlers.py
│     │        │  ├─ class_validators.py
│     │        │  ├─ color.py
│     │        │  ├─ config.py
│     │        │  ├─ dataclasses.py
│     │        │  ├─ datetime_parse.py
│     │        │  ├─ decorator.py
│     │        │  ├─ deprecated
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ class_validators.py
│     │        │  │  ├─ config.py
│     │        │  │  ├─ copy_internals.py
│     │        │  │  ├─ decorator.py
│     │        │  │  ├─ json.py
│     │        │  │  ├─ parse.py
│     │        │  │  └─ tools.py
│     │        │  ├─ env_settings.py
│     │        │  ├─ error_wrappers.py
│     │        │  ├─ errors.py
│     │        │  ├─ experimental
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ arguments_schema.py
│     │        │  │  └─ pipeline.py
│     │        │  ├─ fields.py
│     │        │  ├─ functional_serializers.py
│     │        │  ├─ functional_validators.py
│     │        │  ├─ generics.py
│     │        │  ├─ json.py
│     │        │  ├─ json_schema.py
│     │        │  ├─ main.py
│     │        │  ├─ mypy.py
│     │        │  ├─ networks.py
│     │        │  ├─ parse.py
│     │        │  ├─ plugin
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _loader.py
│     │        │  │  └─ _schema_validator.py
│     │        │  ├─ py.typed
│     │        │  ├─ root_model.py
│     │        │  ├─ schema.py
│     │        │  ├─ tools.py
│     │        │  ├─ type_adapter.py
│     │        │  ├─ types.py
│     │        │  ├─ typing.py
│     │        │  ├─ utils.py
│     │        │  ├─ v1
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _hypothesis_plugin.py
│     │        │  │  ├─ annotated_types.py
│     │        │  │  ├─ class_validators.py
│     │        │  │  ├─ color.py
│     │        │  │  ├─ config.py
│     │        │  │  ├─ dataclasses.py
│     │        │  │  ├─ datetime_parse.py
│     │        │  │  ├─ decorator.py
│     │        │  │  ├─ env_settings.py
│     │        │  │  ├─ error_wrappers.py
│     │        │  │  ├─ errors.py
│     │        │  │  ├─ fields.py
│     │        │  │  ├─ generics.py
│     │        │  │  ├─ json.py
│     │        │  │  ├─ main.py
│     │        │  │  ├─ mypy.py
│     │        │  │  ├─ networks.py
│     │        │  │  ├─ parse.py
│     │        │  │  ├─ py.typed
│     │        │  │  ├─ schema.py
│     │        │  │  ├─ tools.py
│     │        │  │  ├─ types.py
│     │        │  │  ├─ typing.py
│     │        │  │  ├─ utils.py
│     │        │  │  ├─ validators.py
│     │        │  │  └─ version.py
│     │        │  ├─ validate_call_decorator.py
│     │        │  ├─ validators.py
│     │        │  ├─ version.py
│     │        │  └─ warnings.py
│     │        ├─ pydantic-2.11.7.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ pydantic_core
│     │        │  ├─ __init__.py
│     │        │  ├─ _pydantic_core.cpython-312-darwin.so
│     │        │  ├─ _pydantic_core.pyi
│     │        │  ├─ core_schema.py
│     │        │  └─ py.typed
│     │        ├─ pydantic_core-2.33.2.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ pyee
│     │        │  ├─ __init__.py
│     │        │  ├─ asyncio.py
│     │        │  ├─ base.py
│     │        │  ├─ cls.py
│     │        │  ├─ executor.py
│     │        │  ├─ py.typed
│     │        │  ├─ trio.py
│     │        │  ├─ twisted.py
│     │        │  └─ uplift.py
│     │        ├─ pyee-13.0.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ pylsqpack
│     │        │  ├─ __init__.py
│     │        │  ├─ __init__.pyi
│     │        │  ├─ _binding.abi3.so
│     │        │  ├─ binding.c
│     │        │  └─ py.typed
│     │        ├─ pylsqpack-0.3.22.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ pyparsing
│     │        │  ├─ __init__.py
│     │        │  ├─ actions.py
│     │        │  ├─ common.py
│     │        │  ├─ core.py
│     │        │  ├─ diagram
│     │        │  │  └─ __init__.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ helpers.py
│     │        │  ├─ py.typed
│     │        │  ├─ results.py
│     │        │  ├─ testing.py
│     │        │  ├─ tools
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ cvt_pyparsing_pep8_names.py
│     │        │  ├─ unicode.py
│     │        │  └─ util.py
│     │        ├─ pyparsing-3.2.3.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  └─ WHEEL
│     │        ├─ pyperclip
│     │        │  ├─ __init__.py
│     │        │  └─ __main__.py
│     │        ├─ pyperclip-1.9.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  ├─ AUTHORS.txt
│     │        │  │  └─ LICENSE.txt
│     │        │  └─ top_level.txt
│     │        ├─ python_dateutil-2.9.0.post0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ top_level.txt
│     │        │  └─ zip-safe
│     │        ├─ python_dotenv-1.1.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ python_multipart
│     │        │  ├─ __init__.py
│     │        │  ├─ decoders.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ multipart.py
│     │        │  └─ py.typed
│     │        ├─ python_multipart-0.0.20.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE.txt
│     │        ├─ pytz
│     │        │  ├─ __init__.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ lazy.py
│     │        │  ├─ reference.py
│     │        │  ├─ tzfile.py
│     │        │  ├─ tzinfo.py
│     │        │  └─ zoneinfo
│     │        │     ├─ Africa
│     │        │     │  ├─ Abidjan
│     │        │     │  ├─ Accra
│     │        │     │  ├─ Addis_Ababa
│     │        │     │  ├─ Algiers
│     │        │     │  ├─ Asmara
│     │        │     │  ├─ Asmera
│     │        │     │  ├─ Bamako
│     │        │     │  ├─ Bangui
│     │        │     │  ├─ Banjul
│     │        │     │  ├─ Bissau
│     │        │     │  ├─ Blantyre
│     │        │     │  ├─ Brazzaville
│     │        │     │  ├─ Bujumbura
│     │        │     │  ├─ Cairo
│     │        │     │  ├─ Casablanca
│     │        │     │  ├─ Ceuta
│     │        │     │  ├─ Conakry
│     │        │     │  ├─ Dakar
│     │        │     │  ├─ Dar_es_Salaam
│     │        │     │  ├─ Djibouti
│     │        │     │  ├─ Douala
│     │        │     │  ├─ El_Aaiun
│     │        │     │  ├─ Freetown
│     │        │     │  ├─ Gaborone
│     │        │     │  ├─ Harare
│     │        │     │  ├─ Johannesburg
│     │        │     │  ├─ Juba
│     │        │     │  ├─ Kampala
│     │        │     │  ├─ Khartoum
│     │        │     │  ├─ Kigali
│     │        │     │  ├─ Kinshasa
│     │        │     │  ├─ Lagos
│     │        │     │  ├─ Libreville
│     │        │     │  ├─ Lome
│     │        │     │  ├─ Luanda
│     │        │     │  ├─ Lubumbashi
│     │        │     │  ├─ Lusaka
│     │        │     │  ├─ Malabo
│     │        │     │  ├─ Maputo
│     │        │     │  ├─ Maseru
│     │        │     │  ├─ Mbabane
│     │        │     │  ├─ Mogadishu
│     │        │     │  ├─ Monrovia
│     │        │     │  ├─ Nairobi
│     │        │     │  ├─ Ndjamena
│     │        │     │  ├─ Niamey
│     │        │     │  ├─ Nouakchott
│     │        │     │  ├─ Ouagadougou
│     │        │     │  ├─ Porto-Novo
│     │        │     │  ├─ Sao_Tome
│     │        │     │  ├─ Timbuktu
│     │        │     │  ├─ Tripoli
│     │        │     │  ├─ Tunis
│     │        │     │  └─ Windhoek
│     │        │     ├─ America
│     │        │     │  ├─ Adak
│     │        │     │  ├─ Anchorage
│     │        │     │  ├─ Anguilla
│     │        │     │  ├─ Antigua
│     │        │     │  ├─ Araguaina
│     │        │     │  ├─ Argentina
│     │        │     │  │  ├─ Buenos_Aires
│     │        │     │  │  ├─ Catamarca
│     │        │     │  │  ├─ ComodRivadavia
│     │        │     │  │  ├─ Cordoba
│     │        │     │  │  ├─ Jujuy
│     │        │     │  │  ├─ La_Rioja
│     │        │     │  │  ├─ Mendoza
│     │        │     │  │  ├─ Rio_Gallegos
│     │        │     │  │  ├─ Salta
│     │        │     │  │  ├─ San_Juan
│     │        │     │  │  ├─ San_Luis
│     │        │     │  │  ├─ Tucuman
│     │        │     │  │  └─ Ushuaia
│     │        │     │  ├─ Aruba
│     │        │     │  ├─ Asuncion
│     │        │     │  ├─ Atikokan
│     │        │     │  ├─ Atka
│     │        │     │  ├─ Bahia
│     │        │     │  ├─ Bahia_Banderas
│     │        │     │  ├─ Barbados
│     │        │     │  ├─ Belem
│     │        │     │  ├─ Belize
│     │        │     │  ├─ Blanc-Sablon
│     │        │     │  ├─ Boa_Vista
│     │        │     │  ├─ Bogota
│     │        │     │  ├─ Boise
│     │        │     │  ├─ Buenos_Aires
│     │        │     │  ├─ Cambridge_Bay
│     │        │     │  ├─ Campo_Grande
│     │        │     │  ├─ Cancun
│     │        │     │  ├─ Caracas
│     │        │     │  ├─ Catamarca
│     │        │     │  ├─ Cayenne
│     │        │     │  ├─ Cayman
│     │        │     │  ├─ Chicago
│     │        │     │  ├─ Chihuahua
│     │        │     │  ├─ Ciudad_Juarez
│     │        │     │  ├─ Coral_Harbour
│     │        │     │  ├─ Cordoba
│     │        │     │  ├─ Costa_Rica
│     │        │     │  ├─ Coyhaique
│     │        │     │  ├─ Creston
│     │        │     │  ├─ Cuiaba
│     │        │     │  ├─ Curacao
│     │        │     │  ├─ Danmarkshavn
│     │        │     │  ├─ Dawson
│     │        │     │  ├─ Dawson_Creek
│     │        │     │  ├─ Denver
│     │        │     │  ├─ Detroit
│     │        │     │  ├─ Dominica
│     │        │     │  ├─ Edmonton
│     │        │     │  ├─ Eirunepe
│     │        │     │  ├─ El_Salvador
│     │        │     │  ├─ Ensenada
│     │        │     │  ├─ Fort_Nelson
│     │        │     │  ├─ Fort_Wayne
│     │        │     │  ├─ Fortaleza
│     │        │     │  ├─ Glace_Bay
│     │        │     │  ├─ Godthab
│     │        │     │  ├─ Goose_Bay
│     │        │     │  ├─ Grand_Turk
│     │        │     │  ├─ Grenada
│     │        │     │  ├─ Guadeloupe
│     │        │     │  ├─ Guatemala
│     │        │     │  ├─ Guayaquil
│     │        │     │  ├─ Guyana
│     │        │     │  ├─ Halifax
│     │        │     │  ├─ Havana
│     │        │     │  ├─ Hermosillo
│     │        │     │  ├─ Indiana
│     │        │     │  │  ├─ Indianapolis
│     │        │     │  │  ├─ Knox
│     │        │     │  │  ├─ Marengo
│     │        │     │  │  ├─ Petersburg
│     │        │     │  │  ├─ Tell_City
│     │        │     │  │  ├─ Vevay
│     │        │     │  │  ├─ Vincennes
│     │        │     │  │  └─ Winamac
│     │        │     │  ├─ Indianapolis
│     │        │     │  ├─ Inuvik
│     │        │     │  ├─ Iqaluit
│     │        │     │  ├─ Jamaica
│     │        │     │  ├─ Jujuy
│     │        │     │  ├─ Juneau
│     │        │     │  ├─ Kentucky
│     │        │     │  │  ├─ Louisville
│     │        │     │  │  └─ Monticello
│     │        │     │  ├─ Knox_IN
│     │        │     │  ├─ Kralendijk
│     │        │     │  ├─ La_Paz
│     │        │     │  ├─ Lima
│     │        │     │  ├─ Los_Angeles
│     │        │     │  ├─ Louisville
│     │        │     │  ├─ Lower_Princes
│     │        │     │  ├─ Maceio
│     │        │     │  ├─ Managua
│     │        │     │  ├─ Manaus
│     │        │     │  ├─ Marigot
│     │        │     │  ├─ Martinique
│     │        │     │  ├─ Matamoros
│     │        │     │  ├─ Mazatlan
│     │        │     │  ├─ Mendoza
│     │        │     │  ├─ Menominee
│     │        │     │  ├─ Merida
│     │        │     │  ├─ Metlakatla
│     │        │     │  ├─ Mexico_City
│     │        │     │  ├─ Miquelon
│     │        │     │  ├─ Moncton
│     │        │     │  ├─ Monterrey
│     │        │     │  ├─ Montevideo
│     │        │     │  ├─ Montreal
│     │        │     │  ├─ Montserrat
│     │        │     │  ├─ Nassau
│     │        │     │  ├─ New_York
│     │        │     │  ├─ Nipigon
│     │        │     │  ├─ Nome
│     │        │     │  ├─ Noronha
│     │        │     │  ├─ North_Dakota
│     │        │     │  │  ├─ Beulah
│     │        │     │  │  ├─ Center
│     │        │     │  │  └─ New_Salem
│     │        │     │  ├─ Nuuk
│     │        │     │  ├─ Ojinaga
│     │        │     │  ├─ Panama
│     │        │     │  ├─ Pangnirtung
│     │        │     │  ├─ Paramaribo
│     │        │     │  ├─ Phoenix
│     │        │     │  ├─ Port-au-Prince
│     │        │     │  ├─ Port_of_Spain
│     │        │     │  ├─ Porto_Acre
│     │        │     │  ├─ Porto_Velho
│     │        │     │  ├─ Puerto_Rico
│     │        │     │  ├─ Punta_Arenas
│     │        │     │  ├─ Rainy_River
│     │        │     │  ├─ Rankin_Inlet
│     │        │     │  ├─ Recife
│     │        │     │  ├─ Regina
│     │        │     │  ├─ Resolute
│     │        │     │  ├─ Rio_Branco
│     │        │     │  ├─ Rosario
│     │        │     │  ├─ Santa_Isabel
│     │        │     │  ├─ Santarem
│     │        │     │  ├─ Santiago
│     │        │     │  ├─ Santo_Domingo
│     │        │     │  ├─ Sao_Paulo
│     │        │     │  ├─ Scoresbysund
│     │        │     │  ├─ Shiprock
│     │        │     │  ├─ Sitka
│     │        │     │  ├─ St_Barthelemy
│     │        │     │  ├─ St_Johns
│     │        │     │  ├─ St_Kitts
│     │        │     │  ├─ St_Lucia
│     │        │     │  ├─ St_Thomas
│     │        │     │  ├─ St_Vincent
│     │        │     │  ├─ Swift_Current
│     │        │     │  ├─ Tegucigalpa
│     │        │     │  ├─ Thule
│     │        │     │  ├─ Thunder_Bay
│     │        │     │  ├─ Tijuana
│     │        │     │  ├─ Toronto
│     │        │     │  ├─ Tortola
│     │        │     │  ├─ Vancouver
│     │        │     │  ├─ Virgin
│     │        │     │  ├─ Whitehorse
│     │        │     │  ├─ Winnipeg
│     │        │     │  ├─ Yakutat
│     │        │     │  └─ Yellowknife
│     │        │     ├─ Antarctica
│     │        │     │  ├─ Casey
│     │        │     │  ├─ Davis
│     │        │     │  ├─ DumontDUrville
│     │        │     │  ├─ Macquarie
│     │        │     │  ├─ Mawson
│     │        │     │  ├─ McMurdo
│     │        │     │  ├─ Palmer
│     │        │     │  ├─ Rothera
│     │        │     │  ├─ South_Pole
│     │        │     │  ├─ Syowa
│     │        │     │  ├─ Troll
│     │        │     │  └─ Vostok
│     │        │     ├─ Arctic
│     │        │     │  └─ Longyearbyen
│     │        │     ├─ Asia
│     │        │     │  ├─ Aden
│     │        │     │  ├─ Almaty
│     │        │     │  ├─ Amman
│     │        │     │  ├─ Anadyr
│     │        │     │  ├─ Aqtau
│     │        │     │  ├─ Aqtobe
│     │        │     │  ├─ Ashgabat
│     │        │     │  ├─ Ashkhabad
│     │        │     │  ├─ Atyrau
│     │        │     │  ├─ Baghdad
│     │        │     │  ├─ Bahrain
│     │        │     │  ├─ Baku
│     │        │     │  ├─ Bangkok
│     │        │     │  ├─ Barnaul
│     │        │     │  ├─ Beirut
│     │        │     │  ├─ Bishkek
│     │        │     │  ├─ Brunei
│     │        │     │  ├─ Calcutta
│     │        │     │  ├─ Chita
│     │        │     │  ├─ Choibalsan
│     │        │     │  ├─ Chongqing
│     │        │     │  ├─ Chungking
│     │        │     │  ├─ Colombo
│     │        │     │  ├─ Dacca
│     │        │     │  ├─ Damascus
│     │        │     │  ├─ Dhaka
│     │        │     │  ├─ Dili
│     │        │     │  ├─ Dubai
│     │        │     │  ├─ Dushanbe
│     │        │     │  ├─ Famagusta
│     │        │     │  ├─ Gaza
│     │        │     │  ├─ Harbin
│     │        │     │  ├─ Hebron
│     │        │     │  ├─ Ho_Chi_Minh
│     │        │     │  ├─ Hong_Kong
│     │        │     │  ├─ Hovd
│     │        │     │  ├─ Irkutsk
│     │        │     │  ├─ Istanbul
│     │        │     │  ├─ Jakarta
│     │        │     │  ├─ Jayapura
│     │        │     │  ├─ Jerusalem
│     │        │     │  ├─ Kabul
│     │        │     │  ├─ Kamchatka
│     │        │     │  ├─ Karachi
│     │        │     │  ├─ Kashgar
│     │        │     │  ├─ Kathmandu
│     │        │     │  ├─ Katmandu
│     │        │     │  ├─ Khandyga
│     │        │     │  ├─ Kolkata
│     │        │     │  ├─ Krasnoyarsk
│     │        │     │  ├─ Kuala_Lumpur
│     │        │     │  ├─ Kuching
│     │        │     │  ├─ Kuwait
│     │        │     │  ├─ Macao
│     │        │     │  ├─ Macau
│     │        │     │  ├─ Magadan
│     │        │     │  ├─ Makassar
│     │        │     │  ├─ Manila
│     │        │     │  ├─ Muscat
│     │        │     │  ├─ Nicosia
│     │        │     │  ├─ Novokuznetsk
│     │        │     │  ├─ Novosibirsk
│     │        │     │  ├─ Omsk
│     │        │     │  ├─ Oral
│     │        │     │  ├─ Phnom_Penh
│     │        │     │  ├─ Pontianak
│     │        │     │  ├─ Pyongyang
│     │        │     │  ├─ Qatar
│     │        │     │  ├─ Qostanay
│     │        │     │  ├─ Qyzylorda
│     │        │     │  ├─ Rangoon
│     │        │     │  ├─ Riyadh
│     │        │     │  ├─ Saigon
│     │        │     │  ├─ Sakhalin
│     │        │     │  ├─ Samarkand
│     │        │     │  ├─ Seoul
│     │        │     │  ├─ Shanghai
│     │        │     │  ├─ Singapore
│     │        │     │  ├─ Srednekolymsk
│     │        │     │  ├─ Taipei
│     │        │     │  ├─ Tashkent
│     │        │     │  ├─ Tbilisi
│     │        │     │  ├─ Tehran
│     │        │     │  ├─ Tel_Aviv
│     │        │     │  ├─ Thimbu
│     │        │     │  ├─ Thimphu
│     │        │     │  ├─ Tokyo
│     │        │     │  ├─ Tomsk
│     │        │     │  ├─ Ujung_Pandang
│     │        │     │  ├─ Ulaanbaatar
│     │        │     │  ├─ Ulan_Bator
│     │        │     │  ├─ Urumqi
│     │        │     │  ├─ Ust-Nera
│     │        │     │  ├─ Vientiane
│     │        │     │  ├─ Vladivostok
│     │        │     │  ├─ Yakutsk
│     │        │     │  ├─ Yangon
│     │        │     │  ├─ Yekaterinburg
│     │        │     │  └─ Yerevan
│     │        │     ├─ Atlantic
│     │        │     │  ├─ Azores
│     │        │     │  ├─ Bermuda
│     │        │     │  ├─ Canary
│     │        │     │  ├─ Cape_Verde
│     │        │     │  ├─ Faeroe
│     │        │     │  ├─ Faroe
│     │        │     │  ├─ Jan_Mayen
│     │        │     │  ├─ Madeira
│     │        │     │  ├─ Reykjavik
│     │        │     │  ├─ South_Georgia
│     │        │     │  ├─ St_Helena
│     │        │     │  └─ Stanley
│     │        │     ├─ Australia
│     │        │     │  ├─ ACT
│     │        │     │  ├─ Adelaide
│     │        │     │  ├─ Brisbane
│     │        │     │  ├─ Broken_Hill
│     │        │     │  ├─ Canberra
│     │        │     │  ├─ Currie
│     │        │     │  ├─ Darwin
│     │        │     │  ├─ Eucla
│     │        │     │  ├─ Hobart
│     │        │     │  ├─ LHI
│     │        │     │  ├─ Lindeman
│     │        │     │  ├─ Lord_Howe
│     │        │     │  ├─ Melbourne
│     │        │     │  ├─ NSW
│     │        │     │  ├─ North
│     │        │     │  ├─ Perth
│     │        │     │  ├─ Queensland
│     │        │     │  ├─ South
│     │        │     │  ├─ Sydney
│     │        │     │  ├─ Tasmania
│     │        │     │  ├─ Victoria
│     │        │     │  ├─ West
│     │        │     │  └─ Yancowinna
│     │        │     ├─ Brazil
│     │        │     │  ├─ Acre
│     │        │     │  ├─ DeNoronha
│     │        │     │  ├─ East
│     │        │     │  └─ West
│     │        │     ├─ CET
│     │        │     ├─ CST6CDT
│     │        │     ├─ Canada
│     │        │     │  ├─ Atlantic
│     │        │     │  ├─ Central
│     │        │     │  ├─ Eastern
│     │        │     │  ├─ Mountain
│     │        │     │  ├─ Newfoundland
│     │        │     │  ├─ Pacific
│     │        │     │  ├─ Saskatchewan
│     │        │     │  └─ Yukon
│     │        │     ├─ Chile
│     │        │     │  ├─ Continental
│     │        │     │  └─ EasterIsland
│     │        │     ├─ Cuba
│     │        │     ├─ EET
│     │        │     ├─ EST
│     │        │     ├─ EST5EDT
│     │        │     ├─ Egypt
│     │        │     ├─ Eire
│     │        │     ├─ Etc
│     │        │     │  ├─ GMT
│     │        │     │  ├─ GMT+0
│     │        │     │  ├─ GMT+1
│     │        │     │  ├─ GMT+10
│     │        │     │  ├─ GMT+11
│     │        │     │  ├─ GMT+12
│     │        │     │  ├─ GMT+2
│     │        │     │  ├─ GMT+3
│     │        │     │  ├─ GMT+4
│     │        │     │  ├─ GMT+5
│     │        │     │  ├─ GMT+6
│     │        │     │  ├─ GMT+7
│     │        │     │  ├─ GMT+8
│     │        │     │  ├─ GMT+9
│     │        │     │  ├─ GMT-0
│     │        │     │  ├─ GMT-1
│     │        │     │  ├─ GMT-10
│     │        │     │  ├─ GMT-11
│     │        │     │  ├─ GMT-12
│     │        │     │  ├─ GMT-13
│     │        │     │  ├─ GMT-14
│     │        │     │  ├─ GMT-2
│     │        │     │  ├─ GMT-3
│     │        │     │  ├─ GMT-4
│     │        │     │  ├─ GMT-5
│     │        │     │  ├─ GMT-6
│     │        │     │  ├─ GMT-7
│     │        │     │  ├─ GMT-8
│     │        │     │  ├─ GMT-9
│     │        │     │  ├─ GMT0
│     │        │     │  ├─ Greenwich
│     │        │     │  ├─ UCT
│     │        │     │  ├─ UTC
│     │        │     │  ├─ Universal
│     │        │     │  └─ Zulu
│     │        │     ├─ Europe
│     │        │     │  ├─ Amsterdam
│     │        │     │  ├─ Andorra
│     │        │     │  ├─ Astrakhan
│     │        │     │  ├─ Athens
│     │        │     │  ├─ Belfast
│     │        │     │  ├─ Belgrade
│     │        │     │  ├─ Berlin
│     │        │     │  ├─ Bratislava
│     │        │     │  ├─ Brussels
│     │        │     │  ├─ Bucharest
│     │        │     │  ├─ Budapest
│     │        │     │  ├─ Busingen
│     │        │     │  ├─ Chisinau
│     │        │     │  ├─ Copenhagen
│     │        │     │  ├─ Dublin
│     │        │     │  ├─ Gibraltar
│     │        │     │  ├─ Guernsey
│     │        │     │  ├─ Helsinki
│     │        │     │  ├─ Isle_of_Man
│     │        │     │  ├─ Istanbul
│     │        │     │  ├─ Jersey
│     │        │     │  ├─ Kaliningrad
│     │        │     │  ├─ Kiev
│     │        │     │  ├─ Kirov
│     │        │     │  ├─ Kyiv
│     │        │     │  ├─ Lisbon
│     │        │     │  ├─ Ljubljana
│     │        │     │  ├─ London
│     │        │     │  ├─ Luxembourg
│     │        │     │  ├─ Madrid
│     │        │     │  ├─ Malta
│     │        │     │  ├─ Mariehamn
│     │        │     │  ├─ Minsk
│     │        │     │  ├─ Monaco
│     │        │     │  ├─ Moscow
│     │        │     │  ├─ Nicosia
│     │        │     │  ├─ Oslo
│     │        │     │  ├─ Paris
│     │        │     │  ├─ Podgorica
│     │        │     │  ├─ Prague
│     │        │     │  ├─ Riga
│     │        │     │  ├─ Rome
│     │        │     │  ├─ Samara
│     │        │     │  ├─ San_Marino
│     │        │     │  ├─ Sarajevo
│     │        │     │  ├─ Saratov
│     │        │     │  ├─ Simferopol
│     │        │     │  ├─ Skopje
│     │        │     │  ├─ Sofia
│     │        │     │  ├─ Stockholm
│     │        │     │  ├─ Tallinn
│     │        │     │  ├─ Tirane
│     │        │     │  ├─ Tiraspol
│     │        │     │  ├─ Ulyanovsk
│     │        │     │  ├─ Uzhgorod
│     │        │     │  ├─ Vaduz
│     │        │     │  ├─ Vatican
│     │        │     │  ├─ Vienna
│     │        │     │  ├─ Vilnius
│     │        │     │  ├─ Volgograd
│     │        │     │  ├─ Warsaw
│     │        │     │  ├─ Zagreb
│     │        │     │  ├─ Zaporozhye
│     │        │     │  └─ Zurich
│     │        │     ├─ Factory
│     │        │     ├─ GB
│     │        │     ├─ GB-Eire
│     │        │     ├─ GMT
│     │        │     ├─ GMT+0
│     │        │     ├─ GMT-0
│     │        │     ├─ GMT0
│     │        │     ├─ Greenwich
│     │        │     ├─ HST
│     │        │     ├─ Hongkong
│     │        │     ├─ Iceland
│     │        │     ├─ Indian
│     │        │     │  ├─ Antananarivo
│     │        │     │  ├─ Chagos
│     │        │     │  ├─ Christmas
│     │        │     │  ├─ Cocos
│     │        │     │  ├─ Comoro
│     │        │     │  ├─ Kerguelen
│     │        │     │  ├─ Mahe
│     │        │     │  ├─ Maldives
│     │        │     │  ├─ Mauritius
│     │        │     │  ├─ Mayotte
│     │        │     │  └─ Reunion
│     │        │     ├─ Iran
│     │        │     ├─ Israel
│     │        │     ├─ Jamaica
│     │        │     ├─ Japan
│     │        │     ├─ Kwajalein
│     │        │     ├─ Libya
│     │        │     ├─ MET
│     │        │     ├─ MST
│     │        │     ├─ MST7MDT
│     │        │     ├─ Mexico
│     │        │     │  ├─ BajaNorte
│     │        │     │  ├─ BajaSur
│     │        │     │  └─ General
│     │        │     ├─ NZ
│     │        │     ├─ NZ-CHAT
│     │        │     ├─ Navajo
│     │        │     ├─ PRC
│     │        │     ├─ PST8PDT
│     │        │     ├─ Pacific
│     │        │     │  ├─ Apia
│     │        │     │  ├─ Auckland
│     │        │     │  ├─ Bougainville
│     │        │     │  ├─ Chatham
│     │        │     │  ├─ Chuuk
│     │        │     │  ├─ Easter
│     │        │     │  ├─ Efate
│     │        │     │  ├─ Enderbury
│     │        │     │  ├─ Fakaofo
│     │        │     │  ├─ Fiji
│     │        │     │  ├─ Funafuti
│     │        │     │  ├─ Galapagos
│     │        │     │  ├─ Gambier
│     │        │     │  ├─ Guadalcanal
│     │        │     │  ├─ Guam
│     │        │     │  ├─ Honolulu
│     │        │     │  ├─ Johnston
│     │        │     │  ├─ Kanton
│     │        │     │  ├─ Kiritimati
│     │        │     │  ├─ Kosrae
│     │        │     │  ├─ Kwajalein
│     │        │     │  ├─ Majuro
│     │        │     │  ├─ Marquesas
│     │        │     │  ├─ Midway
│     │        │     │  ├─ Nauru
│     │        │     │  ├─ Niue
│     │        │     │  ├─ Norfolk
│     │        │     │  ├─ Noumea
│     │        │     │  ├─ Pago_Pago
│     │        │     │  ├─ Palau
│     │        │     │  ├─ Pitcairn
│     │        │     │  ├─ Pohnpei
│     │        │     │  ├─ Ponape
│     │        │     │  ├─ Port_Moresby
│     │        │     │  ├─ Rarotonga
│     │        │     │  ├─ Saipan
│     │        │     │  ├─ Samoa
│     │        │     │  ├─ Tahiti
│     │        │     │  ├─ Tarawa
│     │        │     │  ├─ Tongatapu
│     │        │     │  ├─ Truk
│     │        │     │  ├─ Wake
│     │        │     │  ├─ Wallis
│     │        │     │  └─ Yap
│     │        │     ├─ Poland
│     │        │     ├─ Portugal
│     │        │     ├─ ROC
│     │        │     ├─ ROK
│     │        │     ├─ Singapore
│     │        │     ├─ Turkey
│     │        │     ├─ UCT
│     │        │     ├─ US
│     │        │     │  ├─ Alaska
│     │        │     │  ├─ Aleutian
│     │        │     │  ├─ Arizona
│     │        │     │  ├─ Central
│     │        │     │  ├─ East-Indiana
│     │        │     │  ├─ Eastern
│     │        │     │  ├─ Hawaii
│     │        │     │  ├─ Indiana-Starke
│     │        │     │  ├─ Michigan
│     │        │     │  ├─ Mountain
│     │        │     │  ├─ Pacific
│     │        │     │  └─ Samoa
│     │        │     ├─ UTC
│     │        │     ├─ Universal
│     │        │     ├─ W-SU
│     │        │     ├─ WET
│     │        │     ├─ Zulu
│     │        │     ├─ iso3166.tab
│     │        │     ├─ leapseconds
│     │        │     ├─ tzdata.zi
│     │        │     ├─ zone.tab
│     │        │     ├─ zone1970.tab
│     │        │     └─ zonenow.tab
│     │        ├─ pytz-2025.2.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ top_level.txt
│     │        │  └─ zip-safe
│     │        ├─ requests
│     │        │  ├─ __init__.py
│     │        │  ├─ __version__.py
│     │        │  ├─ _internal_utils.py
│     │        │  ├─ adapters.py
│     │        │  ├─ api.py
│     │        │  ├─ auth.py
│     │        │  ├─ certs.py
│     │        │  ├─ compat.py
│     │        │  ├─ cookies.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ help.py
│     │        │  ├─ hooks.py
│     │        │  ├─ models.py
│     │        │  ├─ packages.py
│     │        │  ├─ sessions.py
│     │        │  ├─ status_codes.py
│     │        │  ├─ structures.py
│     │        │  └─ utils.py
│     │        ├─ requests-2.32.4.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ ruamel
│     │        │  └─ yaml
│     │        │     ├─ __init__.py
│     │        │     ├─ anchor.py
│     │        │     ├─ comments.py
│     │        │     ├─ compat.py
│     │        │     ├─ composer.py
│     │        │     ├─ configobjwalker.py
│     │        │     ├─ constructor.py
│     │        │     ├─ cyaml.py
│     │        │     ├─ docinfo.py
│     │        │     ├─ dumper.py
│     │        │     ├─ emitter.py
│     │        │     ├─ error.py
│     │        │     ├─ events.py
│     │        │     ├─ loader.py
│     │        │     ├─ main.py
│     │        │     ├─ nodes.py
│     │        │     ├─ parser.py
│     │        │     ├─ py.typed
│     │        │     ├─ reader.py
│     │        │     ├─ representer.py
│     │        │     ├─ resolver.py
│     │        │     ├─ scalarbool.py
│     │        │     ├─ scalarfloat.py
│     │        │     ├─ scalarint.py
│     │        │     ├─ scalarstring.py
│     │        │     ├─ scanner.py
│     │        │     ├─ serializer.py
│     │        │     ├─ tag.py
│     │        │     ├─ timestamp.py
│     │        │     ├─ tokens.py
│     │        │     └─ util.py
│     │        ├─ ruamel.yaml-0.18.10.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ ruamel.yaml.clib-0.2.12.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ rust
│     │        │  ├─ Cargo.toml
│     │        │  ├─ cryptography-cffi
│     │        │  │  └─ Cargo.toml
│     │        │  ├─ cryptography-keepalive
│     │        │  │  └─ Cargo.toml
│     │        │  ├─ cryptography-key-parsing
│     │        │  │  └─ Cargo.toml
│     │        │  ├─ cryptography-openssl
│     │        │  │  └─ Cargo.toml
│     │        │  ├─ cryptography-x509
│     │        │  │  └─ Cargo.toml
│     │        │  └─ cryptography-x509-verification
│     │        │     └─ Cargo.toml
│     │        ├─ scikit_learn-1.7.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ COPYING
│     │        ├─ scipy
│     │        │  ├─ .dylibs
│     │        │  │  ├─ libgcc_s.1.1.dylib
│     │        │  │  ├─ libgfortran.5.dylib
│     │        │  │  └─ libquadmath.0.dylib
│     │        │  ├─ __config__.py
│     │        │  ├─ __init__.py
│     │        │  ├─ _cyutility.cpython-312-darwin.so
│     │        │  ├─ _distributor_init.py
│     │        │  ├─ _lib
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _array_api.py
│     │        │  │  ├─ _array_api_compat_vendor.py
│     │        │  │  ├─ _array_api_no_0d.py
│     │        │  │  ├─ _bunch.py
│     │        │  │  ├─ _ccallback.py
│     │        │  │  ├─ _ccallback_c.cpython-312-darwin.so
│     │        │  │  ├─ _disjoint_set.py
│     │        │  │  ├─ _docscrape.py
│     │        │  │  ├─ _elementwise_iterative_method.py
│     │        │  │  ├─ _fpumode.cpython-312-darwin.so
│     │        │  │  ├─ _gcutils.py
│     │        │  │  ├─ _pep440.py
│     │        │  │  ├─ _sparse.py
│     │        │  │  ├─ _test_ccallback.cpython-312-darwin.so
│     │        │  │  ├─ _test_deprecation_call.cpython-312-darwin.so
│     │        │  │  ├─ _test_deprecation_def.cpython-312-darwin.so
│     │        │  │  ├─ _testutils.py
│     │        │  │  ├─ _threadsafety.py
│     │        │  │  ├─ _tmpdirs.py
│     │        │  │  ├─ _uarray
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _backend.py
│     │        │  │  │  └─ _uarray.cpython-312-darwin.so
│     │        │  │  ├─ _util.py
│     │        │  │  ├─ array_api_compat
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _internal.py
│     │        │  │  │  ├─ common
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _aliases.py
│     │        │  │  │  │  ├─ _fft.py
│     │        │  │  │  │  ├─ _helpers.py
│     │        │  │  │  │  ├─ _linalg.py
│     │        │  │  │  │  └─ _typing.py
│     │        │  │  │  ├─ cupy
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _aliases.py
│     │        │  │  │  │  ├─ _info.py
│     │        │  │  │  │  ├─ _typing.py
│     │        │  │  │  │  ├─ fft.py
│     │        │  │  │  │  └─ linalg.py
│     │        │  │  │  ├─ dask
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ array
│     │        │  │  │  │     ├─ __init__.py
│     │        │  │  │  │     ├─ _aliases.py
│     │        │  │  │  │     ├─ _info.py
│     │        │  │  │  │     ├─ fft.py
│     │        │  │  │  │     └─ linalg.py
│     │        │  │  │  ├─ numpy
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _aliases.py
│     │        │  │  │  │  ├─ _info.py
│     │        │  │  │  │  ├─ _typing.py
│     │        │  │  │  │  ├─ fft.py
│     │        │  │  │  │  └─ linalg.py
│     │        │  │  │  └─ torch
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ _aliases.py
│     │        │  │  │     ├─ _info.py
│     │        │  │  │     ├─ _typing.py
│     │        │  │  │     ├─ fft.py
│     │        │  │  │     └─ linalg.py
│     │        │  │  ├─ array_api_extra
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _delegation.py
│     │        │  │  │  ├─ _lib
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _at.py
│     │        │  │  │  │  ├─ _backends.py
│     │        │  │  │  │  ├─ _funcs.py
│     │        │  │  │  │  ├─ _lazy.py
│     │        │  │  │  │  ├─ _testing.py
│     │        │  │  │  │  └─ _utils
│     │        │  │  │  │     ├─ __init__.py
│     │        │  │  │  │     ├─ _compat.py
│     │        │  │  │  │     ├─ _compat.pyi
│     │        │  │  │  │     ├─ _helpers.py
│     │        │  │  │  │     ├─ _typing.py
│     │        │  │  │  │     └─ _typing.pyi
│     │        │  │  │  └─ testing.py
│     │        │  │  ├─ cobyqa
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ framework.py
│     │        │  │  │  ├─ main.py
│     │        │  │  │  ├─ models.py
│     │        │  │  │  ├─ problem.py
│     │        │  │  │  ├─ settings.py
│     │        │  │  │  ├─ subsolvers
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ geometry.py
│     │        │  │  │  │  └─ optim.py
│     │        │  │  │  └─ utils
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ exceptions.py
│     │        │  │  │     ├─ math.py
│     │        │  │  │     └─ versions.py
│     │        │  │  ├─ decorator.py
│     │        │  │  ├─ deprecation.py
│     │        │  │  ├─ doccer.py
│     │        │  │  ├─ messagestream.cpython-312-darwin.so
│     │        │  │  ├─ pyprima
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ cobyla
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ cobyla.py
│     │        │  │  │  │  ├─ cobylb.py
│     │        │  │  │  │  ├─ geometry.py
│     │        │  │  │  │  ├─ initialize.py
│     │        │  │  │  │  ├─ trustregion.py
│     │        │  │  │  │  └─ update.py
│     │        │  │  │  └─ common
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ _bounds.py
│     │        │  │  │     ├─ _linear_constraints.py
│     │        │  │  │     ├─ _nonlinear_constraints.py
│     │        │  │  │     ├─ _project.py
│     │        │  │  │     ├─ checkbreak.py
│     │        │  │  │     ├─ consts.py
│     │        │  │  │     ├─ evaluate.py
│     │        │  │  │     ├─ history.py
│     │        │  │  │     ├─ infos.py
│     │        │  │  │     ├─ linalg.py
│     │        │  │  │     ├─ message.py
│     │        │  │  │     ├─ powalg.py
│     │        │  │  │     ├─ preproc.py
│     │        │  │  │     ├─ present.py
│     │        │  │  │     ├─ ratio.py
│     │        │  │  │     ├─ redrho.py
│     │        │  │  │     └─ selectx.py
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test__gcutils.py
│     │        │  │  │  ├─ test__pep440.py
│     │        │  │  │  ├─ test__testutils.py
│     │        │  │  │  ├─ test__threadsafety.py
│     │        │  │  │  ├─ test__util.py
│     │        │  │  │  ├─ test_array_api.py
│     │        │  │  │  ├─ test_bunch.py
│     │        │  │  │  ├─ test_ccallback.py
│     │        │  │  │  ├─ test_config.py
│     │        │  │  │  ├─ test_deprecation.py
│     │        │  │  │  ├─ test_doccer.py
│     │        │  │  │  ├─ test_import_cycles.py
│     │        │  │  │  ├─ test_public_api.py
│     │        │  │  │  ├─ test_scipy_version.py
│     │        │  │  │  ├─ test_tmpdirs.py
│     │        │  │  │  └─ test_warnings.py
│     │        │  │  └─ uarray.py
│     │        │  ├─ cluster
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _hierarchy.cpython-312-darwin.so
│     │        │  │  ├─ _optimal_leaf_ordering.cpython-312-darwin.so
│     │        │  │  ├─ _vq.cpython-312-darwin.so
│     │        │  │  ├─ hierarchy.py
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ hierarchy_test_data.py
│     │        │  │  │  ├─ test_disjoint_set.py
│     │        │  │  │  ├─ test_hierarchy.py
│     │        │  │  │  └─ test_vq.py
│     │        │  │  └─ vq.py
│     │        │  ├─ conftest.py
│     │        │  ├─ constants
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _codata.py
│     │        │  │  ├─ _constants.py
│     │        │  │  ├─ codata.py
│     │        │  │  ├─ constants.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_codata.py
│     │        │  │     └─ test_constants.py
│     │        │  ├─ datasets
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _download_all.py
│     │        │  │  ├─ _fetchers.py
│     │        │  │  ├─ _registry.py
│     │        │  │  ├─ _utils.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     └─ test_data.py
│     │        │  ├─ differentiate
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _differentiate.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     └─ test_differentiate.py
│     │        │  ├─ fft
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _backend.py
│     │        │  │  ├─ _basic.py
│     │        │  │  ├─ _basic_backend.py
│     │        │  │  ├─ _debug_backends.py
│     │        │  │  ├─ _fftlog.py
│     │        │  │  ├─ _fftlog_backend.py
│     │        │  │  ├─ _helper.py
│     │        │  │  ├─ _pocketfft
│     │        │  │  │  ├─ LICENSE.md
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ basic.py
│     │        │  │  │  ├─ helper.py
│     │        │  │  │  ├─ pypocketfft.cpython-312-darwin.so
│     │        │  │  │  ├─ realtransforms.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_basic.py
│     │        │  │  │     └─ test_real_transforms.py
│     │        │  │  ├─ _realtransforms.py
│     │        │  │  ├─ _realtransforms_backend.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ mock_backend.py
│     │        │  │     ├─ test_backend.py
│     │        │  │     ├─ test_basic.py
│     │        │  │     ├─ test_fftlog.py
│     │        │  │     ├─ test_helper.py
│     │        │  │     ├─ test_multithreading.py
│     │        │  │     └─ test_real_transforms.py
│     │        │  ├─ fftpack
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _basic.py
│     │        │  │  ├─ _helper.py
│     │        │  │  ├─ _pseudo_diffs.py
│     │        │  │  ├─ _realtransforms.py
│     │        │  │  ├─ basic.py
│     │        │  │  ├─ convolve.cpython-312-darwin.so
│     │        │  │  ├─ helper.py
│     │        │  │  ├─ pseudo_diffs.py
│     │        │  │  ├─ realtransforms.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ fftw_double_ref.npz
│     │        │  │     ├─ fftw_longdouble_ref.npz
│     │        │  │     ├─ fftw_single_ref.npz
│     │        │  │     ├─ test.npz
│     │        │  │     ├─ test_basic.py
│     │        │  │     ├─ test_helper.py
│     │        │  │     ├─ test_import.py
│     │        │  │     ├─ test_pseudo_diffs.py
│     │        │  │     └─ test_real_transforms.py
│     │        │  ├─ integrate
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _bvp.py
│     │        │  │  ├─ _cubature.py
│     │        │  │  ├─ _dop.cpython-312-darwin.so
│     │        │  │  ├─ _ivp
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ bdf.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ dop853_coefficients.py
│     │        │  │  │  ├─ ivp.py
│     │        │  │  │  ├─ lsoda.py
│     │        │  │  │  ├─ radau.py
│     │        │  │  │  ├─ rk.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_ivp.py
│     │        │  │  │     └─ test_rk.py
│     │        │  │  ├─ _lebedev.py
│     │        │  │  ├─ _lsoda.cpython-312-darwin.so
│     │        │  │  ├─ _ode.py
│     │        │  │  ├─ _odepack.cpython-312-darwin.so
│     │        │  │  ├─ _odepack_py.py
│     │        │  │  ├─ _quad_vec.py
│     │        │  │  ├─ _quadpack.cpython-312-darwin.so
│     │        │  │  ├─ _quadpack_py.py
│     │        │  │  ├─ _quadrature.py
│     │        │  │  ├─ _rules
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _base.py
│     │        │  │  │  ├─ _gauss_kronrod.py
│     │        │  │  │  ├─ _gauss_legendre.py
│     │        │  │  │  └─ _genz_malik.py
│     │        │  │  ├─ _tanhsinh.py
│     │        │  │  ├─ _test_multivariate.cpython-312-darwin.so
│     │        │  │  ├─ _test_odeint_banded.cpython-312-darwin.so
│     │        │  │  ├─ _vode.cpython-312-darwin.so
│     │        │  │  ├─ dop.py
│     │        │  │  ├─ lsoda.py
│     │        │  │  ├─ odepack.py
│     │        │  │  ├─ quadpack.py
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test__quad_vec.py
│     │        │  │  │  ├─ test_banded_ode_solvers.py
│     │        │  │  │  ├─ test_bvp.py
│     │        │  │  │  ├─ test_cubature.py
│     │        │  │  │  ├─ test_integrate.py
│     │        │  │  │  ├─ test_odeint_jac.py
│     │        │  │  │  ├─ test_quadpack.py
│     │        │  │  │  ├─ test_quadrature.py
│     │        │  │  │  └─ test_tanhsinh.py
│     │        │  │  └─ vode.py
│     │        │  ├─ interpolate
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _bary_rational.py
│     │        │  │  ├─ _bsplines.py
│     │        │  │  ├─ _cubic.py
│     │        │  │  ├─ _dfitpack.cpython-312-darwin.so
│     │        │  │  ├─ _dierckx.cpython-312-darwin.so
│     │        │  │  ├─ _fitpack.cpython-312-darwin.so
│     │        │  │  ├─ _fitpack2.py
│     │        │  │  ├─ _fitpack_impl.py
│     │        │  │  ├─ _fitpack_py.py
│     │        │  │  ├─ _fitpack_repro.py
│     │        │  │  ├─ _interpnd.cpython-312-darwin.so
│     │        │  │  ├─ _interpolate.py
│     │        │  │  ├─ _ndbspline.py
│     │        │  │  ├─ _ndgriddata.py
│     │        │  │  ├─ _pade.py
│     │        │  │  ├─ _polyint.py
│     │        │  │  ├─ _ppoly.cpython-312-darwin.so
│     │        │  │  ├─ _rbf.py
│     │        │  │  ├─ _rbfinterp.py
│     │        │  │  ├─ _rbfinterp_pythran.cpython-312-darwin.so
│     │        │  │  ├─ _rgi.py
│     │        │  │  ├─ _rgi_cython.cpython-312-darwin.so
│     │        │  │  ├─ dfitpack.py
│     │        │  │  ├─ fitpack.py
│     │        │  │  ├─ fitpack2.py
│     │        │  │  ├─ interpnd.py
│     │        │  │  ├─ interpolate.py
│     │        │  │  ├─ ndgriddata.py
│     │        │  │  ├─ polyint.py
│     │        │  │  ├─ rbf.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_bary_rational.py
│     │        │  │     ├─ test_bsplines.py
│     │        │  │     ├─ test_fitpack.py
│     │        │  │     ├─ test_fitpack2.py
│     │        │  │     ├─ test_gil.py
│     │        │  │     ├─ test_interpnd.py
│     │        │  │     ├─ test_interpolate.py
│     │        │  │     ├─ test_ndgriddata.py
│     │        │  │     ├─ test_pade.py
│     │        │  │     ├─ test_polyint.py
│     │        │  │     ├─ test_rbf.py
│     │        │  │     ├─ test_rbfinterp.py
│     │        │  │     └─ test_rgi.py
│     │        │  ├─ io
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _fast_matrix_market
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ _fmm_core.cpython-312-darwin.so
│     │        │  │  ├─ _fortran.py
│     │        │  │  ├─ _harwell_boeing
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _fortran_format_parser.py
│     │        │  │  │  ├─ hb.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_fortran_format.py
│     │        │  │  │     └─ test_hb.py
│     │        │  │  ├─ _idl.py
│     │        │  │  ├─ _mmio.py
│     │        │  │  ├─ _netcdf.py
│     │        │  │  ├─ _test_fortran.cpython-312-darwin.so
│     │        │  │  ├─ arff
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _arffread.py
│     │        │  │  │  ├─ arffread.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     └─ test_arffread.py
│     │        │  │  ├─ harwell_boeing.py
│     │        │  │  ├─ idl.py
│     │        │  │  ├─ matlab
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _byteordercodes.py
│     │        │  │  │  ├─ _mio.py
│     │        │  │  │  ├─ _mio4.py
│     │        │  │  │  ├─ _mio5.py
│     │        │  │  │  ├─ _mio5_params.py
│     │        │  │  │  ├─ _mio5_utils.cpython-312-darwin.so
│     │        │  │  │  ├─ _mio_utils.cpython-312-darwin.so
│     │        │  │  │  ├─ _miobase.py
│     │        │  │  │  ├─ _streams.cpython-312-darwin.so
│     │        │  │  │  ├─ byteordercodes.py
│     │        │  │  │  ├─ mio.py
│     │        │  │  │  ├─ mio4.py
│     │        │  │  │  ├─ mio5.py
│     │        │  │  │  ├─ mio5_params.py
│     │        │  │  │  ├─ mio5_utils.py
│     │        │  │  │  ├─ mio_utils.py
│     │        │  │  │  ├─ miobase.py
│     │        │  │  │  ├─ streams.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_byteordercodes.py
│     │        │  │  │     ├─ test_mio.py
│     │        │  │  │     ├─ test_mio5_utils.py
│     │        │  │  │     ├─ test_mio_funcs.py
│     │        │  │  │     ├─ test_mio_utils.py
│     │        │  │  │     ├─ test_miobase.py
│     │        │  │  │     ├─ test_pathological.py
│     │        │  │  │     └─ test_streams.py
│     │        │  │  ├─ mmio.py
│     │        │  │  ├─ netcdf.py
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_fortran.py
│     │        │  │  │  ├─ test_idl.py
│     │        │  │  │  ├─ test_mmio.py
│     │        │  │  │  ├─ test_netcdf.py
│     │        │  │  │  ├─ test_paths.py
│     │        │  │  │  └─ test_wavfile.py
│     │        │  │  └─ wavfile.py
│     │        │  ├─ linalg
│     │        │  │  ├─ __init__.pxd
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _basic.py
│     │        │  │  ├─ _blas_subroutines.h
│     │        │  │  ├─ _cythonized_array_utils.cpython-312-darwin.so
│     │        │  │  ├─ _cythonized_array_utils.pxd
│     │        │  │  ├─ _cythonized_array_utils.pyi
│     │        │  │  ├─ _decomp.py
│     │        │  │  ├─ _decomp_cholesky.py
│     │        │  │  ├─ _decomp_cossin.py
│     │        │  │  ├─ _decomp_interpolative.cpython-312-darwin.so
│     │        │  │  ├─ _decomp_ldl.py
│     │        │  │  ├─ _decomp_lu.py
│     │        │  │  ├─ _decomp_lu_cython.cpython-312-darwin.so
│     │        │  │  ├─ _decomp_lu_cython.pyi
│     │        │  │  ├─ _decomp_polar.py
│     │        │  │  ├─ _decomp_qr.py
│     │        │  │  ├─ _decomp_qz.py
│     │        │  │  ├─ _decomp_schur.py
│     │        │  │  ├─ _decomp_svd.py
│     │        │  │  ├─ _decomp_update.cpython-312-darwin.so
│     │        │  │  ├─ _expm_frechet.py
│     │        │  │  ├─ _fblas.cpython-312-darwin.so
│     │        │  │  ├─ _flapack.cpython-312-darwin.so
│     │        │  │  ├─ _lapack_subroutines.h
│     │        │  │  ├─ _linalg_pythran.cpython-312-darwin.so
│     │        │  │  ├─ _matfuncs.py
│     │        │  │  ├─ _matfuncs_expm.cpython-312-darwin.so
│     │        │  │  ├─ _matfuncs_expm.pyi
│     │        │  │  ├─ _matfuncs_inv_ssq.py
│     │        │  │  ├─ _matfuncs_schur_sqrtm.cpython-312-darwin.so
│     │        │  │  ├─ _matfuncs_sqrtm.py
│     │        │  │  ├─ _matfuncs_sqrtm_triu.cpython-312-darwin.so
│     │        │  │  ├─ _misc.py
│     │        │  │  ├─ _procrustes.py
│     │        │  │  ├─ _sketches.py
│     │        │  │  ├─ _solve_toeplitz.cpython-312-darwin.so
│     │        │  │  ├─ _solvers.py
│     │        │  │  ├─ _special_matrices.py
│     │        │  │  ├─ _testutils.py
│     │        │  │  ├─ basic.py
│     │        │  │  ├─ blas.py
│     │        │  │  ├─ cython_blas.cpython-312-darwin.so
│     │        │  │  ├─ cython_blas.pxd
│     │        │  │  ├─ cython_blas.pyx
│     │        │  │  ├─ cython_lapack.cpython-312-darwin.so
│     │        │  │  ├─ cython_lapack.pxd
│     │        │  │  ├─ cython_lapack.pyx
│     │        │  │  ├─ decomp.py
│     │        │  │  ├─ decomp_cholesky.py
│     │        │  │  ├─ decomp_lu.py
│     │        │  │  ├─ decomp_qr.py
│     │        │  │  ├─ decomp_schur.py
│     │        │  │  ├─ decomp_svd.py
│     │        │  │  ├─ interpolative.py
│     │        │  │  ├─ lapack.py
│     │        │  │  ├─ matfuncs.py
│     │        │  │  ├─ misc.py
│     │        │  │  ├─ special_matrices.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ _cython_examples
│     │        │  │     │  ├─ extending.pyx
│     │        │  │     │  └─ meson.build
│     │        │  │     ├─ test_basic.py
│     │        │  │     ├─ test_batch.py
│     │        │  │     ├─ test_blas.py
│     │        │  │     ├─ test_cython_blas.py
│     │        │  │     ├─ test_cython_lapack.py
│     │        │  │     ├─ test_cythonized_array_utils.py
│     │        │  │     ├─ test_decomp.py
│     │        │  │     ├─ test_decomp_cholesky.py
│     │        │  │     ├─ test_decomp_cossin.py
│     │        │  │     ├─ test_decomp_ldl.py
│     │        │  │     ├─ test_decomp_lu.py
│     │        │  │     ├─ test_decomp_polar.py
│     │        │  │     ├─ test_decomp_update.py
│     │        │  │     ├─ test_extending.py
│     │        │  │     ├─ test_fblas.py
│     │        │  │     ├─ test_interpolative.py
│     │        │  │     ├─ test_lapack.py
│     │        │  │     ├─ test_matfuncs.py
│     │        │  │     ├─ test_matmul_toeplitz.py
│     │        │  │     ├─ test_procrustes.py
│     │        │  │     ├─ test_sketches.py
│     │        │  │     ├─ test_solve_toeplitz.py
│     │        │  │     ├─ test_solvers.py
│     │        │  │     └─ test_special_matrices.py
│     │        │  ├─ misc
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ common.py
│     │        │  │  └─ doccer.py
│     │        │  ├─ ndimage
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _ctest.cpython-312-darwin.so
│     │        │  │  ├─ _cytest.cpython-312-darwin.so
│     │        │  │  ├─ _delegators.py
│     │        │  │  ├─ _filters.py
│     │        │  │  ├─ _fourier.py
│     │        │  │  ├─ _interpolation.py
│     │        │  │  ├─ _measurements.py
│     │        │  │  ├─ _morphology.py
│     │        │  │  ├─ _nd_image.cpython-312-darwin.so
│     │        │  │  ├─ _ndimage_api.py
│     │        │  │  ├─ _ni_docstrings.py
│     │        │  │  ├─ _ni_label.cpython-312-darwin.so
│     │        │  │  ├─ _ni_support.py
│     │        │  │  ├─ _rank_filter_1d.cpython-312-darwin.so
│     │        │  │  ├─ _support_alternative_backends.py
│     │        │  │  ├─ filters.py
│     │        │  │  ├─ fourier.py
│     │        │  │  ├─ interpolation.py
│     │        │  │  ├─ measurements.py
│     │        │  │  ├─ morphology.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ dots.png
│     │        │  │     ├─ test_c_api.py
│     │        │  │     ├─ test_datatypes.py
│     │        │  │     ├─ test_filters.py
│     │        │  │     ├─ test_fourier.py
│     │        │  │     ├─ test_interpolation.py
│     │        │  │     ├─ test_measurements.py
│     │        │  │     ├─ test_morphology.py
│     │        │  │     ├─ test_ni_support.py
│     │        │  │     └─ test_splines.py
│     │        │  ├─ odr
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __odrpack.cpython-312-darwin.so
│     │        │  │  ├─ _add_newdocs.py
│     │        │  │  ├─ _models.py
│     │        │  │  ├─ _odrpack.py
│     │        │  │  ├─ models.py
│     │        │  │  ├─ odrpack.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     └─ test_odr.py
│     │        │  ├─ optimize
│     │        │  │  ├─ __init__.pxd
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _basinhopping.py
│     │        │  │  ├─ _bglu_dense.cpython-312-darwin.so
│     │        │  │  ├─ _bracket.py
│     │        │  │  ├─ _chandrupatla.py
│     │        │  │  ├─ _cobyla_py.py
│     │        │  │  ├─ _cobyqa_py.py
│     │        │  │  ├─ _constraints.py
│     │        │  │  ├─ _dcsrch.py
│     │        │  │  ├─ _differentiable_functions.py
│     │        │  │  ├─ _differentialevolution.py
│     │        │  │  ├─ _direct.cpython-312-darwin.so
│     │        │  │  ├─ _direct_py.py
│     │        │  │  ├─ _dual_annealing.py
│     │        │  │  ├─ _elementwise.py
│     │        │  │  ├─ _group_columns.cpython-312-darwin.so
│     │        │  │  ├─ _hessian_update_strategy.py
│     │        │  │  ├─ _highspy
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _core.cpython-312-darwin.so
│     │        │  │  │  ├─ _highs_options.cpython-312-darwin.so
│     │        │  │  │  └─ _highs_wrapper.py
│     │        │  │  ├─ _isotonic.py
│     │        │  │  ├─ _lbfgsb.cpython-312-darwin.so
│     │        │  │  ├─ _lbfgsb_py.py
│     │        │  │  ├─ _linesearch.py
│     │        │  │  ├─ _linprog.py
│     │        │  │  ├─ _linprog_doc.py
│     │        │  │  ├─ _linprog_highs.py
│     │        │  │  ├─ _linprog_ip.py
│     │        │  │  ├─ _linprog_rs.py
│     │        │  │  ├─ _linprog_simplex.py
│     │        │  │  ├─ _linprog_util.py
│     │        │  │  ├─ _lsap.cpython-312-darwin.so
│     │        │  │  ├─ _lsq
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ bvls.py
│     │        │  │  │  ├─ common.py
│     │        │  │  │  ├─ dogbox.py
│     │        │  │  │  ├─ givens_elimination.cpython-312-darwin.so
│     │        │  │  │  ├─ least_squares.py
│     │        │  │  │  ├─ lsq_linear.py
│     │        │  │  │  ├─ trf.py
│     │        │  │  │  └─ trf_linear.py
│     │        │  │  ├─ _milp.py
│     │        │  │  ├─ _minimize.py
│     │        │  │  ├─ _minpack.cpython-312-darwin.so
│     │        │  │  ├─ _minpack_py.py
│     │        │  │  ├─ _moduleTNC.cpython-312-darwin.so
│     │        │  │  ├─ _nnls.py
│     │        │  │  ├─ _nonlin.py
│     │        │  │  ├─ _numdiff.py
│     │        │  │  ├─ _optimize.py
│     │        │  │  ├─ _pava_pybind.cpython-312-darwin.so
│     │        │  │  ├─ _qap.py
│     │        │  │  ├─ _remove_redundancy.py
│     │        │  │  ├─ _root.py
│     │        │  │  ├─ _root_scalar.py
│     │        │  │  ├─ _shgo.py
│     │        │  │  ├─ _shgo_lib
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _complex.py
│     │        │  │  │  └─ _vertex.py
│     │        │  │  ├─ _slsqp_py.py
│     │        │  │  ├─ _slsqplib.cpython-312-darwin.so
│     │        │  │  ├─ _spectral.py
│     │        │  │  ├─ _tnc.py
│     │        │  │  ├─ _trlib
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ _trlib.cpython-312-darwin.so
│     │        │  │  ├─ _trustregion.py
│     │        │  │  ├─ _trustregion_constr
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ canonical_constraint.py
│     │        │  │  │  ├─ equality_constrained_sqp.py
│     │        │  │  │  ├─ minimize_trustregion_constr.py
│     │        │  │  │  ├─ projections.py
│     │        │  │  │  ├─ qp_subproblem.py
│     │        │  │  │  ├─ report.py
│     │        │  │  │  ├─ tests
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_canonical_constraint.py
│     │        │  │  │  │  ├─ test_nested_minimize.py
│     │        │  │  │  │  ├─ test_projections.py
│     │        │  │  │  │  ├─ test_qp_subproblem.py
│     │        │  │  │  │  └─ test_report.py
│     │        │  │  │  └─ tr_interior_point.py
│     │        │  │  ├─ _trustregion_dogleg.py
│     │        │  │  ├─ _trustregion_exact.py
│     │        │  │  ├─ _trustregion_krylov.py
│     │        │  │  ├─ _trustregion_ncg.py
│     │        │  │  ├─ _tstutils.py
│     │        │  │  ├─ _zeros.cpython-312-darwin.so
│     │        │  │  ├─ _zeros_py.py
│     │        │  │  ├─ cobyla.py
│     │        │  │  ├─ cython_optimize
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _zeros.cpython-312-darwin.so
│     │        │  │  │  ├─ _zeros.pxd
│     │        │  │  │  └─ c_zeros.pxd
│     │        │  │  ├─ cython_optimize.pxd
│     │        │  │  ├─ elementwise.py
│     │        │  │  ├─ lbfgsb.py
│     │        │  │  ├─ linesearch.py
│     │        │  │  ├─ minpack.py
│     │        │  │  ├─ minpack2.py
│     │        │  │  ├─ moduleTNC.py
│     │        │  │  ├─ nonlin.py
│     │        │  │  ├─ optimize.py
│     │        │  │  ├─ slsqp.py
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _cython_examples
│     │        │  │  │  │  ├─ extending.pyx
│     │        │  │  │  │  └─ meson.build
│     │        │  │  │  ├─ test__basinhopping.py
│     │        │  │  │  ├─ test__differential_evolution.py
│     │        │  │  │  ├─ test__dual_annealing.py
│     │        │  │  │  ├─ test__linprog_clean_inputs.py
│     │        │  │  │  ├─ test__numdiff.py
│     │        │  │  │  ├─ test__remove_redundancy.py
│     │        │  │  │  ├─ test__root.py
│     │        │  │  │  ├─ test__shgo.py
│     │        │  │  │  ├─ test__spectral.py
│     │        │  │  │  ├─ test_bracket.py
│     │        │  │  │  ├─ test_chandrupatla.py
│     │        │  │  │  ├─ test_cobyla.py
│     │        │  │  │  ├─ test_cobyqa.py
│     │        │  │  │  ├─ test_constraint_conversion.py
│     │        │  │  │  ├─ test_constraints.py
│     │        │  │  │  ├─ test_cython_optimize.py
│     │        │  │  │  ├─ test_differentiable_functions.py
│     │        │  │  │  ├─ test_direct.py
│     │        │  │  │  ├─ test_extending.py
│     │        │  │  │  ├─ test_hessian_update_strategy.py
│     │        │  │  │  ├─ test_isotonic_regression.py
│     │        │  │  │  ├─ test_lbfgsb_hessinv.py
│     │        │  │  │  ├─ test_lbfgsb_setulb.py
│     │        │  │  │  ├─ test_least_squares.py
│     │        │  │  │  ├─ test_linear_assignment.py
│     │        │  │  │  ├─ test_linesearch.py
│     │        │  │  │  ├─ test_linprog.py
│     │        │  │  │  ├─ test_lsq_common.py
│     │        │  │  │  ├─ test_lsq_linear.py
│     │        │  │  │  ├─ test_milp.py
│     │        │  │  │  ├─ test_minimize_constrained.py
│     │        │  │  │  ├─ test_minpack.py
│     │        │  │  │  ├─ test_nnls.py
│     │        │  │  │  ├─ test_nonlin.py
│     │        │  │  │  ├─ test_optimize.py
│     │        │  │  │  ├─ test_quadratic_assignment.py
│     │        │  │  │  ├─ test_regression.py
│     │        │  │  │  ├─ test_slsqp.py
│     │        │  │  │  ├─ test_tnc.py
│     │        │  │  │  ├─ test_trustregion.py
│     │        │  │  │  ├─ test_trustregion_exact.py
│     │        │  │  │  ├─ test_trustregion_krylov.py
│     │        │  │  │  └─ test_zeros.py
│     │        │  │  ├─ tnc.py
│     │        │  │  └─ zeros.py
│     │        │  ├─ signal
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _arraytools.py
│     │        │  │  ├─ _czt.py
│     │        │  │  ├─ _delegators.py
│     │        │  │  ├─ _filter_design.py
│     │        │  │  ├─ _fir_filter_design.py
│     │        │  │  ├─ _lti_conversion.py
│     │        │  │  ├─ _ltisys.py
│     │        │  │  ├─ _max_len_seq.py
│     │        │  │  ├─ _max_len_seq_inner.cpython-312-darwin.so
│     │        │  │  ├─ _peak_finding.py
│     │        │  │  ├─ _peak_finding_utils.cpython-312-darwin.so
│     │        │  │  ├─ _polyutils.py
│     │        │  │  ├─ _savitzky_golay.py
│     │        │  │  ├─ _short_time_fft.py
│     │        │  │  ├─ _signal_api.py
│     │        │  │  ├─ _signaltools.py
│     │        │  │  ├─ _sigtools.cpython-312-darwin.so
│     │        │  │  ├─ _sosfilt.cpython-312-darwin.so
│     │        │  │  ├─ _spectral_py.py
│     │        │  │  ├─ _spline.cpython-312-darwin.so
│     │        │  │  ├─ _spline.pyi
│     │        │  │  ├─ _spline_filters.py
│     │        │  │  ├─ _support_alternative_backends.py
│     │        │  │  ├─ _upfirdn.py
│     │        │  │  ├─ _upfirdn_apply.cpython-312-darwin.so
│     │        │  │  ├─ _waveforms.py
│     │        │  │  ├─ _wavelets.py
│     │        │  │  ├─ bsplines.py
│     │        │  │  ├─ filter_design.py
│     │        │  │  ├─ fir_filter_design.py
│     │        │  │  ├─ lti_conversion.py
│     │        │  │  ├─ ltisys.py
│     │        │  │  ├─ signaltools.py
│     │        │  │  ├─ spectral.py
│     │        │  │  ├─ spline.py
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _scipy_spectral_test_shim.py
│     │        │  │  │  ├─ mpsig.py
│     │        │  │  │  ├─ test_array_tools.py
│     │        │  │  │  ├─ test_bsplines.py
│     │        │  │  │  ├─ test_cont2discrete.py
│     │        │  │  │  ├─ test_czt.py
│     │        │  │  │  ├─ test_dltisys.py
│     │        │  │  │  ├─ test_filter_design.py
│     │        │  │  │  ├─ test_fir_filter_design.py
│     │        │  │  │  ├─ test_ltisys.py
│     │        │  │  │  ├─ test_max_len_seq.py
│     │        │  │  │  ├─ test_peak_finding.py
│     │        │  │  │  ├─ test_result_type.py
│     │        │  │  │  ├─ test_savitzky_golay.py
│     │        │  │  │  ├─ test_short_time_fft.py
│     │        │  │  │  ├─ test_signaltools.py
│     │        │  │  │  ├─ test_spectral.py
│     │        │  │  │  ├─ test_splines.py
│     │        │  │  │  ├─ test_upfirdn.py
│     │        │  │  │  ├─ test_waveforms.py
│     │        │  │  │  ├─ test_wavelets.py
│     │        │  │  │  └─ test_windows.py
│     │        │  │  ├─ waveforms.py
│     │        │  │  ├─ wavelets.py
│     │        │  │  └─ windows
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ _windows.py
│     │        │  │     └─ windows.py
│     │        │  ├─ sparse
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _bsr.py
│     │        │  │  ├─ _compressed.py
│     │        │  │  ├─ _construct.py
│     │        │  │  ├─ _coo.py
│     │        │  │  ├─ _csc.py
│     │        │  │  ├─ _csparsetools.cpython-312-darwin.so
│     │        │  │  ├─ _csr.py
│     │        │  │  ├─ _data.py
│     │        │  │  ├─ _dia.py
│     │        │  │  ├─ _dok.py
│     │        │  │  ├─ _extract.py
│     │        │  │  ├─ _index.py
│     │        │  │  ├─ _lil.py
│     │        │  │  ├─ _matrix.py
│     │        │  │  ├─ _matrix_io.py
│     │        │  │  ├─ _sparsetools.cpython-312-darwin.so
│     │        │  │  ├─ _spfuncs.py
│     │        │  │  ├─ _sputils.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ bsr.py
│     │        │  │  ├─ compressed.py
│     │        │  │  ├─ construct.py
│     │        │  │  ├─ coo.py
│     │        │  │  ├─ csc.py
│     │        │  │  ├─ csgraph
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _flow.cpython-312-darwin.so
│     │        │  │  │  ├─ _laplacian.py
│     │        │  │  │  ├─ _matching.cpython-312-darwin.so
│     │        │  │  │  ├─ _min_spanning_tree.cpython-312-darwin.so
│     │        │  │  │  ├─ _reordering.cpython-312-darwin.so
│     │        │  │  │  ├─ _shortest_path.cpython-312-darwin.so
│     │        │  │  │  ├─ _tools.cpython-312-darwin.so
│     │        │  │  │  ├─ _traversal.cpython-312-darwin.so
│     │        │  │  │  ├─ _validation.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_connected_components.py
│     │        │  │  │     ├─ test_conversions.py
│     │        │  │  │     ├─ test_flow.py
│     │        │  │  │     ├─ test_graph_laplacian.py
│     │        │  │  │     ├─ test_matching.py
│     │        │  │  │     ├─ test_pydata_sparse.py
│     │        │  │  │     ├─ test_reordering.py
│     │        │  │  │     ├─ test_shortest_path.py
│     │        │  │  │     ├─ test_spanning_tree.py
│     │        │  │  │     └─ test_traversal.py
│     │        │  │  ├─ csr.py
│     │        │  │  ├─ data.py
│     │        │  │  ├─ dia.py
│     │        │  │  ├─ dok.py
│     │        │  │  ├─ extract.py
│     │        │  │  ├─ lil.py
│     │        │  │  ├─ linalg
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _dsolve
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _add_newdocs.py
│     │        │  │  │  │  ├─ _superlu.cpython-312-darwin.so
│     │        │  │  │  │  ├─ linsolve.py
│     │        │  │  │  │  └─ tests
│     │        │  │  │  │     ├─ __init__.py
│     │        │  │  │  │     └─ test_linsolve.py
│     │        │  │  │  ├─ _eigen
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _svds.py
│     │        │  │  │  │  ├─ _svds_doc.py
│     │        │  │  │  │  ├─ arpack
│     │        │  │  │  │  │  ├─ COPYING
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ _arpack.cpython-312-darwin.so
│     │        │  │  │  │  │  ├─ arpack.py
│     │        │  │  │  │  │  └─ tests
│     │        │  │  │  │  │     ├─ __init__.py
│     │        │  │  │  │  │     └─ test_arpack.py
│     │        │  │  │  │  ├─ lobpcg
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ lobpcg.py
│     │        │  │  │  │  │  └─ tests
│     │        │  │  │  │  │     ├─ __init__.py
│     │        │  │  │  │  │     └─ test_lobpcg.py
│     │        │  │  │  │  └─ tests
│     │        │  │  │  │     ├─ __init__.py
│     │        │  │  │  │     └─ test_svds.py
│     │        │  │  │  ├─ _expm_multiply.py
│     │        │  │  │  ├─ _interface.py
│     │        │  │  │  ├─ _isolve
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _gcrotmk.py
│     │        │  │  │  │  ├─ iterative.py
│     │        │  │  │  │  ├─ lgmres.py
│     │        │  │  │  │  ├─ lsmr.py
│     │        │  │  │  │  ├─ lsqr.py
│     │        │  │  │  │  ├─ minres.py
│     │        │  │  │  │  ├─ tests
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ test_gcrotmk.py
│     │        │  │  │  │  │  ├─ test_iterative.py
│     │        │  │  │  │  │  ├─ test_lgmres.py
│     │        │  │  │  │  │  ├─ test_lsmr.py
│     │        │  │  │  │  │  ├─ test_lsqr.py
│     │        │  │  │  │  │  ├─ test_minres.py
│     │        │  │  │  │  │  └─ test_utils.py
│     │        │  │  │  │  ├─ tfqmr.py
│     │        │  │  │  │  └─ utils.py
│     │        │  │  │  ├─ _matfuncs.py
│     │        │  │  │  ├─ _norm.py
│     │        │  │  │  ├─ _onenormest.py
│     │        │  │  │  ├─ _propack
│     │        │  │  │  │  ├─ _cpropack.cpython-312-darwin.so
│     │        │  │  │  │  ├─ _dpropack.cpython-312-darwin.so
│     │        │  │  │  │  ├─ _spropack.cpython-312-darwin.so
│     │        │  │  │  │  └─ _zpropack.cpython-312-darwin.so
│     │        │  │  │  ├─ _special_sparse_arrays.py
│     │        │  │  │  ├─ _svdp.py
│     │        │  │  │  ├─ dsolve.py
│     │        │  │  │  ├─ eigen.py
│     │        │  │  │  ├─ interface.py
│     │        │  │  │  ├─ isolve.py
│     │        │  │  │  ├─ matfuncs.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ propack_test_data.npz
│     │        │  │  │     ├─ test_expm_multiply.py
│     │        │  │  │     ├─ test_interface.py
│     │        │  │  │     ├─ test_matfuncs.py
│     │        │  │  │     ├─ test_norm.py
│     │        │  │  │     ├─ test_onenormest.py
│     │        │  │  │     ├─ test_propack.py
│     │        │  │  │     ├─ test_pydata_sparse.py
│     │        │  │  │     └─ test_special_sparse_arrays.py
│     │        │  │  ├─ sparsetools.py
│     │        │  │  ├─ spfuncs.py
│     │        │  │  ├─ sputils.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_arithmetic1d.py
│     │        │  │     ├─ test_array_api.py
│     │        │  │     ├─ test_base.py
│     │        │  │     ├─ test_common1d.py
│     │        │  │     ├─ test_construct.py
│     │        │  │     ├─ test_coo.py
│     │        │  │     ├─ test_csc.py
│     │        │  │     ├─ test_csr.py
│     │        │  │     ├─ test_dok.py
│     │        │  │     ├─ test_extract.py
│     │        │  │     ├─ test_indexing1d.py
│     │        │  │     ├─ test_matrix_io.py
│     │        │  │     ├─ test_minmax1d.py
│     │        │  │     ├─ test_sparsetools.py
│     │        │  │     ├─ test_spfuncs.py
│     │        │  │     └─ test_sputils.py
│     │        │  ├─ spatial
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _ckdtree.cpython-312-darwin.so
│     │        │  │  ├─ _distance_pybind.cpython-312-darwin.so
│     │        │  │  ├─ _distance_wrap.cpython-312-darwin.so
│     │        │  │  ├─ _geometric_slerp.py
│     │        │  │  ├─ _hausdorff.cpython-312-darwin.so
│     │        │  │  ├─ _kdtree.py
│     │        │  │  ├─ _plotutils.py
│     │        │  │  ├─ _procrustes.py
│     │        │  │  ├─ _qhull.cpython-312-darwin.so
│     │        │  │  ├─ _qhull.pyi
│     │        │  │  ├─ _spherical_voronoi.py
│     │        │  │  ├─ _voronoi.cpython-312-darwin.so
│     │        │  │  ├─ _voronoi.pyi
│     │        │  │  ├─ ckdtree.py
│     │        │  │  ├─ distance.py
│     │        │  │  ├─ distance.pyi
│     │        │  │  ├─ kdtree.py
│     │        │  │  ├─ qhull.py
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test__plotutils.py
│     │        │  │  │  ├─ test__procrustes.py
│     │        │  │  │  ├─ test_distance.py
│     │        │  │  │  ├─ test_hausdorff.py
│     │        │  │  │  ├─ test_kdtree.py
│     │        │  │  │  ├─ test_qhull.py
│     │        │  │  │  ├─ test_slerp.py
│     │        │  │  │  └─ test_spherical_voronoi.py
│     │        │  │  └─ transform
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ _rigid_transform.cpython-312-darwin.so
│     │        │  │     ├─ _rotation.cpython-312-darwin.so
│     │        │  │     ├─ _rotation_groups.py
│     │        │  │     ├─ _rotation_spline.py
│     │        │  │     ├─ rotation.py
│     │        │  │     └─ tests
│     │        │  │        ├─ __init__.py
│     │        │  │        ├─ test_rigid_transform.py
│     │        │  │        ├─ test_rotation.py
│     │        │  │        ├─ test_rotation_groups.py
│     │        │  │        └─ test_rotation_spline.py
│     │        │  ├─ special
│     │        │  │  ├─ __init__.pxd
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _add_newdocs.py
│     │        │  │  ├─ _basic.py
│     │        │  │  ├─ _comb.cpython-312-darwin.so
│     │        │  │  ├─ _ellip_harm.py
│     │        │  │  ├─ _ellip_harm_2.cpython-312-darwin.so
│     │        │  │  ├─ _gufuncs.cpython-312-darwin.so
│     │        │  │  ├─ _input_validation.py
│     │        │  │  ├─ _lambertw.py
│     │        │  │  ├─ _logsumexp.py
│     │        │  │  ├─ _mptestutils.py
│     │        │  │  ├─ _multiufuncs.py
│     │        │  │  ├─ _orthogonal.py
│     │        │  │  ├─ _orthogonal.pyi
│     │        │  │  ├─ _precompute
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ cosine_cdf.py
│     │        │  │  │  ├─ expn_asy.py
│     │        │  │  │  ├─ gammainc_asy.py
│     │        │  │  │  ├─ gammainc_data.py
│     │        │  │  │  ├─ hyp2f1_data.py
│     │        │  │  │  ├─ lambertw.py
│     │        │  │  │  ├─ loggamma.py
│     │        │  │  │  ├─ struve_convergence.py
│     │        │  │  │  ├─ utils.py
│     │        │  │  │  ├─ wright_bessel.py
│     │        │  │  │  ├─ wright_bessel_data.py
│     │        │  │  │  ├─ wrightomega.py
│     │        │  │  │  └─ zetac.py
│     │        │  │  ├─ _sf_error.py
│     │        │  │  ├─ _specfun.cpython-312-darwin.so
│     │        │  │  ├─ _special_ufuncs.cpython-312-darwin.so
│     │        │  │  ├─ _spfun_stats.py
│     │        │  │  ├─ _spherical_bessel.py
│     │        │  │  ├─ _support_alternative_backends.py
│     │        │  │  ├─ _test_internal.cpython-312-darwin.so
│     │        │  │  ├─ _test_internal.pyi
│     │        │  │  ├─ _testutils.py
│     │        │  │  ├─ _ufuncs.cpython-312-darwin.so
│     │        │  │  ├─ _ufuncs.pyi
│     │        │  │  ├─ _ufuncs.pyx
│     │        │  │  ├─ _ufuncs_cxx.cpython-312-darwin.so
│     │        │  │  ├─ _ufuncs_cxx.pxd
│     │        │  │  ├─ _ufuncs_cxx.pyx
│     │        │  │  ├─ _ufuncs_cxx_defs.h
│     │        │  │  ├─ _ufuncs_defs.h
│     │        │  │  ├─ add_newdocs.py
│     │        │  │  ├─ basic.py
│     │        │  │  ├─ cython_special.cpython-312-darwin.so
│     │        │  │  ├─ cython_special.pxd
│     │        │  │  ├─ cython_special.pyi
│     │        │  │  ├─ orthogonal.py
│     │        │  │  ├─ sf_error.py
│     │        │  │  ├─ specfun.py
│     │        │  │  ├─ spfun_stats.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ _cython_examples
│     │        │  │     │  ├─ extending.pyx
│     │        │  │     │  └─ meson.build
│     │        │  │     ├─ test_basic.py
│     │        │  │     ├─ test_bdtr.py
│     │        │  │     ├─ test_boost_ufuncs.py
│     │        │  │     ├─ test_boxcox.py
│     │        │  │     ├─ test_cdflib.py
│     │        │  │     ├─ test_cdft_asymptotic.py
│     │        │  │     ├─ test_cephes_intp_cast.py
│     │        │  │     ├─ test_cosine_distr.py
│     │        │  │     ├─ test_cython_special.py
│     │        │  │     ├─ test_data.py
│     │        │  │     ├─ test_dd.py
│     │        │  │     ├─ test_digamma.py
│     │        │  │     ├─ test_ellip_harm.py
│     │        │  │     ├─ test_erfinv.py
│     │        │  │     ├─ test_exponential_integrals.py
│     │        │  │     ├─ test_extending.py
│     │        │  │     ├─ test_faddeeva.py
│     │        │  │     ├─ test_gamma.py
│     │        │  │     ├─ test_gammainc.py
│     │        │  │     ├─ test_hyp2f1.py
│     │        │  │     ├─ test_hypergeometric.py
│     │        │  │     ├─ test_iv_ratio.py
│     │        │  │     ├─ test_kolmogorov.py
│     │        │  │     ├─ test_lambertw.py
│     │        │  │     ├─ test_legendre.py
│     │        │  │     ├─ test_log1mexp.py
│     │        │  │     ├─ test_loggamma.py
│     │        │  │     ├─ test_logit.py
│     │        │  │     ├─ test_logsumexp.py
│     │        │  │     ├─ test_mpmath.py
│     │        │  │     ├─ test_nan_inputs.py
│     │        │  │     ├─ test_ndtr.py
│     │        │  │     ├─ test_ndtri_exp.py
│     │        │  │     ├─ test_orthogonal.py
│     │        │  │     ├─ test_orthogonal_eval.py
│     │        │  │     ├─ test_owens_t.py
│     │        │  │     ├─ test_pcf.py
│     │        │  │     ├─ test_pdtr.py
│     │        │  │     ├─ test_powm1.py
│     │        │  │     ├─ test_precompute_expn_asy.py
│     │        │  │     ├─ test_precompute_gammainc.py
│     │        │  │     ├─ test_precompute_utils.py
│     │        │  │     ├─ test_round.py
│     │        │  │     ├─ test_sf_error.py
│     │        │  │     ├─ test_sici.py
│     │        │  │     ├─ test_specfun.py
│     │        │  │     ├─ test_spence.py
│     │        │  │     ├─ test_spfun_stats.py
│     │        │  │     ├─ test_sph_harm.py
│     │        │  │     ├─ test_spherical_bessel.py
│     │        │  │     ├─ test_support_alternative_backends.py
│     │        │  │     ├─ test_trig.py
│     │        │  │     ├─ test_ufunc_signatures.py
│     │        │  │     ├─ test_wright_bessel.py
│     │        │  │     ├─ test_wrightomega.py
│     │        │  │     └─ test_zeta.py
│     │        │  ├─ stats
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _ansari_swilk_statistics.cpython-312-darwin.so
│     │        │  │  ├─ _axis_nan_policy.py
│     │        │  │  ├─ _biasedurn.cpython-312-darwin.so
│     │        │  │  ├─ _biasedurn.pxd
│     │        │  │  ├─ _binned_statistic.py
│     │        │  │  ├─ _binomtest.py
│     │        │  │  ├─ _bws_test.py
│     │        │  │  ├─ _censored_data.py
│     │        │  │  ├─ _common.py
│     │        │  │  ├─ _constants.py
│     │        │  │  ├─ _continued_fraction.py
│     │        │  │  ├─ _continuous_distns.py
│     │        │  │  ├─ _correlation.py
│     │        │  │  ├─ _covariance.py
│     │        │  │  ├─ _crosstab.py
│     │        │  │  ├─ _discrete_distns.py
│     │        │  │  ├─ _distn_infrastructure.py
│     │        │  │  ├─ _distr_params.py
│     │        │  │  ├─ _distribution_infrastructure.py
│     │        │  │  ├─ _entropy.py
│     │        │  │  ├─ _finite_differences.py
│     │        │  │  ├─ _fit.py
│     │        │  │  ├─ _hypotests.py
│     │        │  │  ├─ _kde.py
│     │        │  │  ├─ _ksstats.py
│     │        │  │  ├─ _levy_stable
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ levyst.cpython-312-darwin.so
│     │        │  │  ├─ _mannwhitneyu.py
│     │        │  │  ├─ _mgc.py
│     │        │  │  ├─ _morestats.py
│     │        │  │  ├─ _mstats_basic.py
│     │        │  │  ├─ _mstats_extras.py
│     │        │  │  ├─ _multicomp.py
│     │        │  │  ├─ _multivariate.py
│     │        │  │  ├─ _new_distributions.py
│     │        │  │  ├─ _odds_ratio.py
│     │        │  │  ├─ _page_trend_test.py
│     │        │  │  ├─ _probability_distribution.py
│     │        │  │  ├─ _qmc.py
│     │        │  │  ├─ _qmc_cy.cpython-312-darwin.so
│     │        │  │  ├─ _qmc_cy.pyi
│     │        │  │  ├─ _qmvnt.py
│     │        │  │  ├─ _qmvnt_cy.cpython-312-darwin.so
│     │        │  │  ├─ _quantile.py
│     │        │  │  ├─ _rcont
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ rcont.cpython-312-darwin.so
│     │        │  │  ├─ _relative_risk.py
│     │        │  │  ├─ _resampling.py
│     │        │  │  ├─ _result_classes.py
│     │        │  │  ├─ _sampling.py
│     │        │  │  ├─ _sensitivity_analysis.py
│     │        │  │  ├─ _sobol.cpython-312-darwin.so
│     │        │  │  ├─ _sobol.pyi
│     │        │  │  ├─ _sobol_direction_numbers.npz
│     │        │  │  ├─ _stats.cpython-312-darwin.so
│     │        │  │  ├─ _stats.pxd
│     │        │  │  ├─ _stats_mstats_common.py
│     │        │  │  ├─ _stats_py.py
│     │        │  │  ├─ _stats_pythran.cpython-312-darwin.so
│     │        │  │  ├─ _survival.py
│     │        │  │  ├─ _tukeylambda_stats.py
│     │        │  │  ├─ _unuran
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ unuran_wrapper.cpython-312-darwin.so
│     │        │  │  │  └─ unuran_wrapper.pyi
│     │        │  │  ├─ _variation.py
│     │        │  │  ├─ _warnings_errors.py
│     │        │  │  ├─ _wilcoxon.py
│     │        │  │  ├─ biasedurn.py
│     │        │  │  ├─ contingency.py
│     │        │  │  ├─ distributions.py
│     │        │  │  ├─ kde.py
│     │        │  │  ├─ morestats.py
│     │        │  │  ├─ mstats.py
│     │        │  │  ├─ mstats_basic.py
│     │        │  │  ├─ mstats_extras.py
│     │        │  │  ├─ mvn.py
│     │        │  │  ├─ qmc.py
│     │        │  │  ├─ sampling.py
│     │        │  │  ├─ stats.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ common_tests.py
│     │        │  │     ├─ test_axis_nan_policy.py
│     │        │  │     ├─ test_binned_statistic.py
│     │        │  │     ├─ test_censored_data.py
│     │        │  │     ├─ test_contingency.py
│     │        │  │     ├─ test_continued_fraction.py
│     │        │  │     ├─ test_continuous.py
│     │        │  │     ├─ test_continuous_basic.py
│     │        │  │     ├─ test_continuous_fit_censored.py
│     │        │  │     ├─ test_correlation.py
│     │        │  │     ├─ test_crosstab.py
│     │        │  │     ├─ test_discrete_basic.py
│     │        │  │     ├─ test_discrete_distns.py
│     │        │  │     ├─ test_distributions.py
│     │        │  │     ├─ test_entropy.py
│     │        │  │     ├─ test_fast_gen_inversion.py
│     │        │  │     ├─ test_fit.py
│     │        │  │     ├─ test_hypotests.py
│     │        │  │     ├─ test_kdeoth.py
│     │        │  │     ├─ test_marray.py
│     │        │  │     ├─ test_mgc.py
│     │        │  │     ├─ test_morestats.py
│     │        │  │     ├─ test_mstats_basic.py
│     │        │  │     ├─ test_mstats_extras.py
│     │        │  │     ├─ test_multicomp.py
│     │        │  │     ├─ test_multivariate.py
│     │        │  │     ├─ test_odds_ratio.py
│     │        │  │     ├─ test_qmc.py
│     │        │  │     ├─ test_quantile.py
│     │        │  │     ├─ test_rank.py
│     │        │  │     ├─ test_relative_risk.py
│     │        │  │     ├─ test_resampling.py
│     │        │  │     ├─ test_sampling.py
│     │        │  │     ├─ test_sensitivity_analysis.py
│     │        │  │     ├─ test_stats.py
│     │        │  │     ├─ test_survival.py
│     │        │  │     ├─ test_tukeylambda_stats.py
│     │        │  │     └─ test_variation.py
│     │        │  └─ version.py
│     │        ├─ scipy-1.16.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  └─ WHEEL
│     │        ├─ service_identity
│     │        │  ├─ __init__.py
│     │        │  ├─ cryptography.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ hazmat.py
│     │        │  ├─ py.typed
│     │        │  └─ pyopenssl.py
│     │        ├─ service_identity-24.2.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ setuptools
│     │        │  ├─ __init__.py
│     │        │  ├─ _core_metadata.py
│     │        │  ├─ _discovery.py
│     │        │  ├─ _distutils
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _log.py
│     │        │  │  ├─ _macos_compat.py
│     │        │  │  ├─ _modified.py
│     │        │  │  ├─ _msvccompiler.py
│     │        │  │  ├─ archive_util.py
│     │        │  │  ├─ ccompiler.py
│     │        │  │  ├─ cmd.py
│     │        │  │  ├─ command
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _framework_compat.py
│     │        │  │  │  ├─ bdist.py
│     │        │  │  │  ├─ bdist_dumb.py
│     │        │  │  │  ├─ bdist_rpm.py
│     │        │  │  │  ├─ build.py
│     │        │  │  │  ├─ build_clib.py
│     │        │  │  │  ├─ build_ext.py
│     │        │  │  │  ├─ build_py.py
│     │        │  │  │  ├─ build_scripts.py
│     │        │  │  │  ├─ check.py
│     │        │  │  │  ├─ clean.py
│     │        │  │  │  ├─ config.py
│     │        │  │  │  ├─ install.py
│     │        │  │  │  ├─ install_data.py
│     │        │  │  │  ├─ install_egg_info.py
│     │        │  │  │  ├─ install_headers.py
│     │        │  │  │  ├─ install_lib.py
│     │        │  │  │  ├─ install_scripts.py
│     │        │  │  │  └─ sdist.py
│     │        │  │  ├─ compat
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ numpy.py
│     │        │  │  │  └─ py39.py
│     │        │  │  ├─ compilers
│     │        │  │  │  └─ C
│     │        │  │  │     ├─ base.py
│     │        │  │  │     ├─ cygwin.py
│     │        │  │  │     ├─ errors.py
│     │        │  │  │     ├─ msvc.py
│     │        │  │  │     ├─ tests
│     │        │  │  │     │  ├─ test_base.py
│     │        │  │  │     │  ├─ test_cygwin.py
│     │        │  │  │     │  ├─ test_mingw.py
│     │        │  │  │     │  ├─ test_msvc.py
│     │        │  │  │     │  └─ test_unix.py
│     │        │  │  │     ├─ unix.py
│     │        │  │  │     └─ zos.py
│     │        │  │  ├─ core.py
│     │        │  │  ├─ cygwinccompiler.py
│     │        │  │  ├─ debug.py
│     │        │  │  ├─ dep_util.py
│     │        │  │  ├─ dir_util.py
│     │        │  │  ├─ dist.py
│     │        │  │  ├─ errors.py
│     │        │  │  ├─ extension.py
│     │        │  │  ├─ fancy_getopt.py
│     │        │  │  ├─ file_util.py
│     │        │  │  ├─ filelist.py
│     │        │  │  ├─ log.py
│     │        │  │  ├─ spawn.py
│     │        │  │  ├─ sysconfig.py
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ compat
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ py39.py
│     │        │  │  │  ├─ support.py
│     │        │  │  │  ├─ test_archive_util.py
│     │        │  │  │  ├─ test_bdist.py
│     │        │  │  │  ├─ test_bdist_dumb.py
│     │        │  │  │  ├─ test_bdist_rpm.py
│     │        │  │  │  ├─ test_build.py
│     │        │  │  │  ├─ test_build_clib.py
│     │        │  │  │  ├─ test_build_ext.py
│     │        │  │  │  ├─ test_build_py.py
│     │        │  │  │  ├─ test_build_scripts.py
│     │        │  │  │  ├─ test_check.py
│     │        │  │  │  ├─ test_clean.py
│     │        │  │  │  ├─ test_cmd.py
│     │        │  │  │  ├─ test_config_cmd.py
│     │        │  │  │  ├─ test_core.py
│     │        │  │  │  ├─ test_dir_util.py
│     │        │  │  │  ├─ test_dist.py
│     │        │  │  │  ├─ test_extension.py
│     │        │  │  │  ├─ test_file_util.py
│     │        │  │  │  ├─ test_filelist.py
│     │        │  │  │  ├─ test_install.py
│     │        │  │  │  ├─ test_install_data.py
│     │        │  │  │  ├─ test_install_headers.py
│     │        │  │  │  ├─ test_install_lib.py
│     │        │  │  │  ├─ test_install_scripts.py
│     │        │  │  │  ├─ test_log.py
│     │        │  │  │  ├─ test_modified.py
│     │        │  │  │  ├─ test_sdist.py
│     │        │  │  │  ├─ test_spawn.py
│     │        │  │  │  ├─ test_sysconfig.py
│     │        │  │  │  ├─ test_text_file.py
│     │        │  │  │  ├─ test_util.py
│     │        │  │  │  ├─ test_version.py
│     │        │  │  │  ├─ test_versionpredicate.py
│     │        │  │  │  └─ unix_compat.py
│     │        │  │  ├─ text_file.py
│     │        │  │  ├─ unixccompiler.py
│     │        │  │  ├─ util.py
│     │        │  │  ├─ version.py
│     │        │  │  ├─ versionpredicate.py
│     │        │  │  └─ zosccompiler.py
│     │        │  ├─ _entry_points.py
│     │        │  ├─ _imp.py
│     │        │  ├─ _importlib.py
│     │        │  ├─ _itertools.py
│     │        │  ├─ _normalization.py
│     │        │  ├─ _path.py
│     │        │  ├─ _reqs.py
│     │        │  ├─ _scripts.py
│     │        │  ├─ _shutil.py
│     │        │  ├─ _static.py
│     │        │  ├─ _vendor
│     │        │  │  ├─ autocommand
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ autoasync.py
│     │        │  │  │  ├─ autocommand.py
│     │        │  │  │  ├─ automain.py
│     │        │  │  │  ├─ autoparse.py
│     │        │  │  │  └─ errors.py
│     │        │  │  ├─ autocommand-2.2.2.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ top_level.txt
│     │        │  │  ├─ backports
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ tarfile
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ __main__.py
│     │        │  │  │     └─ compat
│     │        │  │  │        ├─ __init__.py
│     │        │  │  │        └─ py38.py
│     │        │  │  ├─ backports.tarfile-1.2.0.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ REQUESTED
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ top_level.txt
│     │        │  │  ├─ importlib_metadata-8.0.0.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ REQUESTED
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ top_level.txt
│     │        │  │  ├─ inflect
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ compat
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ py38.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ inflect-7.3.1.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ top_level.txt
│     │        │  │  ├─ jaraco
│     │        │  │  │  ├─ collections
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ py.typed
│     │        │  │  │  ├─ context.py
│     │        │  │  │  ├─ functools
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ __init__.pyi
│     │        │  │  │  │  └─ py.typed
│     │        │  │  │  └─ text
│     │        │  │  │     ├─ Lorem ipsum.txt
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ layouts.py
│     │        │  │  │     ├─ show-newlines.py
│     │        │  │  │     ├─ strip-prefix.py
│     │        │  │  │     ├─ to-dvorak.py
│     │        │  │  │     └─ to-qwerty.py
│     │        │  │  ├─ jaraco.collections-5.1.0.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ REQUESTED
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ top_level.txt
│     │        │  │  ├─ jaraco.context-5.3.0.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ top_level.txt
│     │        │  │  ├─ jaraco.functools-4.0.1.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ top_level.txt
│     │        │  │  ├─ jaraco.text-3.12.1.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ REQUESTED
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ top_level.txt
│     │        │  │  ├─ more_itertools
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __init__.pyi
│     │        │  │  │  ├─ more.py
│     │        │  │  │  ├─ more.pyi
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  ├─ recipes.py
│     │        │  │  │  └─ recipes.pyi
│     │        │  │  ├─ more_itertools-10.3.0.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ REQUESTED
│     │        │  │  │  └─ WHEEL
│     │        │  │  ├─ packaging
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _elffile.py
│     │        │  │  │  ├─ _manylinux.py
│     │        │  │  │  ├─ _musllinux.py
│     │        │  │  │  ├─ _parser.py
│     │        │  │  │  ├─ _structures.py
│     │        │  │  │  ├─ _tokenizer.py
│     │        │  │  │  ├─ licenses
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ _spdx.py
│     │        │  │  │  ├─ markers.py
│     │        │  │  │  ├─ metadata.py
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  ├─ requirements.py
│     │        │  │  │  ├─ specifiers.py
│     │        │  │  │  ├─ tags.py
│     │        │  │  │  ├─ utils.py
│     │        │  │  │  └─ version.py
│     │        │  │  ├─ packaging-24.2.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ LICENSE.APACHE
│     │        │  │  │  ├─ LICENSE.BSD
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ REQUESTED
│     │        │  │  │  └─ WHEEL
│     │        │  │  ├─ platformdirs
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __main__.py
│     │        │  │  │  ├─ android.py
│     │        │  │  │  ├─ api.py
│     │        │  │  │  ├─ macos.py
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  ├─ unix.py
│     │        │  │  │  ├─ version.py
│     │        │  │  │  └─ windows.py
│     │        │  │  ├─ platformdirs-4.2.2.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ REQUESTED
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ licenses
│     │        │  │  │     └─ LICENSE
│     │        │  │  ├─ tomli
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _parser.py
│     │        │  │  │  ├─ _re.py
│     │        │  │  │  ├─ _types.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ tomli-2.0.1.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ REQUESTED
│     │        │  │  │  └─ WHEEL
│     │        │  │  ├─ typeguard
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _checkers.py
│     │        │  │  │  ├─ _config.py
│     │        │  │  │  ├─ _decorators.py
│     │        │  │  │  ├─ _exceptions.py
│     │        │  │  │  ├─ _functions.py
│     │        │  │  │  ├─ _importhook.py
│     │        │  │  │  ├─ _memo.py
│     │        │  │  │  ├─ _pytest_plugin.py
│     │        │  │  │  ├─ _suppression.py
│     │        │  │  │  ├─ _transformer.py
│     │        │  │  │  ├─ _union_transformer.py
│     │        │  │  │  ├─ _utils.py
│     │        │  │  │  └─ py.typed
│     │        │  │  ├─ typeguard-4.3.0.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  ├─ entry_points.txt
│     │        │  │  │  └─ top_level.txt
│     │        │  │  ├─ typing_extensions-4.12.2.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  └─ WHEEL
│     │        │  │  ├─ typing_extensions.py
│     │        │  │  ├─ wheel
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ __main__.py
│     │        │  │  │  ├─ _bdist_wheel.py
│     │        │  │  │  ├─ _setuptools_logging.py
│     │        │  │  │  ├─ bdist_wheel.py
│     │        │  │  │  ├─ cli
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ convert.py
│     │        │  │  │  │  ├─ pack.py
│     │        │  │  │  │  ├─ tags.py
│     │        │  │  │  │  └─ unpack.py
│     │        │  │  │  ├─ macosx_libfile.py
│     │        │  │  │  ├─ metadata.py
│     │        │  │  │  ├─ util.py
│     │        │  │  │  ├─ vendored
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ packaging
│     │        │  │  │  │  │  ├─ LICENSE
│     │        │  │  │  │  │  ├─ LICENSE.APACHE
│     │        │  │  │  │  │  ├─ LICENSE.BSD
│     │        │  │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  │  ├─ _elffile.py
│     │        │  │  │  │  │  ├─ _manylinux.py
│     │        │  │  │  │  │  ├─ _musllinux.py
│     │        │  │  │  │  │  ├─ _parser.py
│     │        │  │  │  │  │  ├─ _structures.py
│     │        │  │  │  │  │  ├─ _tokenizer.py
│     │        │  │  │  │  │  ├─ markers.py
│     │        │  │  │  │  │  ├─ requirements.py
│     │        │  │  │  │  │  ├─ specifiers.py
│     │        │  │  │  │  │  ├─ tags.py
│     │        │  │  │  │  │  ├─ utils.py
│     │        │  │  │  │  │  └─ version.py
│     │        │  │  │  │  └─ vendor.txt
│     │        │  │  │  └─ wheelfile.py
│     │        │  │  ├─ wheel-0.45.1.dist-info
│     │        │  │  │  ├─ INSTALLER
│     │        │  │  │  ├─ LICENSE.txt
│     │        │  │  │  ├─ METADATA
│     │        │  │  │  ├─ RECORD
│     │        │  │  │  ├─ REQUESTED
│     │        │  │  │  ├─ WHEEL
│     │        │  │  │  └─ entry_points.txt
│     │        │  │  ├─ zipp
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ compat
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ py310.py
│     │        │  │  │  └─ glob.py
│     │        │  │  └─ zipp-3.19.2.dist-info
│     │        │  │     ├─ INSTALLER
│     │        │  │     ├─ LICENSE
│     │        │  │     ├─ METADATA
│     │        │  │     ├─ RECORD
│     │        │  │     ├─ REQUESTED
│     │        │  │     ├─ WHEEL
│     │        │  │     └─ top_level.txt
│     │        │  ├─ archive_util.py
│     │        │  ├─ build_meta.py
│     │        │  ├─ cli-32.exe
│     │        │  ├─ cli-64.exe
│     │        │  ├─ cli-arm64.exe
│     │        │  ├─ cli.exe
│     │        │  ├─ command
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _requirestxt.py
│     │        │  │  ├─ alias.py
│     │        │  │  ├─ bdist_egg.py
│     │        │  │  ├─ bdist_rpm.py
│     │        │  │  ├─ bdist_wheel.py
│     │        │  │  ├─ build.py
│     │        │  │  ├─ build_clib.py
│     │        │  │  ├─ build_ext.py
│     │        │  │  ├─ build_py.py
│     │        │  │  ├─ develop.py
│     │        │  │  ├─ dist_info.py
│     │        │  │  ├─ easy_install.py
│     │        │  │  ├─ editable_wheel.py
│     │        │  │  ├─ egg_info.py
│     │        │  │  ├─ install.py
│     │        │  │  ├─ install_egg_info.py
│     │        │  │  ├─ install_lib.py
│     │        │  │  ├─ install_scripts.py
│     │        │  │  ├─ launcher manifest.xml
│     │        │  │  ├─ rotate.py
│     │        │  │  ├─ saveopts.py
│     │        │  │  ├─ sdist.py
│     │        │  │  ├─ setopt.py
│     │        │  │  └─ test.py
│     │        │  ├─ compat
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ py310.py
│     │        │  │  ├─ py311.py
│     │        │  │  ├─ py312.py
│     │        │  │  └─ py39.py
│     │        │  ├─ config
│     │        │  │  ├─ NOTICE
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _apply_pyprojecttoml.py
│     │        │  │  ├─ _validate_pyproject
│     │        │  │  │  ├─ NOTICE
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ error_reporting.py
│     │        │  │  │  ├─ extra_validations.py
│     │        │  │  │  ├─ fastjsonschema_exceptions.py
│     │        │  │  │  ├─ fastjsonschema_validations.py
│     │        │  │  │  └─ formats.py
│     │        │  │  ├─ distutils.schema.json
│     │        │  │  ├─ expand.py
│     │        │  │  ├─ pyprojecttoml.py
│     │        │  │  ├─ setupcfg.py
│     │        │  │  └─ setuptools.schema.json
│     │        │  ├─ depends.py
│     │        │  ├─ discovery.py
│     │        │  ├─ dist.py
│     │        │  ├─ errors.py
│     │        │  ├─ extension.py
│     │        │  ├─ glob.py
│     │        │  ├─ gui-32.exe
│     │        │  ├─ gui-64.exe
│     │        │  ├─ gui-arm64.exe
│     │        │  ├─ gui.exe
│     │        │  ├─ installer.py
│     │        │  ├─ launch.py
│     │        │  ├─ logging.py
│     │        │  ├─ modified.py
│     │        │  ├─ monkey.py
│     │        │  ├─ msvc.py
│     │        │  ├─ namespaces.py
│     │        │  ├─ script (dev).tmpl
│     │        │  ├─ script.tmpl
│     │        │  ├─ tests
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ compat
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ py39.py
│     │        │  │  ├─ config
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ downloads
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ preload.py
│     │        │  │  │  ├─ setupcfg_examples.txt
│     │        │  │  │  ├─ test_apply_pyprojecttoml.py
│     │        │  │  │  ├─ test_expand.py
│     │        │  │  │  ├─ test_pyprojecttoml.py
│     │        │  │  │  ├─ test_pyprojecttoml_dynamic_deps.py
│     │        │  │  │  └─ test_setupcfg.py
│     │        │  │  ├─ contexts.py
│     │        │  │  ├─ environment.py
│     │        │  │  ├─ fixtures.py
│     │        │  │  ├─ indexes
│     │        │  │  │  └─ test_links_priority
│     │        │  │  │     ├─ external.html
│     │        │  │  │     └─ simple
│     │        │  │  │        └─ foobar
│     │        │  │  │           └─ index.html
│     │        │  │  ├─ integration
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ helpers.py
│     │        │  │  │  ├─ test_pbr.py
│     │        │  │  │  └─ test_pip_install_sdist.py
│     │        │  │  ├─ mod_with_constant.py
│     │        │  │  ├─ namespaces.py
│     │        │  │  ├─ script-with-bom.py
│     │        │  │  ├─ test_archive_util.py
│     │        │  │  ├─ test_bdist_deprecations.py
│     │        │  │  ├─ test_bdist_egg.py
│     │        │  │  ├─ test_bdist_wheel.py
│     │        │  │  ├─ test_build.py
│     │        │  │  ├─ test_build_clib.py
│     │        │  │  ├─ test_build_ext.py
│     │        │  │  ├─ test_build_meta.py
│     │        │  │  ├─ test_build_py.py
│     │        │  │  ├─ test_config_discovery.py
│     │        │  │  ├─ test_core_metadata.py
│     │        │  │  ├─ test_depends.py
│     │        │  │  ├─ test_develop.py
│     │        │  │  ├─ test_dist.py
│     │        │  │  ├─ test_dist_info.py
│     │        │  │  ├─ test_distutils_adoption.py
│     │        │  │  ├─ test_editable_install.py
│     │        │  │  ├─ test_egg_info.py
│     │        │  │  ├─ test_extern.py
│     │        │  │  ├─ test_find_packages.py
│     │        │  │  ├─ test_find_py_modules.py
│     │        │  │  ├─ test_glob.py
│     │        │  │  ├─ test_install_scripts.py
│     │        │  │  ├─ test_logging.py
│     │        │  │  ├─ test_manifest.py
│     │        │  │  ├─ test_namespaces.py
│     │        │  │  ├─ test_scripts.py
│     │        │  │  ├─ test_sdist.py
│     │        │  │  ├─ test_setopt.py
│     │        │  │  ├─ test_setuptools.py
│     │        │  │  ├─ test_shutil_wrapper.py
│     │        │  │  ├─ test_unicode_utils.py
│     │        │  │  ├─ test_virtualenv.py
│     │        │  │  ├─ test_warnings.py
│     │        │  │  ├─ test_wheel.py
│     │        │  │  ├─ test_windows_wrappers.py
│     │        │  │  ├─ text.py
│     │        │  │  └─ textwrap.py
│     │        │  ├─ unicode_utils.py
│     │        │  ├─ version.py
│     │        │  ├─ warnings.py
│     │        │  ├─ wheel.py
│     │        │  └─ windows_support.py
│     │        ├─ setuptools-80.9.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ six-1.17.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ six.py
│     │        ├─ sklearn
│     │        │  ├─ .dylibs
│     │        │  │  └─ libomp.dylib
│     │        │  ├─ __check_build
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _check_build.cpython-312-darwin.so
│     │        │  │  ├─ _check_build.pyx
│     │        │  │  └─ meson.build
│     │        │  ├─ __init__.py
│     │        │  ├─ _build_utils
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ tempita.py
│     │        │  │  └─ version.py
│     │        │  ├─ _built_with_meson.py
│     │        │  ├─ _config.py
│     │        │  ├─ _cyutility.cpython-312-darwin.so
│     │        │  ├─ _distributor_init.py
│     │        │  ├─ _isotonic.cpython-312-darwin.so
│     │        │  ├─ _isotonic.pyx
│     │        │  ├─ _loss
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _loss.cpython-312-darwin.so
│     │        │  │  ├─ _loss.pxd
│     │        │  │  ├─ _loss.pyx.tp
│     │        │  │  ├─ link.py
│     │        │  │  ├─ loss.py
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_link.py
│     │        │  │     └─ test_loss.py
│     │        │  ├─ _min_dependencies.py
│     │        │  ├─ base.py
│     │        │  ├─ calibration.py
│     │        │  ├─ cluster
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _affinity_propagation.py
│     │        │  │  ├─ _agglomerative.py
│     │        │  │  ├─ _bicluster.py
│     │        │  │  ├─ _birch.py
│     │        │  │  ├─ _bisect_k_means.py
│     │        │  │  ├─ _dbscan.py
│     │        │  │  ├─ _dbscan_inner.cpython-312-darwin.so
│     │        │  │  ├─ _dbscan_inner.pyx
│     │        │  │  ├─ _feature_agglomeration.py
│     │        │  │  ├─ _hdbscan
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _linkage.cpython-312-darwin.so
│     │        │  │  │  ├─ _linkage.pyx
│     │        │  │  │  ├─ _reachability.cpython-312-darwin.so
│     │        │  │  │  ├─ _reachability.pyx
│     │        │  │  │  ├─ _tree.cpython-312-darwin.so
│     │        │  │  │  ├─ _tree.pxd
│     │        │  │  │  ├─ _tree.pyx
│     │        │  │  │  ├─ hdbscan.py
│     │        │  │  │  ├─ meson.build
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     └─ test_reachibility.py
│     │        │  │  ├─ _hierarchical_fast.cpython-312-darwin.so
│     │        │  │  ├─ _hierarchical_fast.pxd
│     │        │  │  ├─ _hierarchical_fast.pyx
│     │        │  │  ├─ _k_means_common.cpython-312-darwin.so
│     │        │  │  ├─ _k_means_common.pxd
│     │        │  │  ├─ _k_means_common.pyx
│     │        │  │  ├─ _k_means_elkan.cpython-312-darwin.so
│     │        │  │  ├─ _k_means_elkan.pyx
│     │        │  │  ├─ _k_means_lloyd.cpython-312-darwin.so
│     │        │  │  ├─ _k_means_lloyd.pyx
│     │        │  │  ├─ _k_means_minibatch.cpython-312-darwin.so
│     │        │  │  ├─ _k_means_minibatch.pyx
│     │        │  │  ├─ _kmeans.py
│     │        │  │  ├─ _mean_shift.py
│     │        │  │  ├─ _optics.py
│     │        │  │  ├─ _spectral.py
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ common.py
│     │        │  │     ├─ test_affinity_propagation.py
│     │        │  │     ├─ test_bicluster.py
│     │        │  │     ├─ test_birch.py
│     │        │  │     ├─ test_bisect_k_means.py
│     │        │  │     ├─ test_dbscan.py
│     │        │  │     ├─ test_feature_agglomeration.py
│     │        │  │     ├─ test_hdbscan.py
│     │        │  │     ├─ test_hierarchical.py
│     │        │  │     ├─ test_k_means.py
│     │        │  │     ├─ test_mean_shift.py
│     │        │  │     ├─ test_optics.py
│     │        │  │     └─ test_spectral.py
│     │        │  ├─ compose
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _column_transformer.py
│     │        │  │  ├─ _target.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_column_transformer.py
│     │        │  │     └─ test_target.py
│     │        │  ├─ conftest.py
│     │        │  ├─ covariance
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _elliptic_envelope.py
│     │        │  │  ├─ _empirical_covariance.py
│     │        │  │  ├─ _graph_lasso.py
│     │        │  │  ├─ _robust_covariance.py
│     │        │  │  ├─ _shrunk_covariance.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_covariance.py
│     │        │  │     ├─ test_elliptic_envelope.py
│     │        │  │     ├─ test_graphical_lasso.py
│     │        │  │     └─ test_robust_covariance.py
│     │        │  ├─ cross_decomposition
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _pls.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     └─ test_pls.py
│     │        │  ├─ datasets
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _arff_parser.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _california_housing.py
│     │        │  │  ├─ _covtype.py
│     │        │  │  ├─ _kddcup99.py
│     │        │  │  ├─ _lfw.py
│     │        │  │  ├─ _olivetti_faces.py
│     │        │  │  ├─ _openml.py
│     │        │  │  ├─ _rcv1.py
│     │        │  │  ├─ _samples_generator.py
│     │        │  │  ├─ _species_distributions.py
│     │        │  │  ├─ _svmlight_format_fast.cpython-312-darwin.so
│     │        │  │  ├─ _svmlight_format_fast.pyx
│     │        │  │  ├─ _svmlight_format_io.py
│     │        │  │  ├─ _twenty_newsgroups.py
│     │        │  │  ├─ descr
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ breast_cancer.rst
│     │        │  │  │  ├─ california_housing.rst
│     │        │  │  │  ├─ covtype.rst
│     │        │  │  │  ├─ diabetes.rst
│     │        │  │  │  ├─ digits.rst
│     │        │  │  │  ├─ iris.rst
│     │        │  │  │  ├─ kddcup99.rst
│     │        │  │  │  ├─ lfw.rst
│     │        │  │  │  ├─ linnerud.rst
│     │        │  │  │  ├─ olivetti_faces.rst
│     │        │  │  │  ├─ rcv1.rst
│     │        │  │  │  ├─ species_distributions.rst
│     │        │  │  │  ├─ twenty_newsgroups.rst
│     │        │  │  │  └─ wine_data.rst
│     │        │  │  ├─ images
│     │        │  │  │  ├─ README.txt
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ china.jpg
│     │        │  │  │  └─ flower.jpg
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_20news.py
│     │        │  │     ├─ test_arff_parser.py
│     │        │  │     ├─ test_base.py
│     │        │  │     ├─ test_california_housing.py
│     │        │  │     ├─ test_common.py
│     │        │  │     ├─ test_covtype.py
│     │        │  │     ├─ test_kddcup99.py
│     │        │  │     ├─ test_lfw.py
│     │        │  │     ├─ test_olivetti_faces.py
│     │        │  │     ├─ test_openml.py
│     │        │  │     ├─ test_rcv1.py
│     │        │  │     ├─ test_samples_generator.py
│     │        │  │     └─ test_svmlight_format.py
│     │        │  ├─ decomposition
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _cdnmf_fast.cpython-312-darwin.so
│     │        │  │  ├─ _cdnmf_fast.pyx
│     │        │  │  ├─ _dict_learning.py
│     │        │  │  ├─ _factor_analysis.py
│     │        │  │  ├─ _fastica.py
│     │        │  │  ├─ _incremental_pca.py
│     │        │  │  ├─ _kernel_pca.py
│     │        │  │  ├─ _lda.py
│     │        │  │  ├─ _nmf.py
│     │        │  │  ├─ _online_lda_fast.cpython-312-darwin.so
│     │        │  │  ├─ _online_lda_fast.pyx
│     │        │  │  ├─ _pca.py
│     │        │  │  ├─ _sparse_pca.py
│     │        │  │  ├─ _truncated_svd.py
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_dict_learning.py
│     │        │  │     ├─ test_factor_analysis.py
│     │        │  │     ├─ test_fastica.py
│     │        │  │     ├─ test_incremental_pca.py
│     │        │  │     ├─ test_kernel_pca.py
│     │        │  │     ├─ test_nmf.py
│     │        │  │     ├─ test_online_lda.py
│     │        │  │     ├─ test_pca.py
│     │        │  │     ├─ test_sparse_pca.py
│     │        │  │     └─ test_truncated_svd.py
│     │        │  ├─ discriminant_analysis.py
│     │        │  ├─ dummy.py
│     │        │  ├─ ensemble
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _bagging.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _forest.py
│     │        │  │  ├─ _gb.py
│     │        │  │  ├─ _gradient_boosting.cpython-312-darwin.so
│     │        │  │  ├─ _gradient_boosting.pyx
│     │        │  │  ├─ _hist_gradient_boosting
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _binning.cpython-312-darwin.so
│     │        │  │  │  ├─ _binning.pyx
│     │        │  │  │  ├─ _bitset.cpython-312-darwin.so
│     │        │  │  │  ├─ _bitset.pxd
│     │        │  │  │  ├─ _bitset.pyx
│     │        │  │  │  ├─ _gradient_boosting.cpython-312-darwin.so
│     │        │  │  │  ├─ _gradient_boosting.pyx
│     │        │  │  │  ├─ _predictor.cpython-312-darwin.so
│     │        │  │  │  ├─ _predictor.pyx
│     │        │  │  │  ├─ binning.py
│     │        │  │  │  ├─ common.cpython-312-darwin.so
│     │        │  │  │  ├─ common.pxd
│     │        │  │  │  ├─ common.pyx
│     │        │  │  │  ├─ gradient_boosting.py
│     │        │  │  │  ├─ grower.py
│     │        │  │  │  ├─ histogram.cpython-312-darwin.so
│     │        │  │  │  ├─ histogram.pyx
│     │        │  │  │  ├─ meson.build
│     │        │  │  │  ├─ predictor.py
│     │        │  │  │  ├─ splitting.cpython-312-darwin.so
│     │        │  │  │  ├─ splitting.pyx
│     │        │  │  │  ├─ tests
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ test_binning.py
│     │        │  │  │  │  ├─ test_bitset.py
│     │        │  │  │  │  ├─ test_compare_lightgbm.py
│     │        │  │  │  │  ├─ test_gradient_boosting.py
│     │        │  │  │  │  ├─ test_grower.py
│     │        │  │  │  │  ├─ test_histogram.py
│     │        │  │  │  │  ├─ test_monotonic_constraints.py
│     │        │  │  │  │  ├─ test_predictor.py
│     │        │  │  │  │  ├─ test_splitting.py
│     │        │  │  │  │  └─ test_warm_start.py
│     │        │  │  │  └─ utils.py
│     │        │  │  ├─ _iforest.py
│     │        │  │  ├─ _stacking.py
│     │        │  │  ├─ _voting.py
│     │        │  │  ├─ _weight_boosting.py
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_bagging.py
│     │        │  │     ├─ test_base.py
│     │        │  │     ├─ test_common.py
│     │        │  │     ├─ test_forest.py
│     │        │  │     ├─ test_gradient_boosting.py
│     │        │  │     ├─ test_iforest.py
│     │        │  │     ├─ test_stacking.py
│     │        │  │     ├─ test_voting.py
│     │        │  │     └─ test_weight_boosting.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ experimental
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ enable_halving_search_cv.py
│     │        │  │  ├─ enable_hist_gradient_boosting.py
│     │        │  │  ├─ enable_iterative_imputer.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_enable_hist_gradient_boosting.py
│     │        │  │     ├─ test_enable_iterative_imputer.py
│     │        │  │     └─ test_enable_successive_halving.py
│     │        │  ├─ externals
│     │        │  │  ├─ README
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _arff.py
│     │        │  │  ├─ _array_api_compat_vendor.py
│     │        │  │  ├─ _packaging
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _structures.py
│     │        │  │  │  └─ version.py
│     │        │  │  ├─ _scipy
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ sparse
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     └─ csgraph
│     │        │  │  │        ├─ __init__.py
│     │        │  │  │        └─ _laplacian.py
│     │        │  │  ├─ array_api_compat
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ README.md
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _internal.py
│     │        │  │  │  ├─ common
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _aliases.py
│     │        │  │  │  │  ├─ _fft.py
│     │        │  │  │  │  ├─ _helpers.py
│     │        │  │  │  │  ├─ _linalg.py
│     │        │  │  │  │  └─ _typing.py
│     │        │  │  │  ├─ cupy
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _aliases.py
│     │        │  │  │  │  ├─ _info.py
│     │        │  │  │  │  ├─ _typing.py
│     │        │  │  │  │  ├─ fft.py
│     │        │  │  │  │  └─ linalg.py
│     │        │  │  │  ├─ dask
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  └─ array
│     │        │  │  │  │     ├─ __init__.py
│     │        │  │  │  │     ├─ _aliases.py
│     │        │  │  │  │     ├─ _info.py
│     │        │  │  │  │     ├─ fft.py
│     │        │  │  │  │     └─ linalg.py
│     │        │  │  │  ├─ numpy
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _aliases.py
│     │        │  │  │  │  ├─ _info.py
│     │        │  │  │  │  ├─ _typing.py
│     │        │  │  │  │  ├─ fft.py
│     │        │  │  │  │  └─ linalg.py
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  └─ torch
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ _aliases.py
│     │        │  │  │     ├─ _info.py
│     │        │  │  │     ├─ _typing.py
│     │        │  │  │     ├─ fft.py
│     │        │  │  │     └─ linalg.py
│     │        │  │  ├─ array_api_extra
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ README.md
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _delegation.py
│     │        │  │  │  ├─ _lib
│     │        │  │  │  │  ├─ __init__.py
│     │        │  │  │  │  ├─ _at.py
│     │        │  │  │  │  ├─ _backends.py
│     │        │  │  │  │  ├─ _funcs.py
│     │        │  │  │  │  ├─ _lazy.py
│     │        │  │  │  │  ├─ _testing.py
│     │        │  │  │  │  └─ _utils
│     │        │  │  │  │     ├─ __init__.py
│     │        │  │  │  │     ├─ _compat.py
│     │        │  │  │  │     ├─ _compat.pyi
│     │        │  │  │  │     ├─ _helpers.py
│     │        │  │  │  │     ├─ _typing.py
│     │        │  │  │  │     └─ _typing.pyi
│     │        │  │  │  ├─ py.typed
│     │        │  │  │  └─ testing.py
│     │        │  │  └─ conftest.py
│     │        │  ├─ feature_extraction
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _dict_vectorizer.py
│     │        │  │  ├─ _hash.py
│     │        │  │  ├─ _hashing_fast.cpython-312-darwin.so
│     │        │  │  ├─ _hashing_fast.pyx
│     │        │  │  ├─ _stop_words.py
│     │        │  │  ├─ image.py
│     │        │  │  ├─ meson.build
│     │        │  │  ├─ tests
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_dict_vectorizer.py
│     │        │  │  │  ├─ test_feature_hasher.py
│     │        │  │  │  ├─ test_image.py
│     │        │  │  │  └─ test_text.py
│     │        │  │  └─ text.py
│     │        │  ├─ feature_selection
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _from_model.py
│     │        │  │  ├─ _mutual_info.py
│     │        │  │  ├─ _rfe.py
│     │        │  │  ├─ _sequential.py
│     │        │  │  ├─ _univariate_selection.py
│     │        │  │  ├─ _variance_threshold.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_base.py
│     │        │  │     ├─ test_chi2.py
│     │        │  │     ├─ test_feature_select.py
│     │        │  │     ├─ test_from_model.py
│     │        │  │     ├─ test_mutual_info.py
│     │        │  │     ├─ test_rfe.py
│     │        │  │     ├─ test_sequential.py
│     │        │  │     └─ test_variance_threshold.py
│     │        │  ├─ frozen
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _frozen.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     └─ test_frozen.py
│     │        │  ├─ gaussian_process
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _gpc.py
│     │        │  │  ├─ _gpr.py
│     │        │  │  ├─ kernels.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ _mini_sequence_kernel.py
│     │        │  │     ├─ test_gpc.py
│     │        │  │     ├─ test_gpr.py
│     │        │  │     └─ test_kernels.py
│     │        │  ├─ impute
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _iterative.py
│     │        │  │  ├─ _knn.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_base.py
│     │        │  │     ├─ test_common.py
│     │        │  │     ├─ test_impute.py
│     │        │  │     └─ test_knn.py
│     │        │  ├─ inspection
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _partial_dependence.py
│     │        │  │  ├─ _pd_utils.py
│     │        │  │  ├─ _permutation_importance.py
│     │        │  │  ├─ _plot
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ decision_boundary.py
│     │        │  │  │  ├─ partial_dependence.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_boundary_decision_display.py
│     │        │  │  │     └─ test_plot_partial_dependence.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_partial_dependence.py
│     │        │  │     ├─ test_pd_utils.py
│     │        │  │     └─ test_permutation_importance.py
│     │        │  ├─ isotonic.py
│     │        │  ├─ kernel_approximation.py
│     │        │  ├─ kernel_ridge.py
│     │        │  ├─ linear_model
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _bayes.py
│     │        │  │  ├─ _cd_fast.cpython-312-darwin.so
│     │        │  │  ├─ _cd_fast.pyx
│     │        │  │  ├─ _coordinate_descent.py
│     │        │  │  ├─ _glm
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _newton_solver.py
│     │        │  │  │  ├─ glm.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     └─ test_glm.py
│     │        │  │  ├─ _huber.py
│     │        │  │  ├─ _least_angle.py
│     │        │  │  ├─ _linear_loss.py
│     │        │  │  ├─ _logistic.py
│     │        │  │  ├─ _omp.py
│     │        │  │  ├─ _passive_aggressive.py
│     │        │  │  ├─ _perceptron.py
│     │        │  │  ├─ _quantile.py
│     │        │  │  ├─ _ransac.py
│     │        │  │  ├─ _ridge.py
│     │        │  │  ├─ _sag.py
│     │        │  │  ├─ _sag_fast.cpython-312-darwin.so
│     │        │  │  ├─ _sag_fast.pyx.tp
│     │        │  │  ├─ _sgd_fast.cpython-312-darwin.so
│     │        │  │  ├─ _sgd_fast.pyx.tp
│     │        │  │  ├─ _stochastic_gradient.py
│     │        │  │  ├─ _theil_sen.py
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_base.py
│     │        │  │     ├─ test_bayes.py
│     │        │  │     ├─ test_common.py
│     │        │  │     ├─ test_coordinate_descent.py
│     │        │  │     ├─ test_huber.py
│     │        │  │     ├─ test_least_angle.py
│     │        │  │     ├─ test_linear_loss.py
│     │        │  │     ├─ test_logistic.py
│     │        │  │     ├─ test_omp.py
│     │        │  │     ├─ test_passive_aggressive.py
│     │        │  │     ├─ test_perceptron.py
│     │        │  │     ├─ test_quantile.py
│     │        │  │     ├─ test_ransac.py
│     │        │  │     ├─ test_ridge.py
│     │        │  │     ├─ test_sag.py
│     │        │  │     ├─ test_sgd.py
│     │        │  │     ├─ test_sparse_coordinate_descent.py
│     │        │  │     └─ test_theil_sen.py
│     │        │  ├─ manifold
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _barnes_hut_tsne.cpython-312-darwin.so
│     │        │  │  ├─ _barnes_hut_tsne.pyx
│     │        │  │  ├─ _isomap.py
│     │        │  │  ├─ _locally_linear.py
│     │        │  │  ├─ _mds.py
│     │        │  │  ├─ _spectral_embedding.py
│     │        │  │  ├─ _t_sne.py
│     │        │  │  ├─ _utils.cpython-312-darwin.so
│     │        │  │  ├─ _utils.pyx
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_isomap.py
│     │        │  │     ├─ test_locally_linear.py
│     │        │  │     ├─ test_mds.py
│     │        │  │     ├─ test_spectral_embedding.py
│     │        │  │     └─ test_t_sne.py
│     │        │  ├─ meson.build
│     │        │  ├─ metrics
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _classification.py
│     │        │  │  ├─ _dist_metrics.cpython-312-darwin.so
│     │        │  │  ├─ _dist_metrics.pxd
│     │        │  │  ├─ _dist_metrics.pxd.tp
│     │        │  │  ├─ _dist_metrics.pyx.tp
│     │        │  │  ├─ _pairwise_distances_reduction
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _argkmin.cpython-312-darwin.so
│     │        │  │  │  ├─ _argkmin.pxd.tp
│     │        │  │  │  ├─ _argkmin.pyx.tp
│     │        │  │  │  ├─ _argkmin_classmode.cpython-312-darwin.so
│     │        │  │  │  ├─ _argkmin_classmode.pyx.tp
│     │        │  │  │  ├─ _base.cpython-312-darwin.so
│     │        │  │  │  ├─ _base.pxd.tp
│     │        │  │  │  ├─ _base.pyx.tp
│     │        │  │  │  ├─ _classmode.pxd
│     │        │  │  │  ├─ _datasets_pair.cpython-312-darwin.so
│     │        │  │  │  ├─ _datasets_pair.pxd.tp
│     │        │  │  │  ├─ _datasets_pair.pyx.tp
│     │        │  │  │  ├─ _dispatcher.py
│     │        │  │  │  ├─ _middle_term_computer.cpython-312-darwin.so
│     │        │  │  │  ├─ _middle_term_computer.pxd.tp
│     │        │  │  │  ├─ _middle_term_computer.pyx.tp
│     │        │  │  │  ├─ _radius_neighbors.cpython-312-darwin.so
│     │        │  │  │  ├─ _radius_neighbors.pxd.tp
│     │        │  │  │  ├─ _radius_neighbors.pyx.tp
│     │        │  │  │  ├─ _radius_neighbors_classmode.cpython-312-darwin.so
│     │        │  │  │  ├─ _radius_neighbors_classmode.pyx.tp
│     │        │  │  │  └─ meson.build
│     │        │  │  ├─ _pairwise_fast.cpython-312-darwin.so
│     │        │  │  ├─ _pairwise_fast.pyx
│     │        │  │  ├─ _plot
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ confusion_matrix.py
│     │        │  │  │  ├─ det_curve.py
│     │        │  │  │  ├─ precision_recall_curve.py
│     │        │  │  │  ├─ regression.py
│     │        │  │  │  ├─ roc_curve.py
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_common_curve_display.py
│     │        │  │  │     ├─ test_confusion_matrix_display.py
│     │        │  │  │     ├─ test_det_curve_display.py
│     │        │  │  │     ├─ test_precision_recall_display.py
│     │        │  │  │     ├─ test_predict_error_display.py
│     │        │  │  │     └─ test_roc_curve_display.py
│     │        │  │  ├─ _ranking.py
│     │        │  │  ├─ _regression.py
│     │        │  │  ├─ _scorer.py
│     │        │  │  ├─ cluster
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _bicluster.py
│     │        │  │  │  ├─ _expected_mutual_info_fast.cpython-312-darwin.so
│     │        │  │  │  ├─ _expected_mutual_info_fast.pyx
│     │        │  │  │  ├─ _supervised.py
│     │        │  │  │  ├─ _unsupervised.py
│     │        │  │  │  ├─ meson.build
│     │        │  │  │  └─ tests
│     │        │  │  │     ├─ __init__.py
│     │        │  │  │     ├─ test_bicluster.py
│     │        │  │  │     ├─ test_common.py
│     │        │  │  │     ├─ test_supervised.py
│     │        │  │  │     └─ test_unsupervised.py
│     │        │  │  ├─ meson.build
│     │        │  │  ├─ pairwise.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_classification.py
│     │        │  │     ├─ test_common.py
│     │        │  │     ├─ test_dist_metrics.py
│     │        │  │     ├─ test_pairwise.py
│     │        │  │     ├─ test_pairwise_distances_reduction.py
│     │        │  │     ├─ test_ranking.py
│     │        │  │     ├─ test_regression.py
│     │        │  │     └─ test_score_objects.py
│     │        │  ├─ mixture
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _bayesian_mixture.py
│     │        │  │  ├─ _gaussian_mixture.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_bayesian_mixture.py
│     │        │  │     ├─ test_gaussian_mixture.py
│     │        │  │     └─ test_mixture.py
│     │        │  ├─ model_selection
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _classification_threshold.py
│     │        │  │  ├─ _plot.py
│     │        │  │  ├─ _search.py
│     │        │  │  ├─ _search_successive_halving.py
│     │        │  │  ├─ _split.py
│     │        │  │  ├─ _validation.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ common.py
│     │        │  │     ├─ test_classification_threshold.py
│     │        │  │     ├─ test_plot.py
│     │        │  │     ├─ test_search.py
│     │        │  │     ├─ test_split.py
│     │        │  │     ├─ test_successive_halving.py
│     │        │  │     └─ test_validation.py
│     │        │  ├─ multiclass.py
│     │        │  ├─ multioutput.py
│     │        │  ├─ naive_bayes.py
│     │        │  ├─ neighbors
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _ball_tree.cpython-312-darwin.so
│     │        │  │  ├─ _ball_tree.pyx.tp
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _binary_tree.pxi.tp
│     │        │  │  ├─ _classification.py
│     │        │  │  ├─ _graph.py
│     │        │  │  ├─ _kd_tree.cpython-312-darwin.so
│     │        │  │  ├─ _kd_tree.pyx.tp
│     │        │  │  ├─ _kde.py
│     │        │  │  ├─ _lof.py
│     │        │  │  ├─ _nca.py
│     │        │  │  ├─ _nearest_centroid.py
│     │        │  │  ├─ _partition_nodes.cpython-312-darwin.so
│     │        │  │  ├─ _partition_nodes.pxd
│     │        │  │  ├─ _partition_nodes.pyx
│     │        │  │  ├─ _quad_tree.cpython-312-darwin.so
│     │        │  │  ├─ _quad_tree.pxd
│     │        │  │  ├─ _quad_tree.pyx
│     │        │  │  ├─ _regression.py
│     │        │  │  ├─ _unsupervised.py
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_ball_tree.py
│     │        │  │     ├─ test_graph.py
│     │        │  │     ├─ test_kd_tree.py
│     │        │  │     ├─ test_kde.py
│     │        │  │     ├─ test_lof.py
│     │        │  │     ├─ test_nca.py
│     │        │  │     ├─ test_nearest_centroid.py
│     │        │  │     ├─ test_neighbors.py
│     │        │  │     ├─ test_neighbors_pipeline.py
│     │        │  │     ├─ test_neighbors_tree.py
│     │        │  │     └─ test_quad_tree.py
│     │        │  ├─ neural_network
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _multilayer_perceptron.py
│     │        │  │  ├─ _rbm.py
│     │        │  │  ├─ _stochastic_optimizers.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_base.py
│     │        │  │     ├─ test_mlp.py
│     │        │  │     ├─ test_rbm.py
│     │        │  │     └─ test_stochastic_optimizers.py
│     │        │  ├─ pipeline.py
│     │        │  ├─ preprocessing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _csr_polynomial_expansion.cpython-312-darwin.so
│     │        │  │  ├─ _csr_polynomial_expansion.pyx
│     │        │  │  ├─ _data.py
│     │        │  │  ├─ _discretization.py
│     │        │  │  ├─ _encoders.py
│     │        │  │  ├─ _function_transformer.py
│     │        │  │  ├─ _label.py
│     │        │  │  ├─ _polynomial.py
│     │        │  │  ├─ _target_encoder.py
│     │        │  │  ├─ _target_encoder_fast.cpython-312-darwin.so
│     │        │  │  ├─ _target_encoder_fast.pyx
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_common.py
│     │        │  │     ├─ test_data.py
│     │        │  │     ├─ test_discretization.py
│     │        │  │     ├─ test_encoders.py
│     │        │  │     ├─ test_function_transformer.py
│     │        │  │     ├─ test_label.py
│     │        │  │     ├─ test_polynomial.py
│     │        │  │     └─ test_target_encoder.py
│     │        │  ├─ random_projection.py
│     │        │  ├─ semi_supervised
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _label_propagation.py
│     │        │  │  ├─ _self_training.py
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_label_propagation.py
│     │        │  │     └─ test_self_training.py
│     │        │  ├─ svm
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _base.py
│     │        │  │  ├─ _bounds.py
│     │        │  │  ├─ _classes.py
│     │        │  │  ├─ _liblinear.cpython-312-darwin.so
│     │        │  │  ├─ _liblinear.pxi
│     │        │  │  ├─ _liblinear.pyx
│     │        │  │  ├─ _libsvm.cpython-312-darwin.so
│     │        │  │  ├─ _libsvm.pxi
│     │        │  │  ├─ _libsvm.pyx
│     │        │  │  ├─ _libsvm_sparse.cpython-312-darwin.so
│     │        │  │  ├─ _libsvm_sparse.pyx
│     │        │  │  ├─ _newrand.cpython-312-darwin.so
│     │        │  │  ├─ _newrand.pyx
│     │        │  │  ├─ meson.build
│     │        │  │  ├─ src
│     │        │  │  │  ├─ liblinear
│     │        │  │  │  │  ├─ COPYRIGHT
│     │        │  │  │  │  ├─ _cython_blas_helpers.h
│     │        │  │  │  │  ├─ liblinear_helper.c
│     │        │  │  │  │  ├─ linear.cpp
│     │        │  │  │  │  ├─ linear.h
│     │        │  │  │  │  ├─ tron.cpp
│     │        │  │  │  │  └─ tron.h
│     │        │  │  │  ├─ libsvm
│     │        │  │  │  │  ├─ LIBSVM_CHANGES
│     │        │  │  │  │  ├─ _svm_cython_blas_helpers.h
│     │        │  │  │  │  ├─ libsvm_helper.c
│     │        │  │  │  │  ├─ libsvm_sparse_helper.c
│     │        │  │  │  │  ├─ libsvm_template.cpp
│     │        │  │  │  │  ├─ svm.cpp
│     │        │  │  │  │  └─ svm.h
│     │        │  │  │  └─ newrand
│     │        │  │  │     └─ newrand.h
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_bounds.py
│     │        │  │     ├─ test_sparse.py
│     │        │  │     └─ test_svm.py
│     │        │  ├─ tests
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ metadata_routing_common.py
│     │        │  │  ├─ test_base.py
│     │        │  │  ├─ test_build.py
│     │        │  │  ├─ test_calibration.py
│     │        │  │  ├─ test_check_build.py
│     │        │  │  ├─ test_common.py
│     │        │  │  ├─ test_config.py
│     │        │  │  ├─ test_discriminant_analysis.py
│     │        │  │  ├─ test_docstring_parameters.py
│     │        │  │  ├─ test_docstring_parameters_consistency.py
│     │        │  │  ├─ test_docstrings.py
│     │        │  │  ├─ test_dummy.py
│     │        │  │  ├─ test_init.py
│     │        │  │  ├─ test_isotonic.py
│     │        │  │  ├─ test_kernel_approximation.py
│     │        │  │  ├─ test_kernel_ridge.py
│     │        │  │  ├─ test_metadata_routing.py
│     │        │  │  ├─ test_metaestimators.py
│     │        │  │  ├─ test_metaestimators_metadata_routing.py
│     │        │  │  ├─ test_min_dependencies_readme.py
│     │        │  │  ├─ test_multiclass.py
│     │        │  │  ├─ test_multioutput.py
│     │        │  │  ├─ test_naive_bayes.py
│     │        │  │  ├─ test_pipeline.py
│     │        │  │  ├─ test_public_functions.py
│     │        │  │  └─ test_random_projection.py
│     │        │  ├─ tree
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _classes.py
│     │        │  │  ├─ _criterion.cpython-312-darwin.so
│     │        │  │  ├─ _criterion.pxd
│     │        │  │  ├─ _criterion.pyx
│     │        │  │  ├─ _export.py
│     │        │  │  ├─ _partitioner.cpython-312-darwin.so
│     │        │  │  ├─ _partitioner.pxd
│     │        │  │  ├─ _partitioner.pyx
│     │        │  │  ├─ _reingold_tilford.py
│     │        │  │  ├─ _splitter.cpython-312-darwin.so
│     │        │  │  ├─ _splitter.pxd
│     │        │  │  ├─ _splitter.pyx
│     │        │  │  ├─ _tree.cpython-312-darwin.so
│     │        │  │  ├─ _tree.pxd
│     │        │  │  ├─ _tree.pyx
│     │        │  │  ├─ _utils.cpython-312-darwin.so
│     │        │  │  ├─ _utils.pxd
│     │        │  │  ├─ _utils.pyx
│     │        │  │  ├─ meson.build
│     │        │  │  └─ tests
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ test_export.py
│     │        │  │     ├─ test_monotonic_tree.py
│     │        │  │     ├─ test_reingold_tilford.py
│     │        │  │     └─ test_tree.py
│     │        │  └─ utils
│     │        │     ├─ __init__.py
│     │        │     ├─ _arpack.py
│     │        │     ├─ _array_api.py
│     │        │     ├─ _available_if.py
│     │        │     ├─ _bunch.py
│     │        │     ├─ _chunking.py
│     │        │     ├─ _cython_blas.cpython-312-darwin.so
│     │        │     ├─ _cython_blas.pxd
│     │        │     ├─ _cython_blas.pyx
│     │        │     ├─ _encode.py
│     │        │     ├─ _estimator_html_repr.py
│     │        │     ├─ _fast_dict.cpython-312-darwin.so
│     │        │     ├─ _fast_dict.pxd
│     │        │     ├─ _fast_dict.pyx
│     │        │     ├─ _heap.cpython-312-darwin.so
│     │        │     ├─ _heap.pxd
│     │        │     ├─ _heap.pyx
│     │        │     ├─ _indexing.py
│     │        │     ├─ _isfinite.cpython-312-darwin.so
│     │        │     ├─ _isfinite.pyx
│     │        │     ├─ _mask.py
│     │        │     ├─ _metadata_requests.py
│     │        │     ├─ _missing.py
│     │        │     ├─ _mocking.py
│     │        │     ├─ _openmp_helpers.cpython-312-darwin.so
│     │        │     ├─ _openmp_helpers.pxd
│     │        │     ├─ _openmp_helpers.pyx
│     │        │     ├─ _optional_dependencies.py
│     │        │     ├─ _param_validation.py
│     │        │     ├─ _plotting.py
│     │        │     ├─ _pprint.py
│     │        │     ├─ _random.cpython-312-darwin.so
│     │        │     ├─ _random.pxd
│     │        │     ├─ _random.pyx
│     │        │     ├─ _repr_html
│     │        │     │  ├─ __init__.py
│     │        │     │  ├─ base.py
│     │        │     │  ├─ estimator.css
│     │        │     │  ├─ estimator.js
│     │        │     │  ├─ estimator.py
│     │        │     │  ├─ params.css
│     │        │     │  ├─ params.py
│     │        │     │  └─ tests
│     │        │     │     ├─ __init__.py
│     │        │     │     ├─ test_estimator.py
│     │        │     │     └─ test_params.py
│     │        │     ├─ _response.py
│     │        │     ├─ _seq_dataset.cpython-312-darwin.so
│     │        │     ├─ _seq_dataset.pxd.tp
│     │        │     ├─ _seq_dataset.pyx.tp
│     │        │     ├─ _set_output.py
│     │        │     ├─ _show_versions.py
│     │        │     ├─ _sorting.cpython-312-darwin.so
│     │        │     ├─ _sorting.pxd
│     │        │     ├─ _sorting.pyx
│     │        │     ├─ _tags.py
│     │        │     ├─ _test_common
│     │        │     │  ├─ __init__.py
│     │        │     │  └─ instance_generator.py
│     │        │     ├─ _testing.py
│     │        │     ├─ _typedefs.cpython-312-darwin.so
│     │        │     ├─ _typedefs.pxd
│     │        │     ├─ _typedefs.pyx
│     │        │     ├─ _unique.py
│     │        │     ├─ _user_interface.py
│     │        │     ├─ _vector_sentinel.cpython-312-darwin.so
│     │        │     ├─ _vector_sentinel.pxd
│     │        │     ├─ _vector_sentinel.pyx
│     │        │     ├─ _weight_vector.cpython-312-darwin.so
│     │        │     ├─ _weight_vector.pxd.tp
│     │        │     ├─ _weight_vector.pyx.tp
│     │        │     ├─ arrayfuncs.cpython-312-darwin.so
│     │        │     ├─ arrayfuncs.pyx
│     │        │     ├─ class_weight.py
│     │        │     ├─ deprecation.py
│     │        │     ├─ discovery.py
│     │        │     ├─ estimator_checks.py
│     │        │     ├─ extmath.py
│     │        │     ├─ fixes.py
│     │        │     ├─ graph.py
│     │        │     ├─ meson.build
│     │        │     ├─ metadata_routing.py
│     │        │     ├─ metaestimators.py
│     │        │     ├─ multiclass.py
│     │        │     ├─ murmurhash.cpython-312-darwin.so
│     │        │     ├─ murmurhash.pxd
│     │        │     ├─ murmurhash.pyx
│     │        │     ├─ optimize.py
│     │        │     ├─ parallel.py
│     │        │     ├─ random.py
│     │        │     ├─ sparsefuncs.py
│     │        │     ├─ sparsefuncs_fast.cpython-312-darwin.so
│     │        │     ├─ sparsefuncs_fast.pyx
│     │        │     ├─ src
│     │        │     │  ├─ MurmurHash3.cpp
│     │        │     │  └─ MurmurHash3.h
│     │        │     ├─ stats.py
│     │        │     ├─ tests
│     │        │     │  ├─ __init__.py
│     │        │     │  ├─ test_arpack.py
│     │        │     │  ├─ test_array_api.py
│     │        │     │  ├─ test_arrayfuncs.py
│     │        │     │  ├─ test_bunch.py
│     │        │     │  ├─ test_chunking.py
│     │        │     │  ├─ test_class_weight.py
│     │        │     │  ├─ test_cython_blas.py
│     │        │     │  ├─ test_deprecation.py
│     │        │     │  ├─ test_encode.py
│     │        │     │  ├─ test_estimator_checks.py
│     │        │     │  ├─ test_estimator_html_repr.py
│     │        │     │  ├─ test_extmath.py
│     │        │     │  ├─ test_fast_dict.py
│     │        │     │  ├─ test_fixes.py
│     │        │     │  ├─ test_graph.py
│     │        │     │  ├─ test_indexing.py
│     │        │     │  ├─ test_mask.py
│     │        │     │  ├─ test_metaestimators.py
│     │        │     │  ├─ test_missing.py
│     │        │     │  ├─ test_mocking.py
│     │        │     │  ├─ test_multiclass.py
│     │        │     │  ├─ test_murmurhash.py
│     │        │     │  ├─ test_optimize.py
│     │        │     │  ├─ test_parallel.py
│     │        │     │  ├─ test_param_validation.py
│     │        │     │  ├─ test_plotting.py
│     │        │     │  ├─ test_pprint.py
│     │        │     │  ├─ test_random.py
│     │        │     │  ├─ test_response.py
│     │        │     │  ├─ test_seq_dataset.py
│     │        │     │  ├─ test_set_output.py
│     │        │     │  ├─ test_shortest_path.py
│     │        │     │  ├─ test_show_versions.py
│     │        │     │  ├─ test_sparsefuncs.py
│     │        │     │  ├─ test_stats.py
│     │        │     │  ├─ test_tags.py
│     │        │     │  ├─ test_testing.py
│     │        │     │  ├─ test_typedefs.py
│     │        │     │  ├─ test_unique.py
│     │        │     │  ├─ test_user_interface.py
│     │        │     │  ├─ test_validation.py
│     │        │     │  └─ test_weight_vector.py
│     │        │     └─ validation.py
│     │        ├─ sniffio
│     │        │  ├─ __init__.py
│     │        │  ├─ _impl.py
│     │        │  ├─ _tests
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ test_sniffio.py
│     │        │  ├─ _version.py
│     │        │  └─ py.typed
│     │        ├─ sniffio-1.3.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ LICENSE.APACHE2
│     │        │  ├─ LICENSE.MIT
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ sortedcontainers
│     │        │  ├─ __init__.py
│     │        │  ├─ sorteddict.py
│     │        │  ├─ sortedlist.py
│     │        │  └─ sortedset.py
│     │        ├─ sortedcontainers-2.4.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ soupsieve
│     │        │  ├─ __init__.py
│     │        │  ├─ __meta__.py
│     │        │  ├─ css_match.py
│     │        │  ├─ css_parser.py
│     │        │  ├─ css_types.py
│     │        │  ├─ pretty.py
│     │        │  ├─ py.typed
│     │        │  └─ util.py
│     │        ├─ soupsieve-2.7.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE.md
│     │        ├─ sqlalchemy
│     │        │  ├─ __init__.py
│     │        │  ├─ connectors
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ aioodbc.py
│     │        │  │  ├─ asyncio.py
│     │        │  │  └─ pyodbc.py
│     │        │  ├─ cyextension
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ collections.cpython-312-darwin.so
│     │        │  │  ├─ collections.pyx
│     │        │  │  ├─ immutabledict.cpython-312-darwin.so
│     │        │  │  ├─ immutabledict.pxd
│     │        │  │  ├─ immutabledict.pyx
│     │        │  │  ├─ processors.cpython-312-darwin.so
│     │        │  │  ├─ processors.pyx
│     │        │  │  ├─ resultproxy.cpython-312-darwin.so
│     │        │  │  ├─ resultproxy.pyx
│     │        │  │  ├─ util.cpython-312-darwin.so
│     │        │  │  └─ util.pyx
│     │        │  ├─ dialects
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _typing.py
│     │        │  │  ├─ mssql
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ aioodbc.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ information_schema.py
│     │        │  │  │  ├─ json.py
│     │        │  │  │  ├─ provision.py
│     │        │  │  │  ├─ pymssql.py
│     │        │  │  │  └─ pyodbc.py
│     │        │  │  ├─ mysql
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ aiomysql.py
│     │        │  │  │  ├─ asyncmy.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ cymysql.py
│     │        │  │  │  ├─ dml.py
│     │        │  │  │  ├─ enumerated.py
│     │        │  │  │  ├─ expression.py
│     │        │  │  │  ├─ json.py
│     │        │  │  │  ├─ mariadb.py
│     │        │  │  │  ├─ mariadbconnector.py
│     │        │  │  │  ├─ mysqlconnector.py
│     │        │  │  │  ├─ mysqldb.py
│     │        │  │  │  ├─ provision.py
│     │        │  │  │  ├─ pymysql.py
│     │        │  │  │  ├─ pyodbc.py
│     │        │  │  │  ├─ reflection.py
│     │        │  │  │  ├─ reserved_words.py
│     │        │  │  │  └─ types.py
│     │        │  │  ├─ oracle
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ cx_oracle.py
│     │        │  │  │  ├─ dictionary.py
│     │        │  │  │  ├─ oracledb.py
│     │        │  │  │  ├─ provision.py
│     │        │  │  │  ├─ types.py
│     │        │  │  │  └─ vector.py
│     │        │  │  ├─ postgresql
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _psycopg_common.py
│     │        │  │  │  ├─ array.py
│     │        │  │  │  ├─ asyncpg.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ dml.py
│     │        │  │  │  ├─ ext.py
│     │        │  │  │  ├─ hstore.py
│     │        │  │  │  ├─ json.py
│     │        │  │  │  ├─ named_types.py
│     │        │  │  │  ├─ operators.py
│     │        │  │  │  ├─ pg8000.py
│     │        │  │  │  ├─ pg_catalog.py
│     │        │  │  │  ├─ provision.py
│     │        │  │  │  ├─ psycopg.py
│     │        │  │  │  ├─ psycopg2.py
│     │        │  │  │  ├─ psycopg2cffi.py
│     │        │  │  │  ├─ ranges.py
│     │        │  │  │  └─ types.py
│     │        │  │  ├─ sqlite
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ aiosqlite.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ dml.py
│     │        │  │  │  ├─ json.py
│     │        │  │  │  ├─ provision.py
│     │        │  │  │  ├─ pysqlcipher.py
│     │        │  │  │  └─ pysqlite.py
│     │        │  │  └─ type_migration_guidelines.txt
│     │        │  ├─ engine
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _py_processors.py
│     │        │  │  ├─ _py_row.py
│     │        │  │  ├─ _py_util.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ characteristics.py
│     │        │  │  ├─ create.py
│     │        │  │  ├─ cursor.py
│     │        │  │  ├─ default.py
│     │        │  │  ├─ events.py
│     │        │  │  ├─ interfaces.py
│     │        │  │  ├─ mock.py
│     │        │  │  ├─ processors.py
│     │        │  │  ├─ reflection.py
│     │        │  │  ├─ result.py
│     │        │  │  ├─ row.py
│     │        │  │  ├─ strategies.py
│     │        │  │  ├─ url.py
│     │        │  │  └─ util.py
│     │        │  ├─ event
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ api.py
│     │        │  │  ├─ attr.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ legacy.py
│     │        │  │  └─ registry.py
│     │        │  ├─ events.py
│     │        │  ├─ exc.py
│     │        │  ├─ ext
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ associationproxy.py
│     │        │  │  ├─ asyncio
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ engine.py
│     │        │  │  │  ├─ exc.py
│     │        │  │  │  ├─ result.py
│     │        │  │  │  ├─ scoping.py
│     │        │  │  │  └─ session.py
│     │        │  │  ├─ automap.py
│     │        │  │  ├─ baked.py
│     │        │  │  ├─ compiler.py
│     │        │  │  ├─ declarative
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  └─ extensions.py
│     │        │  │  ├─ horizontal_shard.py
│     │        │  │  ├─ hybrid.py
│     │        │  │  ├─ indexable.py
│     │        │  │  ├─ instrumentation.py
│     │        │  │  ├─ mutable.py
│     │        │  │  ├─ mypy
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ apply.py
│     │        │  │  │  ├─ decl_class.py
│     │        │  │  │  ├─ infer.py
│     │        │  │  │  ├─ names.py
│     │        │  │  │  ├─ plugin.py
│     │        │  │  │  └─ util.py
│     │        │  │  ├─ orderinglist.py
│     │        │  │  └─ serializer.py
│     │        │  ├─ future
│     │        │  │  ├─ __init__.py
│     │        │  │  └─ engine.py
│     │        │  ├─ inspection.py
│     │        │  ├─ log.py
│     │        │  ├─ orm
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _orm_constructors.py
│     │        │  │  ├─ _typing.py
│     │        │  │  ├─ attributes.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ bulk_persistence.py
│     │        │  │  ├─ clsregistry.py
│     │        │  │  ├─ collections.py
│     │        │  │  ├─ context.py
│     │        │  │  ├─ decl_api.py
│     │        │  │  ├─ decl_base.py
│     │        │  │  ├─ dependency.py
│     │        │  │  ├─ descriptor_props.py
│     │        │  │  ├─ dynamic.py
│     │        │  │  ├─ evaluator.py
│     │        │  │  ├─ events.py
│     │        │  │  ├─ exc.py
│     │        │  │  ├─ identity.py
│     │        │  │  ├─ instrumentation.py
│     │        │  │  ├─ interfaces.py
│     │        │  │  ├─ loading.py
│     │        │  │  ├─ mapped_collection.py
│     │        │  │  ├─ mapper.py
│     │        │  │  ├─ path_registry.py
│     │        │  │  ├─ persistence.py
│     │        │  │  ├─ properties.py
│     │        │  │  ├─ query.py
│     │        │  │  ├─ relationships.py
│     │        │  │  ├─ scoping.py
│     │        │  │  ├─ session.py
│     │        │  │  ├─ state.py
│     │        │  │  ├─ state_changes.py
│     │        │  │  ├─ strategies.py
│     │        │  │  ├─ strategy_options.py
│     │        │  │  ├─ sync.py
│     │        │  │  ├─ unitofwork.py
│     │        │  │  ├─ util.py
│     │        │  │  └─ writeonly.py
│     │        │  ├─ pool
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ events.py
│     │        │  │  └─ impl.py
│     │        │  ├─ py.typed
│     │        │  ├─ schema.py
│     │        │  ├─ sql
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _dml_constructors.py
│     │        │  │  ├─ _elements_constructors.py
│     │        │  │  ├─ _orm_types.py
│     │        │  │  ├─ _py_util.py
│     │        │  │  ├─ _selectable_constructors.py
│     │        │  │  ├─ _typing.py
│     │        │  │  ├─ annotation.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ cache_key.py
│     │        │  │  ├─ coercions.py
│     │        │  │  ├─ compiler.py
│     │        │  │  ├─ crud.py
│     │        │  │  ├─ ddl.py
│     │        │  │  ├─ default_comparator.py
│     │        │  │  ├─ dml.py
│     │        │  │  ├─ elements.py
│     │        │  │  ├─ events.py
│     │        │  │  ├─ expression.py
│     │        │  │  ├─ functions.py
│     │        │  │  ├─ lambdas.py
│     │        │  │  ├─ naming.py
│     │        │  │  ├─ operators.py
│     │        │  │  ├─ roles.py
│     │        │  │  ├─ schema.py
│     │        │  │  ├─ selectable.py
│     │        │  │  ├─ sqltypes.py
│     │        │  │  ├─ traversals.py
│     │        │  │  ├─ type_api.py
│     │        │  │  ├─ util.py
│     │        │  │  └─ visitors.py
│     │        │  ├─ testing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ assertions.py
│     │        │  │  ├─ assertsql.py
│     │        │  │  ├─ asyncio.py
│     │        │  │  ├─ config.py
│     │        │  │  ├─ engines.py
│     │        │  │  ├─ entities.py
│     │        │  │  ├─ exclusions.py
│     │        │  │  ├─ fixtures
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ base.py
│     │        │  │  │  ├─ mypy.py
│     │        │  │  │  ├─ orm.py
│     │        │  │  │  └─ sql.py
│     │        │  │  ├─ pickleable.py
│     │        │  │  ├─ plugin
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ bootstrap.py
│     │        │  │  │  ├─ plugin_base.py
│     │        │  │  │  └─ pytestplugin.py
│     │        │  │  ├─ profiling.py
│     │        │  │  ├─ provision.py
│     │        │  │  ├─ requirements.py
│     │        │  │  ├─ schema.py
│     │        │  │  ├─ suite
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ test_cte.py
│     │        │  │  │  ├─ test_ddl.py
│     │        │  │  │  ├─ test_deprecations.py
│     │        │  │  │  ├─ test_dialect.py
│     │        │  │  │  ├─ test_insert.py
│     │        │  │  │  ├─ test_reflection.py
│     │        │  │  │  ├─ test_results.py
│     │        │  │  │  ├─ test_rowcount.py
│     │        │  │  │  ├─ test_select.py
│     │        │  │  │  ├─ test_sequence.py
│     │        │  │  │  ├─ test_types.py
│     │        │  │  │  ├─ test_unicode_ddl.py
│     │        │  │  │  └─ test_update_delete.py
│     │        │  │  ├─ util.py
│     │        │  │  └─ warnings.py
│     │        │  ├─ types.py
│     │        │  └─ util
│     │        │     ├─ __init__.py
│     │        │     ├─ _collections.py
│     │        │     ├─ _concurrency_py3k.py
│     │        │     ├─ _has_cy.py
│     │        │     ├─ _py_collections.py
│     │        │     ├─ compat.py
│     │        │     ├─ concurrency.py
│     │        │     ├─ deprecations.py
│     │        │     ├─ langhelpers.py
│     │        │     ├─ preloaded.py
│     │        │     ├─ queue.py
│     │        │     ├─ tool_support.py
│     │        │     ├─ topological.py
│     │        │     └─ typing.py
│     │        ├─ sqlalchemy-2.0.43.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ starlette
│     │        │  ├─ __init__.py
│     │        │  ├─ _exception_handler.py
│     │        │  ├─ _utils.py
│     │        │  ├─ applications.py
│     │        │  ├─ authentication.py
│     │        │  ├─ background.py
│     │        │  ├─ concurrency.py
│     │        │  ├─ config.py
│     │        │  ├─ convertors.py
│     │        │  ├─ datastructures.py
│     │        │  ├─ endpoints.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ formparsers.py
│     │        │  ├─ middleware
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ authentication.py
│     │        │  │  ├─ base.py
│     │        │  │  ├─ cors.py
│     │        │  │  ├─ errors.py
│     │        │  │  ├─ exceptions.py
│     │        │  │  ├─ gzip.py
│     │        │  │  ├─ httpsredirect.py
│     │        │  │  ├─ sessions.py
│     │        │  │  ├─ trustedhost.py
│     │        │  │  └─ wsgi.py
│     │        │  ├─ py.typed
│     │        │  ├─ requests.py
│     │        │  ├─ responses.py
│     │        │  ├─ routing.py
│     │        │  ├─ schemas.py
│     │        │  ├─ staticfiles.py
│     │        │  ├─ status.py
│     │        │  ├─ templating.py
│     │        │  ├─ testclient.py
│     │        │  ├─ types.py
│     │        │  └─ websockets.py
│     │        ├─ starlette-0.47.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE.md
│     │        ├─ threadpoolctl-3.6.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ threadpoolctl.py
│     │        ├─ tornado
│     │        │  ├─ __init__.py
│     │        │  ├─ __init__.pyi
│     │        │  ├─ _locale_data.py
│     │        │  ├─ auth.py
│     │        │  ├─ autoreload.py
│     │        │  ├─ concurrent.py
│     │        │  ├─ curl_httpclient.py
│     │        │  ├─ escape.py
│     │        │  ├─ gen.py
│     │        │  ├─ http1connection.py
│     │        │  ├─ httpclient.py
│     │        │  ├─ httpserver.py
│     │        │  ├─ httputil.py
│     │        │  ├─ ioloop.py
│     │        │  ├─ iostream.py
│     │        │  ├─ locale.py
│     │        │  ├─ locks.py
│     │        │  ├─ log.py
│     │        │  ├─ netutil.py
│     │        │  ├─ options.py
│     │        │  ├─ platform
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ asyncio.py
│     │        │  │  ├─ caresresolver.py
│     │        │  │  └─ twisted.py
│     │        │  ├─ process.py
│     │        │  ├─ py.typed
│     │        │  ├─ queues.py
│     │        │  ├─ routing.py
│     │        │  ├─ simple_httpclient.py
│     │        │  ├─ speedups.abi3.so
│     │        │  ├─ speedups.pyi
│     │        │  ├─ tcpclient.py
│     │        │  ├─ tcpserver.py
│     │        │  ├─ template.py
│     │        │  ├─ test
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ __main__.py
│     │        │  │  ├─ asyncio_test.py
│     │        │  │  ├─ auth_test.py
│     │        │  │  ├─ autoreload_test.py
│     │        │  │  ├─ circlerefs_test.py
│     │        │  │  ├─ concurrent_test.py
│     │        │  │  ├─ csv_translations
│     │        │  │  │  └─ fr_FR.csv
│     │        │  │  ├─ curl_httpclient_test.py
│     │        │  │  ├─ escape_test.py
│     │        │  │  ├─ gen_test.py
│     │        │  │  ├─ gettext_translations
│     │        │  │  │  └─ fr_FR
│     │        │  │  │     └─ LC_MESSAGES
│     │        │  │  │        ├─ tornado_test.mo
│     │        │  │  │        └─ tornado_test.po
│     │        │  │  ├─ http1connection_test.py
│     │        │  │  ├─ httpclient_test.py
│     │        │  │  ├─ httpserver_test.py
│     │        │  │  ├─ httputil_test.py
│     │        │  │  ├─ import_test.py
│     │        │  │  ├─ ioloop_test.py
│     │        │  │  ├─ iostream_test.py
│     │        │  │  ├─ locale_test.py
│     │        │  │  ├─ locks_test.py
│     │        │  │  ├─ log_test.py
│     │        │  │  ├─ netutil_test.py
│     │        │  │  ├─ options_test.cfg
│     │        │  │  ├─ options_test.py
│     │        │  │  ├─ options_test_types.cfg
│     │        │  │  ├─ options_test_types_str.cfg
│     │        │  │  ├─ process_test.py
│     │        │  │  ├─ queues_test.py
│     │        │  │  ├─ resolve_test_helper.py
│     │        │  │  ├─ routing_test.py
│     │        │  │  ├─ runtests.py
│     │        │  │  ├─ simple_httpclient_test.py
│     │        │  │  ├─ static
│     │        │  │  │  ├─ dir
│     │        │  │  │  │  └─ index.html
│     │        │  │  │  ├─ robots.txt
│     │        │  │  │  ├─ sample.xml
│     │        │  │  │  ├─ sample.xml.bz2
│     │        │  │  │  └─ sample.xml.gz
│     │        │  │  ├─ static_foo.txt
│     │        │  │  ├─ tcpclient_test.py
│     │        │  │  ├─ tcpserver_test.py
│     │        │  │  ├─ template_test.py
│     │        │  │  ├─ templates
│     │        │  │  │  └─ utf8.html
│     │        │  │  ├─ test.crt
│     │        │  │  ├─ test.key
│     │        │  │  ├─ testing_test.py
│     │        │  │  ├─ twisted_test.py
│     │        │  │  ├─ util.py
│     │        │  │  ├─ util_test.py
│     │        │  │  ├─ web_test.py
│     │        │  │  ├─ websocket_test.py
│     │        │  │  └─ wsgi_test.py
│     │        │  ├─ testing.py
│     │        │  ├─ util.py
│     │        │  ├─ web.py
│     │        │  ├─ websocket.py
│     │        │  └─ wsgi.py
│     │        ├─ tornado-6.5.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  └─ LICENSE
│     │        │  └─ top_level.txt
│     │        ├─ typing_extensions-4.14.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ typing_extensions.py
│     │        ├─ typing_inspection
│     │        │  ├─ __init__.py
│     │        │  ├─ introspection.py
│     │        │  ├─ py.typed
│     │        │  ├─ typing_objects.py
│     │        │  └─ typing_objects.pyi
│     │        ├─ typing_inspection-0.4.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ tzdata-2025.2.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ licenses
│     │        │  │  ├─ LICENSE
│     │        │  │  └─ licenses
│     │        │  │     └─ LICENSE_APACHE
│     │        │  └─ top_level.txt
│     │        ├─ urllib3
│     │        │  ├─ __init__.py
│     │        │  ├─ _base_connection.py
│     │        │  ├─ _collections.py
│     │        │  ├─ _request_methods.py
│     │        │  ├─ _version.py
│     │        │  ├─ connection.py
│     │        │  ├─ connectionpool.py
│     │        │  ├─ contrib
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ emscripten
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ connection.py
│     │        │  │  │  ├─ emscripten_fetch_worker.js
│     │        │  │  │  ├─ fetch.py
│     │        │  │  │  ├─ request.py
│     │        │  │  │  └─ response.py
│     │        │  │  ├─ pyopenssl.py
│     │        │  │  └─ socks.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ fields.py
│     │        │  ├─ filepost.py
│     │        │  ├─ http2
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ connection.py
│     │        │  │  └─ probe.py
│     │        │  ├─ poolmanager.py
│     │        │  ├─ py.typed
│     │        │  ├─ response.py
│     │        │  └─ util
│     │        │     ├─ __init__.py
│     │        │     ├─ connection.py
│     │        │     ├─ proxy.py
│     │        │     ├─ request.py
│     │        │     ├─ response.py
│     │        │     ├─ retry.py
│     │        │     ├─ ssl_.py
│     │        │     ├─ ssl_match_hostname.py
│     │        │     ├─ ssltransport.py
│     │        │     ├─ timeout.py
│     │        │     ├─ url.py
│     │        │     ├─ util.py
│     │        │     └─ wait.py
│     │        ├─ urllib3-2.5.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ licenses
│     │        │     └─ LICENSE.txt
│     │        ├─ urwid
│     │        │  ├─ __init__.py
│     │        │  ├─ canvas.py
│     │        │  ├─ command_map.py
│     │        │  ├─ container.py
│     │        │  ├─ decoration.py
│     │        │  ├─ display
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ _posix_raw_display.py
│     │        │  │  ├─ _raw_display_base.py
│     │        │  │  ├─ _web.css
│     │        │  │  ├─ _web.js
│     │        │  │  ├─ _win32.py
│     │        │  │  ├─ _win32_raw_display.py
│     │        │  │  ├─ common.py
│     │        │  │  ├─ curses.py
│     │        │  │  ├─ escape.py
│     │        │  │  ├─ html_fragment.py
│     │        │  │  ├─ lcd.py
│     │        │  │  ├─ raw.py
│     │        │  │  └─ web.py
│     │        │  ├─ event_loop
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ abstract_loop.py
│     │        │  │  ├─ asyncio_loop.py
│     │        │  │  ├─ glib_loop.py
│     │        │  │  ├─ main_loop.py
│     │        │  │  ├─ select_loop.py
│     │        │  │  ├─ tornado_loop.py
│     │        │  │  ├─ trio_loop.py
│     │        │  │  ├─ twisted_loop.py
│     │        │  │  └─ zmq_loop.py
│     │        │  ├─ font.py
│     │        │  ├─ graphics.py
│     │        │  ├─ numedit.py
│     │        │  ├─ signals.py
│     │        │  ├─ split_repr.py
│     │        │  ├─ str_util.py
│     │        │  ├─ text_layout.py
│     │        │  ├─ util.py
│     │        │  ├─ version.py
│     │        │  ├─ vterm.py
│     │        │  ├─ widget
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ attr_map.py
│     │        │  │  ├─ attr_wrap.py
│     │        │  │  ├─ bar_graph.py
│     │        │  │  ├─ big_text.py
│     │        │  │  ├─ box_adapter.py
│     │        │  │  ├─ columns.py
│     │        │  │  ├─ constants.py
│     │        │  │  ├─ container.py
│     │        │  │  ├─ divider.py
│     │        │  │  ├─ edit.py
│     │        │  │  ├─ filler.py
│     │        │  │  ├─ frame.py
│     │        │  │  ├─ grid_flow.py
│     │        │  │  ├─ line_box.py
│     │        │  │  ├─ listbox.py
│     │        │  │  ├─ monitored_list.py
│     │        │  │  ├─ overlay.py
│     │        │  │  ├─ padding.py
│     │        │  │  ├─ pile.py
│     │        │  │  ├─ popup.py
│     │        │  │  ├─ progress_bar.py
│     │        │  │  ├─ scrollable.py
│     │        │  │  ├─ solid_fill.py
│     │        │  │  ├─ text.py
│     │        │  │  ├─ treetools.py
│     │        │  │  ├─ widget.py
│     │        │  │  ├─ widget_decoration.py
│     │        │  │  └─ wimp.py
│     │        │  └─ wimp.py
│     │        ├─ urwid-2.6.16.dist-info
│     │        │  ├─ COPYING
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ uvicorn
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ _subprocess.py
│     │        │  ├─ _types.py
│     │        │  ├─ config.py
│     │        │  ├─ importer.py
│     │        │  ├─ lifespan
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ off.py
│     │        │  │  └─ on.py
│     │        │  ├─ logging.py
│     │        │  ├─ loops
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ asyncio.py
│     │        │  │  ├─ auto.py
│     │        │  │  └─ uvloop.py
│     │        │  ├─ main.py
│     │        │  ├─ middleware
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ asgi2.py
│     │        │  │  ├─ message_logger.py
│     │        │  │  ├─ proxy_headers.py
│     │        │  │  └─ wsgi.py
│     │        │  ├─ protocols
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ http
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ auto.py
│     │        │  │  │  ├─ flow_control.py
│     │        │  │  │  ├─ h11_impl.py
│     │        │  │  │  └─ httptools_impl.py
│     │        │  │  ├─ utils.py
│     │        │  │  └─ websockets
│     │        │  │     ├─ __init__.py
│     │        │  │     ├─ auto.py
│     │        │  │     ├─ websockets_impl.py
│     │        │  │     ├─ websockets_sansio_impl.py
│     │        │  │     └─ wsproto_impl.py
│     │        │  ├─ py.typed
│     │        │  ├─ server.py
│     │        │  ├─ supervisors
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ basereload.py
│     │        │  │  ├─ multiprocess.py
│     │        │  │  ├─ statreload.py
│     │        │  │  └─ watchfilesreload.py
│     │        │  └─ workers.py
│     │        ├─ uvicorn-0.35.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  └─ licenses
│     │        │     └─ LICENSE.md
│     │        ├─ uvloop
│     │        │  ├─ __init__.py
│     │        │  ├─ _noop.py
│     │        │  ├─ _testbase.py
│     │        │  ├─ _version.py
│     │        │  ├─ cbhandles.pxd
│     │        │  ├─ cbhandles.pyx
│     │        │  ├─ dns.pyx
│     │        │  ├─ errors.pyx
│     │        │  ├─ handles
│     │        │  │  ├─ async_.pxd
│     │        │  │  ├─ async_.pyx
│     │        │  │  ├─ basetransport.pxd
│     │        │  │  ├─ basetransport.pyx
│     │        │  │  ├─ check.pxd
│     │        │  │  ├─ check.pyx
│     │        │  │  ├─ fsevent.pxd
│     │        │  │  ├─ fsevent.pyx
│     │        │  │  ├─ handle.pxd
│     │        │  │  ├─ handle.pyx
│     │        │  │  ├─ idle.pxd
│     │        │  │  ├─ idle.pyx
│     │        │  │  ├─ pipe.pxd
│     │        │  │  ├─ pipe.pyx
│     │        │  │  ├─ poll.pxd
│     │        │  │  ├─ poll.pyx
│     │        │  │  ├─ process.pxd
│     │        │  │  ├─ process.pyx
│     │        │  │  ├─ stream.pxd
│     │        │  │  ├─ stream.pyx
│     │        │  │  ├─ streamserver.pxd
│     │        │  │  ├─ streamserver.pyx
│     │        │  │  ├─ tcp.pxd
│     │        │  │  ├─ tcp.pyx
│     │        │  │  ├─ timer.pxd
│     │        │  │  ├─ timer.pyx
│     │        │  │  ├─ udp.pxd
│     │        │  │  └─ udp.pyx
│     │        │  ├─ includes
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ consts.pxi
│     │        │  │  ├─ debug.pxd
│     │        │  │  ├─ flowcontrol.pxd
│     │        │  │  ├─ python.pxd
│     │        │  │  ├─ stdlib.pxi
│     │        │  │  ├─ system.pxd
│     │        │  │  └─ uv.pxd
│     │        │  ├─ loop.cpython-312-darwin.so
│     │        │  ├─ loop.pxd
│     │        │  ├─ loop.pyi
│     │        │  ├─ loop.pyx
│     │        │  ├─ lru.pyx
│     │        │  ├─ pseudosock.pyx
│     │        │  ├─ py.typed
│     │        │  ├─ request.pxd
│     │        │  ├─ request.pyx
│     │        │  ├─ server.pxd
│     │        │  ├─ server.pyx
│     │        │  ├─ sslproto.pxd
│     │        │  └─ sslproto.pyx
│     │        ├─ uvloop-0.21.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE-APACHE
│     │        │  ├─ LICENSE-MIT
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ version-info.toml
│     │        ├─ watchfiles
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ _rust_notify.cpython-312-darwin.so
│     │        │  ├─ _rust_notify.pyi
│     │        │  ├─ cli.py
│     │        │  ├─ filters.py
│     │        │  ├─ main.py
│     │        │  ├─ py.typed
│     │        │  ├─ run.py
│     │        │  └─ version.py
│     │        ├─ watchfiles-1.1.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  └─ licenses
│     │        │     └─ LICENSE
│     │        ├─ wcwidth
│     │        │  ├─ __init__.py
│     │        │  ├─ table_vs16.py
│     │        │  ├─ table_wide.py
│     │        │  ├─ table_zero.py
│     │        │  ├─ unicode_versions.py
│     │        │  └─ wcwidth.py
│     │        ├─ wcwidth-0.2.13.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ top_level.txt
│     │        │  └─ zip-safe
│     │        ├─ websockets
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ asyncio
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ async_timeout.py
│     │        │  │  ├─ client.py
│     │        │  │  ├─ compatibility.py
│     │        │  │  ├─ connection.py
│     │        │  │  ├─ messages.py
│     │        │  │  ├─ router.py
│     │        │  │  └─ server.py
│     │        │  ├─ auth.py
│     │        │  ├─ cli.py
│     │        │  ├─ client.py
│     │        │  ├─ connection.py
│     │        │  ├─ datastructures.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ extensions
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ base.py
│     │        │  │  └─ permessage_deflate.py
│     │        │  ├─ frames.py
│     │        │  ├─ headers.py
│     │        │  ├─ http.py
│     │        │  ├─ http11.py
│     │        │  ├─ imports.py
│     │        │  ├─ legacy
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ auth.py
│     │        │  │  ├─ client.py
│     │        │  │  ├─ exceptions.py
│     │        │  │  ├─ framing.py
│     │        │  │  ├─ handshake.py
│     │        │  │  ├─ http.py
│     │        │  │  ├─ protocol.py
│     │        │  │  └─ server.py
│     │        │  ├─ protocol.py
│     │        │  ├─ py.typed
│     │        │  ├─ server.py
│     │        │  ├─ speedups.c
│     │        │  ├─ speedups.cpython-312-darwin.so
│     │        │  ├─ speedups.pyi
│     │        │  ├─ streams.py
│     │        │  ├─ sync
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ client.py
│     │        │  │  ├─ connection.py
│     │        │  │  ├─ messages.py
│     │        │  │  ├─ router.py
│     │        │  │  ├─ server.py
│     │        │  │  └─ utils.py
│     │        │  ├─ typing.py
│     │        │  ├─ uri.py
│     │        │  ├─ utils.py
│     │        │  └─ version.py
│     │        ├─ websockets-15.0.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  ├─ entry_points.txt
│     │        │  └─ top_level.txt
│     │        ├─ werkzeug
│     │        │  ├─ __init__.py
│     │        │  ├─ _internal.py
│     │        │  ├─ _reloader.py
│     │        │  ├─ datastructures
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ accept.py
│     │        │  │  ├─ auth.py
│     │        │  │  ├─ cache_control.py
│     │        │  │  ├─ csp.py
│     │        │  │  ├─ etag.py
│     │        │  │  ├─ file_storage.py
│     │        │  │  ├─ headers.py
│     │        │  │  ├─ mixins.py
│     │        │  │  ├─ range.py
│     │        │  │  └─ structures.py
│     │        │  ├─ debug
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ console.py
│     │        │  │  ├─ repr.py
│     │        │  │  ├─ shared
│     │        │  │  │  ├─ ICON_LICENSE.md
│     │        │  │  │  ├─ console.png
│     │        │  │  │  ├─ debugger.js
│     │        │  │  │  ├─ less.png
│     │        │  │  │  ├─ more.png
│     │        │  │  │  └─ style.css
│     │        │  │  └─ tbtools.py
│     │        │  ├─ exceptions.py
│     │        │  ├─ formparser.py
│     │        │  ├─ http.py
│     │        │  ├─ local.py
│     │        │  ├─ middleware
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ dispatcher.py
│     │        │  │  ├─ http_proxy.py
│     │        │  │  ├─ lint.py
│     │        │  │  ├─ profiler.py
│     │        │  │  ├─ proxy_fix.py
│     │        │  │  └─ shared_data.py
│     │        │  ├─ py.typed
│     │        │  ├─ routing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ converters.py
│     │        │  │  ├─ exceptions.py
│     │        │  │  ├─ map.py
│     │        │  │  ├─ matcher.py
│     │        │  │  └─ rules.py
│     │        │  ├─ sansio
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ http.py
│     │        │  │  ├─ multipart.py
│     │        │  │  ├─ request.py
│     │        │  │  ├─ response.py
│     │        │  │  └─ utils.py
│     │        │  ├─ security.py
│     │        │  ├─ serving.py
│     │        │  ├─ test.py
│     │        │  ├─ testapp.py
│     │        │  ├─ urls.py
│     │        │  ├─ user_agent.py
│     │        │  ├─ utils.py
│     │        │  ├─ wrappers
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ request.py
│     │        │  │  └─ response.py
│     │        │  └─ wsgi.py
│     │        ├─ werkzeug-3.1.3.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  └─ WHEEL
│     │        ├─ wheel
│     │        │  ├─ __init__.py
│     │        │  ├─ __main__.py
│     │        │  ├─ _bdist_wheel.py
│     │        │  ├─ _setuptools_logging.py
│     │        │  ├─ bdist_wheel.py
│     │        │  ├─ cli
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ convert.py
│     │        │  │  ├─ pack.py
│     │        │  │  ├─ tags.py
│     │        │  │  └─ unpack.py
│     │        │  ├─ macosx_libfile.py
│     │        │  ├─ metadata.py
│     │        │  ├─ util.py
│     │        │  ├─ vendored
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ packaging
│     │        │  │  │  ├─ LICENSE
│     │        │  │  │  ├─ LICENSE.APACHE
│     │        │  │  │  ├─ LICENSE.BSD
│     │        │  │  │  ├─ __init__.py
│     │        │  │  │  ├─ _elffile.py
│     │        │  │  │  ├─ _manylinux.py
│     │        │  │  │  ├─ _musllinux.py
│     │        │  │  │  ├─ _parser.py
│     │        │  │  │  ├─ _structures.py
│     │        │  │  │  ├─ _tokenizer.py
│     │        │  │  │  ├─ markers.py
│     │        │  │  │  ├─ requirements.py
│     │        │  │  │  ├─ specifiers.py
│     │        │  │  │  ├─ tags.py
│     │        │  │  │  ├─ utils.py
│     │        │  │  │  └─ version.py
│     │        │  │  └─ vendor.txt
│     │        │  └─ wheelfile.py
│     │        ├─ wheel-0.45.1.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE.txt
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  ├─ WHEEL
│     │        │  └─ entry_points.txt
│     │        ├─ wsproto
│     │        │  ├─ __init__.py
│     │        │  ├─ connection.py
│     │        │  ├─ events.py
│     │        │  ├─ extensions.py
│     │        │  ├─ frame_protocol.py
│     │        │  ├─ handshake.py
│     │        │  ├─ py.typed
│     │        │  ├─ typing.py
│     │        │  └─ utilities.py
│     │        ├─ wsproto-1.2.0.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ LICENSE
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ WHEEL
│     │        │  └─ top_level.txt
│     │        ├─ xgboost
│     │        │  ├─ .dylibs
│     │        │  │  └─ libomp.dylib
│     │        │  ├─ VERSION
│     │        │  ├─ __init__.py
│     │        │  ├─ _typing.py
│     │        │  ├─ callback.py
│     │        │  ├─ collective.py
│     │        │  ├─ compat.py
│     │        │  ├─ config.py
│     │        │  ├─ core.py
│     │        │  ├─ dask.py
│     │        │  ├─ data.py
│     │        │  ├─ federated.py
│     │        │  ├─ lib
│     │        │  │  └─ libxgboost.dylib
│     │        │  ├─ libpath.py
│     │        │  ├─ plotting.py
│     │        │  ├─ py.typed
│     │        │  ├─ rabit.py
│     │        │  ├─ sklearn.py
│     │        │  ├─ spark
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ core.py
│     │        │  │  ├─ data.py
│     │        │  │  ├─ estimator.py
│     │        │  │  ├─ params.py
│     │        │  │  └─ utils.py
│     │        │  ├─ testing
│     │        │  │  ├─ __init__.py
│     │        │  │  ├─ dask.py
│     │        │  │  ├─ data.py
│     │        │  │  ├─ data_iter.py
│     │        │  │  ├─ metrics.py
│     │        │  │  ├─ params.py
│     │        │  │  ├─ ranking.py
│     │        │  │  ├─ shared.py
│     │        │  │  └─ updater.py
│     │        │  ├─ tracker.py
│     │        │  └─ training.py
│     │        ├─ xgboost-2.0.3.dist-info
│     │        │  ├─ INSTALLER
│     │        │  ├─ METADATA
│     │        │  ├─ RECORD
│     │        │  ├─ REQUESTED
│     │        │  └─ WHEEL
│     │        ├─ yaml
│     │        │  ├─ __init__.py
│     │        │  ├─ _yaml.cpython-312-darwin.so
│     │        │  ├─ composer.py
│     │        │  ├─ constructor.py
│     │        │  ├─ cyaml.py
│     │        │  ├─ dumper.py
│     │        │  ├─ emitter.py
│     │        │  ├─ error.py
│     │        │  ├─ events.py
│     │        │  ├─ loader.py
│     │        │  ├─ nodes.py
│     │        │  ├─ parser.py
│     │        │  ├─ reader.py
│     │        │  ├─ representer.py
│     │        │  ├─ resolver.py
│     │        │  ├─ scanner.py
│     │        │  ├─ serializer.py
│     │        │  └─ tokens.py
│     │        ├─ zstandard
│     │        │  ├─ __init__.py
│     │        │  ├─ __init__.pyi
│     │        │  ├─ _cffi.cpython-312-darwin.so
│     │        │  ├─ backend_c.cpython-312-darwin.so
│     │        │  ├─ backend_cffi.py
│     │        │  └─ py.typed
│     │        └─ zstandard-0.23.0.dist-info
│     │           ├─ INSTALLER
│     │           ├─ LICENSE
│     │           ├─ METADATA
│     │           ├─ RECORD
│     │           ├─ WHEEL
│     │           └─ top_level.txt
│     └─ pyvenv.cfg
├─ elise-src-20250902.zip
├─ enhanced_ml_dashboard.html
├─ frontend
│  ├─ .next
│  │  ├─ app-build-manifest.json
│  │  ├─ build
│  │  │  └─ chunks
│  │  │     ├─ [turbopack]_runtime.js
│  │  │     └─ [turbopack]_runtime.js.map
│  │  ├─ build-manifest.json
│  │  ├─ cache
│  │  │  ├─ .rscinfo
│  │  │  └─ chrome-devtools-workspace-uuid
│  │  ├─ fallback-build-manifest.json
│  │  ├─ package.json
│  │  ├─ postcss.js
│  │  ├─ postcss.js.map
│  │  ├─ prerender-manifest.json
│  │  ├─ routes-manifest.json
│  │  ├─ server
│  │  │  ├─ app
│  │  │  │  ├─ favicon.ico
│  │  │  │  │  ├─ route
│  │  │  │  │  │  ├─ app-build-manifest.json
│  │  │  │  │  │  ├─ app-paths-manifest.json
│  │  │  │  │  │  └─ build-manifest.json
│  │  │  │  │  ├─ route.js
│  │  │  │  │  └─ route.js.map
│  │  │  │  ├─ page
│  │  │  │  │  ├─ app-build-manifest.json
│  │  │  │  │  ├─ app-paths-manifest.json
│  │  │  │  │  ├─ build-manifest.json
│  │  │  │  │  ├─ next-font-manifest.json
│  │  │  │  │  ├─ react-loadable-manifest.json
│  │  │  │  │  └─ server-reference-manifest.json
│  │  │  │  ├─ page.js
│  │  │  │  ├─ page.js.map
│  │  │  │  └─ page_client-reference-manifest.js
│  │  │  ├─ app-paths-manifest.json
│  │  │  ├─ chunks
│  │  │  │  ├─ [turbopack]_runtime.js
│  │  │  │  ├─ [turbopack]_runtime.js.map
│  │  │  │  └─ ssr
│  │  │  │     ├─ [externals]_next_dist_shared_lib_no-fallback-error_external_d7a8835d.js
│  │  │  │     ├─ [externals]_next_dist_shared_lib_no-fallback-error_external_d7a8835d.js.map
│  │  │  │     ├─ [turbopack]_runtime.js
│  │  │  │     └─ [turbopack]_runtime.js.map
│  │  │  ├─ interception-route-rewrite-manifest.js
│  │  │  ├─ middleware-build-manifest.js
│  │  │  ├─ middleware-manifest.json
│  │  │  ├─ next-font-manifest.js
│  │  │  ├─ next-font-manifest.json
│  │  │  ├─ pages
│  │  │  │  ├─ _app
│  │  │  │  │  ├─ build-manifest.json
│  │  │  │  │  ├─ next-font-manifest.json
│  │  │  │  │  ├─ pages-manifest.json
│  │  │  │  │  └─ react-loadable-manifest.json
│  │  │  │  ├─ _app.js
│  │  │  │  ├─ _app.js.map
│  │  │  │  ├─ _document
│  │  │  │  │  ├─ next-font-manifest.json
│  │  │  │  │  ├─ pages-manifest.json
│  │  │  │  │  └─ react-loadable-manifest.json
│  │  │  │  ├─ _document.js
│  │  │  │  ├─ _document.js.map
│  │  │  │  ├─ _error
│  │  │  │  │  ├─ build-manifest.json
│  │  │  │  │  ├─ next-font-manifest.json
│  │  │  │  │  ├─ pages-manifest.json
│  │  │  │  │  └─ react-loadable-manifest.json
│  │  │  │  ├─ _error.js
│  │  │  │  └─ _error.js.map
│  │  │  ├─ pages-manifest.json
│  │  │  ├─ server-reference-manifest.js
│  │  │  └─ server-reference-manifest.json
│  │  ├─ static
│  │  │  ├─ chunks
│  │  │  │  ├─ pages
│  │  │  │  │  ├─ _app.js
│  │  │  │  │  └─ _error.js
│  │  │  │  ├─ src_app_layout_68b267f5.js
│  │  │  │  └─ src_app_page_cdd2739d.js
│  │  │  ├─ development
│  │  │  │  ├─ _buildManifest.js
│  │  │  │  ├─ _clientMiddlewareManifest.json
│  │  │  │  └─ _ssgManifest.js
│  │  │  └─ media
│  │  │     ├─ 8ee3a1ba4ed5baee-s.p.be19f591.woff2
│  │  │     ├─ 942c7eecbf9bc714-s.cb6bbcb1.woff2
│  │  │     ├─ 973faccb4f6aedb5-s.b7d310ad.woff2
│  │  │     ├─ b0a57561b6cb5495-s.p.da1ebef7.woff2
│  │  │     ├─ d26cc22533d232c7-s.81df3a5b.woff2
│  │  │     ├─ e5e2a9f48cda0a81-s.e32db976.woff2
│  │  │     └─ favicon.a4bca595.ico
│  │  └─ trace
│  ├─ README.md
│  ├─ eslint.config.mjs
│  ├─ jsconfig.json
│  ├─ next.config.mjs
│  ├─ package-lock.json
│  ├─ package.json
│  ├─ postcss.config.mjs
│  ├─ public
│  │  ├─ file.svg
│  │  ├─ globe.svg
│  │  ├─ next.svg
│  │  ├─ vercel.svg
│  │  └─ window.svg
│  └─ src
│     └─ app
│        ├─ api
│        │  └─ api.js
│        ├─ components
│        │  └─ CrawlForm.jsx
│        ├─ favicon.ico
│        ├─ globals.css
│        ├─ layout.js
│        ├─ page.js
│        └─ pages
│           └─ CrawlAndFuzzPage.jsx
├─ models
│  └─ ranker.joblib
├─ payloads
│  └─ temp
├─ test_enhanced_ml_frontend.html
├─ test_fixed_ml.py
├─ test_fuzzer_ml_integration.py
└─ verify_ml_authenticity.py

```
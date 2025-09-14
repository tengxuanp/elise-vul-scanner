from pathlib import Path
import sys

# Ensure repo root is on sys.path when running as a script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.modules.ml.sqli_dialect_infer import predict_sqli_dialect
from backend.modules.probes.sqli_triage import detect_sqli_dialect_ml

def main():
    samples = [
        ("MySQL", "You have an error in your SQL syntax", {"content-type": "text/html"}, 500),
        ("PostgreSQL", "ERROR: syntax error at or near", {"content-type": "text/html"}, 500),
        ("MSSQL", "Unclosed quotation mark after the character string.", {"content-type": "text/html"}, 500),
        ("SQLite", "SQLiteException: no such table", {"content-type": "text/html"}, 500),
        ("Unknown", "Database error occurred", {"content-type": "text/html"}, 500),
    ]

    print("-- Direct predictor --")
    for name, txt, hdrs, code in samples:
        out = predict_sqli_dialect(txt, hdrs, code)
        print(name, '->', out)

    print("\n-- Triage wrapper --")
    for name, txt, hdrs, code in samples:
        dialect, proba, source = detect_sqli_dialect_ml(txt, hdrs, code)
        print(name, '->', dialect, proba, source)

if __name__ == '__main__':
    main()

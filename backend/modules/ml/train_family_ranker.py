from __future__ import annotations
import joblib, pandas as pd, pathlib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

FAMILIES = ["sqli","xss","redirect","base"]

def train_family(df: pd.DataFrame):
    X, y = df["text"].values, df["y_family"].values
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1,2), min_df=2, max_features=30000)),
        ("clf", LogisticRegression(max_iter=400, solver="lbfgs", multi_class="auto"))
    ])
    pipe.fit(X, y)
    return pipe

def train_payload_ranker(df: pd.DataFrame, family: str, payloads_txt: list[str]):
    # Weak supervision fallback for payload ranking
    if not payloads_txt:
        return ("tfidf_only", None)
    try:
        from sklearn.svm import LinearSVC
        from sklearn.feature_extraction.text import TfidfVectorizer
        import numpy as np
        payload_df = pd.DataFrame({"payload": payloads_txt})
        vec = TfidfVectorizer(analyzer="char", ngram_range=(3,5), min_df=1)
        X = vec.fit_transform(payload_df["payload"])
        y = [1 if any(t in p.lower() for t in ["'", " or ", " union ", " select ", "--", "/*", "sleep(",
                                                "<script", "onerror", "onload", "alert(", "http://", "https://", "//"])
             else 0 for p in payloads_txt]
        clf = LinearSVC().fit(X, y)
        return ("svm", (vec, clf))
    except Exception:
        return ("tfidf_only", None)

def main():
    data_fp = "backend/modules/ml/data/family_corpus.csv"
    df = pd.read_csv(data_fp)
    out_dir = pathlib.Path("backend/modules/ml/models"); out_dir.mkdir(parents=True, exist_ok=True)

    fam_model = train_family(df)
    joblib.dump(fam_model, out_dir/"family_clf.joblib")

    from backend.modules.payloads import PAYLOADS_BY_FAMILY
    for fam, payloads in PAYLOADS_BY_FAMILY.items():
        tag, obj = train_payload_ranker(df, fam, payloads)
        joblib.dump((tag, obj), out_dir/f"ranker_{fam}.joblib")

    print("Saved models to", out_dir)

if __name__ == "__main__":
    main()

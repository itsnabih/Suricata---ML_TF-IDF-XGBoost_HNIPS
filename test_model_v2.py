#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script untuk model v2 (dual vectorizer: word + char + SQL keywords)
Mendukung override threshold agar bisa eksplorasi trade-off Precision/Recall.
"""
from __future__ import annotations
import argparse, json, re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import parse_qs, unquote_plus, urlparse

import joblib
import numpy as np
import scipy.sparse as sp
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

_RE_HTTP_LINE   = re.compile(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", re.IGNORECASE)
_RE_PATH_PREFIX = re.compile(r"^(?:/[^?#]*)?\?", re.IGNORECASE)

SQL_KEYWORDS = [
    "select","union","insert","update","delete","drop","create","alter",
    "truncate","exec","execute","xp_","sp_","sleep","benchmark","waitfor",
    "delay","having","order by","limit","where","from","information_schema",
    "sysobjects","pg_sleep","utl_","dbms_","extractvalue","updatexml",
    "load_file","outfile","dumpfile","concat","char(","chr(","ascii(",
    "substring","mid(","hex(","0x","cast(","convert(","ifnull","isnull",
    "or 1=1","and 1=1","or '1'='1","'='","1--"," --","#","/*","*/","/*!",
    "rlike","regexp","procedure","analyse","make_set","elt(","field(",
    "row(","exp(","floor(rand","group by","benchmark(","dbms_pipe",
]


def normalize_encoded(text: str, max_passes: int = 3) -> str:
    prev = None
    result = text
    for _ in range(max_passes):
        prev = result
        try:
            result = unquote_plus(result)
        except Exception:
            break
        if result == prev:
            break
    return result


_UA_SUFFIX = re.compile(r'\s+ua=\S+.*$', re.IGNORECASE)


def strip_bias_artifacts(text: str) -> str:
    """
    Buang token konfounding sebelum feature extraction:
    1. Suffix 'ua=Mozilla/5.0' (ditambahkan logger, bukan payload asli)
    2. Parameter '&Submit=Submit' (DVWA artifact - 100% korelasi dengan label attack)
    """
    text = _UA_SUFFIX.sub("", text).strip()
    if "Submit" in text or "submit" in text:
        text = re.sub(r'(?:&|(?<=\?))[Ss]ubmit=[^&\s#]*', '', text)
        text = re.sub(r'&{2,}', '&', text)
        text = re.sub(r'[?&]$', '', text).strip()
    return text



def extract_payload_text(raw: str, strip_param_names: bool = False) -> str:
    if not raw or not isinstance(raw, str):
        return ""
    text = raw.strip()
    text = _RE_HTTP_LINE.sub("", text).strip()
    if " HTTP/" in text:
        text = text.split(" HTTP/")[0]
    # Buang artifact yang menyebabkan bias dataset
    text = strip_bias_artifacts(text)
    query_string = ""
    if "://" in text:
        try:
            parsed = urlparse(text)
            query_string = parsed.query
        except Exception:
            pass
    elif text.startswith("/"):
        query_string = text.split("?", 1)[1] if "?" in text else ""
        if not query_string:
            return normalize_encoded(text)
    elif "=" in text and not text.startswith("'") and not text.startswith('"'):
        query_string = text
    if query_string:
        try:
            params = parse_qs(query_string, keep_blank_values=True)
            if params:
                if strip_param_names:
                    parts = [normalize_encoded(v) for vals in params.values() for v in vals if normalize_encoded(v)]
                    if parts:
                        return " ".join(parts)
                else:
                    parts = [f"{normalize_encoded(k)} {normalize_encoded(v)}" for k, vals in params.items() for v in vals]
                    if parts:
                        return " ".join(parts)
        except Exception:
            pass
    m = _RE_PATH_PREFIX.match(text)
    if m:
        text = text[m.end():]
    return normalize_encoded(text)


def extract_sql_keyword_features(texts: List[str]) -> sp.csr_matrix:
    n, k = len(texts), len(SQL_KEYWORDS)
    data, rows, cols = [], [], []
    for i, text in enumerate(texts):
        lower = text.lower()
        for j, kw in enumerate(SQL_KEYWORDS):
            if kw in lower:
                rows.append(i); cols.append(j); data.append(1.0)
    return sp.csr_matrix((data, (rows, cols)), shape=(n, k))


def build_features(texts, word_vec, char_vec):
    X_word = word_vec.transform(texts)
    X_char = char_vec.transform(texts)
    X_kw = extract_sql_keyword_features(texts)
    return sp.hstack([X_word, X_char, X_kw], format="csr")


@dataclass
class ModelArtifacts:
    threshold: float
    strip_param_names: bool
    word_vec: object
    char_vec: object
    selector: object
    model: object
    version: int


def load_artifacts(meta_path, vectorizer_path, model_path, selector_path=None) -> ModelArtifacts:
    meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))
    version = meta.get("version", 1)
    threshold = float(meta["threshold"])
    strip_param_names = meta.get("preprocessing", {}).get("strip_param_names", True)

    vec_data = joblib.load(vectorizer_path)

    if isinstance(vec_data, dict) and "word" in vec_data:
        # v2 dual vectorizer
        word_vec = vec_data["word"]
        char_vec = vec_data["char"]
    else:
        # v1 single vectorizer — wrap untuk kompatibilitas
        word_vec = vec_data
        char_vec = None

    model = joblib.load(model_path)
    selector = None
    if selector_path:
        p = Path(selector_path)
        if p.exists():
            selector = joblib.load(str(p))

    return ModelArtifacts(
        threshold=threshold, strip_param_names=strip_param_names,
        word_vec=word_vec, char_vec=char_vec,
        selector=selector, model=model, version=version
    )


def featurize(art: ModelArtifacts, raws: List[str]):
    cleaned = [extract_payload_text(x, art.strip_param_names) for x in raws]
    if art.char_vec is not None:
        X = build_features(cleaned, art.word_vec, art.char_vec)
    else:
        X = art.word_vec.transform(cleaned)
    if art.selector is not None:
        X = art.selector.transform(X)
    return cleaned, X


def predict_proba(art: ModelArtifacts, raws: List[str]):
    cleaned, X = featurize(art, raws)
    proba = art.model.predict_proba(X)[:, 1].astype(np.float64)
    return cleaned, proba


def parse_labeled_line(line: str):
    s = line.strip()
    if not s:
        return None
    seps = ["\t", "|", ","]
    parts = None
    used_sep = None
    for sep in seps:
        if sep in s:
            parts = [p.strip() for p in s.split(sep)]
            used_sep = sep
            break
    if not parts or len(parts) < 2:
        return None
    if len(parts) > 2 and used_sep == ",":
        payload = ",".join(parts[:-1]).strip()
        label = parts[-1].strip()
        return payload, label
    a, b = parts[0], parts[1]
    def is_label(x):
        return x.strip().lower() in ("attack","benign","1","0","true","false","pos","neg","positive","negative")
    if is_label(b) and not is_label(a):
        return a, b
    if is_label(a) and not is_label(b):
        return b, a
    return a, b


def label_to_int(label: str):
    t = label.strip().lower()
    if t in ("attack","1","true","pos","positive"):
        return 1
    if t in ("benign","0","false","neg","negative"):
        return 0
    return None


def eval_wordlist(art: ModelArtifacts, wordlist_path: str, override_threshold: float = None):
    p = Path(wordlist_path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {p.resolve()}")
    raws, y_true, skipped = [], [], 0
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        parsed = parse_labeled_line(line)
        if not parsed:
            skipped += 1
            continue
        payload, label_str = parsed
        y = label_to_int(label_str)
        if y is None:
            skipped += 1
            continue
        raws.append(payload)
        y_true.append(y)
    if not raws:
        raise ValueError("No labeled samples found in wordlist.")

    cleaned, proba = predict_proba(art, raws)
    thr = override_threshold if override_threshold is not None else art.threshold
    y_pred = (proba >= thr).astype(np.int32)
    y_true_arr = np.array(y_true, dtype=np.int32)

    acc   = accuracy_score(y_true_arr, y_pred)
    prec  = precision_score(y_true_arr, y_pred, zero_division=0)
    rec   = recall_score(y_true_arr, y_pred, zero_division=0)
    f1    = f1_score(y_true_arr, y_pred, zero_division=0)
    cm    = confusion_matrix(y_true_arr, y_pred, labels=[0, 1])

    print(f"=== EVALUATION (Model v{art.version}) ===")
    print(f"Samples used  : {len(y_true_arr)} (skipped: {skipped})")
    print(f"Threshold used: {thr:.8f}")
    print("")
    print(f"Accuracy : {acc:.6f}")
    print(f"Precision: {prec:.6f}")
    print(f"Recall   : {rec:.6f}")
    print(f"F1       : {f1:.6f}")
    print("")
    print("Confusion Matrix [ [TN FP], [FN TP] ]:")
    print(cm)
    tn, fp, fn, tp = cm[0,0], cm[0,1], cm[1,0], cm[1,1]
    print(f"TN={tn} FP={fp} FN={fn} TP={tp}")
    print("")
    print("Classification report:")
    print(classification_report(y_true_arr, y_pred, target_names=["benign(0)","attack(1)"], zero_division=0))

    mistakes = np.where(y_pred != y_true_arr)[0]
    if mistakes.size:
        print(f"\n=== TOP {min(10, len(mistakes))} MISTAKES ===")
        conf = np.abs(proba[mistakes] - thr)
        top = mistakes[np.argsort(conf)[::-1]][:10]
        for i in top:
            tl = "attack" if y_true_arr[i] == 1 else "benign"
            pl = "attack" if y_pred[i] == 1 else "benign"
            print(f"- true={tl:6s} pred={pl:6s} proba={proba[i]:.6f}")
            print(f"  clean: {cleaned[i][:120]}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Evaluate SQLi model v2")
    ap.add_argument("--meta",       default="model_meta.json")
    ap.add_argument("--vectorizer", default="tfidf_vectorizer.pkl")
    ap.add_argument("--model",      default="xgb_sqli_model.pkl")
    ap.add_argument("--selector",   default="feature_selector.pkl")
    ap.add_argument("--no-selector", action="store_true")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--wordlist",    help="Path to labeled wordlist")
    mode.add_argument("--payload",     help="Single payload to test")
    mode.add_argument("--interactive", action="store_true")
    ap.add_argument("--threshold",  type=float, default=None, help="Override threshold (default: from model_meta.json)")
    args = ap.parse_args()

    selector_path = None if args.no_selector else args.selector
    art = load_artifacts(args.meta, args.vectorizer, args.model, selector_path)

    if args.wordlist:
        return eval_wordlist(art, args.wordlist, override_threshold=args.threshold)

    if args.payload:
        cleaned, proba = predict_proba(art, [args.payload])
        thr = args.threshold if args.threshold is not None else art.threshold
        p = float(proba[0])
        print(f"Threshold   : {thr:.8f}")
        print(f"Probability : {p:.8f}")
        print(f"Decision    : {'BLOCK (attack)' if p >= thr else 'ALLOW (benign)'}")
        print(f"Clean text  : {cleaned[0]}")
        return 0

    if args.interactive:
        print(f"=== INTERACTIVE MODE (Model v{art.version}) ===")
        thr = args.threshold if args.threshold is not None else art.threshold
        print(f"Threshold: {thr:.8f}  (override with --threshold X.X)")
        print("Type :q to quit\n")
        while True:
            try:
                s = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not s or s.lower() in (":q", "quit", "exit"):
                break
            cleaned, proba = predict_proba(art, [s])
            p = float(proba[0])
            print(f"proba={p:.8f}  => {'BLOCK' if p >= thr else 'ALLOW'}")
            print(f"clean: {cleaned[0]}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

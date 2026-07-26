#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Dict

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

from urllib.parse import parse_qs, unquote_plus, urlparse

_RE_HTTP_LINE   = re.compile(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", re.IGNORECASE)
_RE_PATH_PREFIX = re.compile(r"^(?:/[^?#]*)?\?", re.IGNORECASE)
_RE_VALID_KEY   = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\.]*$")

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
 
def extract_payload_values(raw: str, strip_param_names: bool = True, max_decode_passes: int = 3) -> str:
    if not raw or not isinstance(raw, str):
        return ""

    text = raw.strip()
    text = _RE_HTTP_LINE.sub("", text).strip()

    if " HTTP/" in text:
        text = text.split(" HTTP/")[0]

    query_string = ""

    if "://" in text:
        try:
            parsed = urlparse(text)
            query_string = parsed.query
        except Exception:
            pass
    elif text.startswith("/"):
        if "?" in text:
            query_string = text.split("?", 1)[1]
        else:
            return normalize_encoded(text, max_passes=max_decode_passes)
    elif "=" in text and not text.startswith("'") and not text.startswith('"'):
        query_string = text

    if query_string:
        try:
            params = parse_qs(query_string, keep_blank_values=True)
            if params:
                if strip_param_names:
                    all_values = []
                    for vals in params.values():
                        for v in vals:
                            decoded = normalize_encoded(v, max_passes=max_decode_passes)
                            if decoded:
                                all_values.append(decoded)
                    if all_values:
                        return " ".join(all_values)
                else:
                    parts = []
                    for k, vals in params.items():
                        for v in vals:
                            parts.append(
                                f"{normalize_encoded(k, max_passes=max_decode_passes)}="
                                f"{normalize_encoded(v, max_passes=max_decode_passes)}"
                            )
                    if parts:
                        return " ".join(parts)
        except Exception:
            pass

    m = _RE_PATH_PREFIX.match(text)
    if m:
        text = text[m.end():]

    return normalize_encoded(text, max_passes=max_decode_passes)

@dataclass
class Artifacts:
    threshold: float
    strip_param_names: bool
    max_decode_passes: int
    vectorizer: object
    selector: Optional[object]
    model: object

def load_artifacts(meta_path: str, vectorizer_path: str, model_path: str, selector_path: Optional[str]) -> Artifacts:
    meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))

    vectorizer = joblib.load(vectorizer_path)
    model = joblib.load(model_path)

    selector = None
    if selector_path:
        p = Path(selector_path)
        if p.exists():
            selector = joblib.load(str(p))

    threshold = float(meta["threshold"])
    preprocessing = meta.get("preprocessing", {})
    strip_param_names = bool(preprocessing.get("strip_param_names", True))
    max_decode_passes = int(preprocessing.get("max_decode_passes", 3))

    return Artifacts(
        threshold=threshold,
        strip_param_names=strip_param_names,
        max_decode_passes=max_decode_passes,
        vectorizer=vectorizer,
        selector=selector,
        model=model,
    )

def featurize(art: Artifacts, raws: List[str]):
    cleaned = [
        extract_payload_values(x, art.strip_param_names, art.max_decode_passes)
        for x in raws
    ]
    X = art.vectorizer.transform(cleaned)
    if art.selector is not None:
        X = art.selector.transform(X)
    return cleaned, X

def predict_proba(art: Artifacts, raws: List[str]) -> Tuple[List[str], np.ndarray]:
    cleaned, X = featurize(art, raws)
    proba = art.model.predict_proba(X)[:, 1].astype(np.float64)
    return cleaned, proba

def parse_labeled_line(line: str) -> Optional[Tuple[str, str]]:
    """
    Return (payload, label_str) or None if cannot parse.
    Accepts separators: comma, tab, pipe. Tries to auto-detect where label is.
    """
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

    def is_label(x: str) -> bool:
        t = x.strip().lower()
        return t in ("attack", "benign", "1", "0", "true", "false", "pos", "neg", "positive", "negative")

    if is_label(b) and not is_label(a):
        return a, b
    if is_label(a) and not is_label(b):
        return b, a

    return a, b

def label_to_int(label: str) -> Optional[int]:
    t = label.strip().lower()
    if t in ("attack", "1", "true", "pos", "positive"):
        return 1
    if t in ("benign", "0", "false", "neg", "negative"):
        return 0
    return None

def eval_wordlist(art: Artifacts, wordlist_path: str, allow_unlabeled: bool = False) -> int:
    p = Path(wordlist_path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {p.resolve()}")

    raws: List[str] = []
    y_true: List[int] = []
    skipped = 0
    unlabeled = 0

    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        parsed = parse_labeled_line(line)
        if not parsed:
            skipped += 1
            continue
        payload, label_str = parsed
        y = label_to_int(label_str)
        if y is None:
            if allow_unlabeled:
                unlabeled += 1
                continue
            skipped += 1
            continue
        raws.append(payload)
        y_true.append(y)

    if not raws:
        raise ValueError("No labeled samples parsed from wordlist. Pastikan formatnya benar (payload,label atau label,payload).")

    cleaned, proba = predict_proba(art, raws)
    y_pred = (proba >= art.threshold).astype(np.int32)

    y_true_arr = np.array(y_true, dtype=np.int32)
    acc = accuracy_score(y_true_arr, y_pred)
    prec = precision_score(y_true_arr, y_pred, zero_division=0)
    rec = recall_score(y_true_arr, y_pred, zero_division=0)
    f1 = f1_score(y_true_arr, y_pred, zero_division=0)
    cm = confusion_matrix(y_true_arr, y_pred, labels=[0, 1])

    print("=== EVALUATION (WORDLIST) ===")
    print(f"Samples used: {len(y_true_arr)}")
    print(f"Skipped lines: {skipped}")
    if allow_unlabeled:
        print(f"Unlabeled lines ignored: {unlabeled}")
    print(f"Threshold: {art.threshold:.8f}")
    print("")
    print(f"Accuracy : {acc:.6f}")
    print(f"Precision: {prec:.6f}")
    print(f"Recall   : {rec:.6f}")
    print(f"F1       : {f1:.6f}")
    print("")
    print("Confusion Matrix [ [TN FP], [FN TP] ]:")
    print(cm)
    print("")
    print("Classification report:")
    print(classification_report(y_true_arr, y_pred, target_names=["benign(0)", "attack(1)"], zero_division=0))

    mistakes = np.where(y_pred != y_true_arr)[0]
    if mistakes.size:
        print("\n=== TOP MISTAKES (by confidence) ===")
        conf = np.abs(proba[mistakes] - art.threshold)
        top = mistakes[np.argsort(conf)[::-1]][:10]
        for i in top:
            true_lbl = "attack" if y_true_arr[i] == 1 else "benign"
            pred_lbl = "attack" if y_pred[i] == 1 else "benign"
            print(f"- true={true_lbl:6s} pred={pred_lbl:6s} proba_attack={proba[i]:.6f}")
            print(f"  clean: {cleaned[i][:160]}")
            print(f"  raw  : {raws[i][:160]}")
    else:
        print("\nNo mistakes found in this wordlist sample set.")

    return 0

def test_single(art: Artifacts, payload: str) -> int:
    cleaned, proba = predict_proba(art, [payload])
    p = float(proba[0])
    blocked = p >= art.threshold
    print("=== SINGLE TEST ===")
    print(f"Threshold       : {art.threshold:.8f}")
    print(f"proba_attack    : {p:.8f}")
    print(f"decision        : {'BLOCK (attack)' if blocked else 'ALLOW (benign)'}")
    print(f"clean_payload   : {cleaned[0]}")
    print(f"raw_input       : {payload}")
    return 0

def interactive_mode(art: Artifacts) -> int:
    print("=== INTERACTIVE MODE ===")
    print("Paste payload/URL/HTTP line. Type ':q' to quit.")
    print(f"Threshold: {art.threshold:.8f}\n")
    while True:
        try:
            s = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return 0
        if not s:
            continue
        if s.lower() in (":q", "quit", "exit"):
            return 0
        cleaned, proba = predict_proba(art, [s])
        p = float(proba[0])
        blocked = p >= art.threshold
        print(f"proba_attack={p:.8f}  =>  {'BLOCK' if blocked else 'ALLOW'}")
        print(f"clean: {cleaned[0]}\n")

def parse_args():
    ap = argparse.ArgumentParser(description="Evaluate/test existing SQLi model artifacts.")
    ap.add_argument("--meta", default="model_meta.json")
    ap.add_argument("--vectorizer", default="tfidf_vectorizer.pkl")
    ap.add_argument("--model", default="xgb_sqli_model.pkl")
    ap.add_argument("--selector", default="feature_selector.pkl")
    ap.add_argument("--no-selector", action="store_true", help="Ignore selector even if file exists.")

    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--wordlist", help="Path to labeled wordlist for accuracy evaluation.")
    mode.add_argument("--payload", help="Single payload/URL for manual test.")
    mode.add_argument("--interactive", action="store_true", help="Interactive manual testing.")

    ap.add_argument("--allow-unlabeled", action="store_true", help="Ignore unlabeled lines instead of counting as skipped.")
    return ap.parse_args()

def main() -> int:
    args = parse_args()
    selector_path = None if args.no_selector else args.selector

    art = load_artifacts(args.meta, args.vectorizer, args.model, selector_path)

    for f in (args.meta, args.vectorizer, args.model):
        if not Path(f).exists():
            raise FileNotFoundError(f"Missing required file: {Path(f).resolve()}")
    if (not args.no_selector) and args.selector and (not Path(args.selector).exists()):
        pass

    if args.wordlist:
        return eval_wordlist(art, args.wordlist, allow_unlabeled=args.allow_unlabeled)
    if args.payload:
        return test_single(art, args.payload)
    if args.interactive:
        return interactive_mode(art)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

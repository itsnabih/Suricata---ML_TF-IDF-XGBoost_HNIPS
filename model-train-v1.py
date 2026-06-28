#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLi IPS Model Training - Fixed Version
========================================
Perbaikan utama:
  1. PayloadExtractor: ekstrak nilai query-param dari URL, fallback ke raw text
  2. Normalisasi: URL-decode bertingkat, strip path/host, lowercase opsional
  3. Char n-gram HANYA atas payload bersih → model tidak lagi belajar "?id=", "F%2F", dll
  4. Opsi --strip-param-names  untuk membuang nama param (default ON)
  5. Preprocessing diuji via show_preprocessing_samples()
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, unquote_plus, urlparse

import joblib
import numpy as np
import pandas as pd
import xgboost
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

warnings.filterwarnings("ignore", category=FutureWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

POS_LABEL = "attack"
NEG_LABEL = "benign"

XGBOOST_VERSION = tuple(map(int, xgboost.__version__.split(".")[:2]))
XGBOOST_MAJOR = XGBOOST_VERSION[0]

# ── Regex helpers ──────────────────────────────────────────────────────────
_RE_HTTP_LINE   = re.compile(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", re.IGNORECASE)
_RE_PATH_PREFIX = re.compile(r"^(?:/[^?#]*)?\?", re.IGNORECASE)
# Key parameter URL yang valid: dimulai huruf/underscore, hanya alfanumerik/underscore/minus/titik
_RE_VALID_KEY   = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\.]*$")


def _looks_like_query_string(text: str) -> bool:
    """
    Heuristik untuk membedakan query string (key=value) dari raw SQL payload.
    Prinsip: key yang valid adalah identifier (huruf/underscore di depan).
    Contoh yang BUKAN query string: "1' OR '1'='1", "1+OR+1=1"
    Contoh yang ADALAH query string: "id=1' OR '1'='1", "q=hello"
    """
    if "=" not in text:
        return False
    # Decode satu pass untuk normalisasi (menangani id%3D1 → id=1)
    try:
        decoded = unquote_plus(text)
    except Exception:
        decoded = text
    first_eq = decoded.index("=")
    key_part = decoded[:first_eq].strip()
    return bool(_RE_VALID_KEY.match(key_part))


# ═══════════════════════════════════════════════════════════════════════════
#  PAYLOAD EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════

def normalize_encoded(text: str, max_passes: int = 3) -> str:
    """URL-decode secara bertingkat (menangani double/triple encoding)."""
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


def extract_payload_values(raw: str, strip_param_names: bool = True) -> str:
    """
    Ekstrak nilai-nilai query parameter dari sebuah string yang mungkin berupa:
      - URL lengkap   : http://site.com/page.php?id=1'+OR+'1'='1&cat=2
      - Query string  : id=1'+OR+'1'='1&cat=2
      - Raw payload   : 1' OR '1'='1
      - HTTP req line : GET /page.php?id=1'-- HTTP/1.1

    Strategi:
      1. Coba parse sebagai URL / query string → ambil VALUES saja (bukan nama param)
      2. Jika tidak ada query string, normalisasi lalu kembalikan seluruh text
      3. Selalu URL-decode bertingkat sebelum dikembalikan
    """
    if not raw or not isinstance(raw, str):
        return ""

    text = raw.strip()

    # Hapus HTTP method prefix (GET /... atau POST /...)
    text = _RE_HTTP_LINE.sub("", text).strip()

    # Ambil bagian sebelum " HTTP/1.x" kalau ada
    if " HTTP/" in text:
        text = text.split(" HTTP/")[0]

    # ── Coba parse sebagai URL / query string ──────────────────────────────
    query_string = ""

    # Kasus 1: ada "://" → URL lengkap
    if "://" in text:
        try:
            parsed = urlparse(text)
            query_string = parsed.query
        except Exception:
            pass

    # Kasus 2: dimulai dengan path "/..." + "?" → strip path dulu
    elif text.startswith("/"):
        if "?" in text:
            query_string = text.split("?", 1)[1]
        else:
            # path tanpa query string → kembalikan bersih
            return normalize_encoded(text)

    # Kasus 3: mengandung "=" → kemungkinan query string atau key=value
    elif "=" in text and not text.startswith("'") and not text.startswith('"'):
        # Kalau ada "&" atau hanya satu "=", anggap query string
        query_string = text

    # ── Ekstrak values dari query string ──────────────────────────────────
    if query_string:
        try:
            # parse_qs decode otomatis
            params = parse_qs(query_string, keep_blank_values=True)
            if params:
                if strip_param_names:
                    # Hanya ambil nilai, bukan nama parameter
                    all_values = []
                    for vals in params.values():
                        for v in vals:
                            decoded = normalize_encoded(v)
                            if decoded:
                                all_values.append(decoded)
                    if all_values:
                        return " ".join(all_values)
                else:
                    # Sertakan key=value tapi decode keduanya
                    parts = []
                    for k, vals in params.items():
                        for v in vals:
                            parts.append(
                                f"{normalize_encoded(k)}={normalize_encoded(v)}"
                            )
                    if parts:
                        return " ".join(parts)
        except Exception:
            pass

    # ── Fallback: kembalikan text setelah strip path prefix & decode ───────
    # Strip path prefix kalau ada (/page.php?...)
    m = _RE_PATH_PREFIX.match(text)
    if m:
        text = text[m.end():]

    return normalize_encoded(text)


def preprocess_texts(
    texts: np.ndarray,
    strip_param_names: bool = True,
) -> List[str]:
    """Terapkan payload extraction ke seluruh array teks."""
    return [extract_payload_values(t, strip_param_names) for t in texts]


def show_preprocessing_samples(
    df: pd.DataFrame,
    cfg: "TrainConfig",
    n: int = 10,
) -> None:
    """Tampilkan sampel sebelum & sesudah preprocessing untuk QA."""
    logger.info("\n=== Preprocessing Samples (QA) ===")
    sample = df.sample(min(n, len(df)), random_state=cfg.seed)
    for _, row in sample.iterrows():
        raw = str(row[cfg.text_col])
        processed = extract_payload_values(raw, cfg.strip_param_names)
        label = row[cfg.label_col]
        logger.info(f"  [{label}]")
        logger.info(f"    RAW  : {raw[:120]}")
        logger.info(f"    CLEAN: {processed[:120]}")


# ═══════════════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TrainConfig:
    dataset_path: str
    text_col: str = "payload"
    label_col: str = "label"
    seed: int = 42

    # Preprocessing (BARU)
    strip_param_names: bool = True   # Buang nama parameter, ambil nilai saja
    max_decode_passes: int = 3       # Kedalaman URL-decode bertingkat

    # Splits
    test_size: float = 0.15
    val_size: float = 0.15

    # TF-IDF: char n-gram robust untuk urlencoded + obfuscation
    analyzer: str = "char"
    ngram_min: int = 2               # Dikurangi dari 3 → 2 karena payload lebih bersih
    ngram_max: int = 5
    min_df: int = 2
    max_features: int = 30000
    lowercase: bool = True           # True karena sudah di-strip, case obfuscation penting

    # Feature selection
    use_feature_selection: bool = True
    n_selected_features: int = 15000

    # XGBoost
    n_estimators: int = 1000
    learning_rate: float = 0.05
    max_depth: int = 6
    min_child_weight: float = 2.0
    subsample: float = 0.9
    colsample_bytree: float = 0.7
    reg_lambda: float = 2.0
    reg_alpha: float = 0.0
    gamma: float = 0.0
    n_jobs: int = max(1, os.cpu_count() or 1)
    tree_method: str = "hist"

    # IPS policy
    target_fpr: float = 0.001
    prefer_recall: bool = True
    use_cv_threshold: bool = False
    cv_folds: int = 3

    # Early stopping
    early_stopping_rounds: int = 50

    # Adversarial testing
    run_evasion_tests: bool = True

    # Feature importance
    show_top_features: int = 30

    # Hyperparameter tuning
    run_hyperparam_search: bool = False
    hyperparam_trials: int = 10

    # Output
    out_vectorizer: str = "tfidf_vectorizer.pkl"
    out_selector: str = "feature_selector.pkl"
    out_model: str = "xgb_sqli_model.pkl"
    out_meta: str = "model_meta.json"


# ═══════════════════════════════════════════════════════════════════════════
#  DATA LOADING
# ═══════════════════════════════════════════════════════════════════════════

def load_dataset(cfg: TrainConfig) -> pd.DataFrame:
    path = Path(cfg.dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path.resolve()}")

    encodings = ["utf-8", "latin-1", "iso-8859-1"]
    df = None
    for enc in encodings:
        try:
            df = pd.read_csv(path, encoding=enc, on_bad_lines="skip")
            logger.info(f"Loaded dataset with {enc} encoding")
            break
        except (UnicodeDecodeError, pd.errors.ParserError) as e:
            logger.warning(f"Failed ({enc}): {e}")

    if df is None:
        raise ValueError("Could not load dataset with any supported encoding")

    for col in (cfg.text_col, cfg.label_col):
        if col not in df.columns:
            raise ValueError(
                f"Missing column '{col}'. Found: {list(df.columns)}"
            )

    df[cfg.label_col] = df[cfg.label_col].astype(str).str.strip().str.lower()
    df = df[df[cfg.label_col].isin([NEG_LABEL, POS_LABEL])].copy()
    df[cfg.text_col] = df[cfg.text_col].astype(str)
    df = df[df[cfg.text_col].str.len() > 0].copy()

    initial = len(df)
    df = df.drop_duplicates(subset=[cfg.text_col, cfg.label_col]).reset_index(drop=True)
    removed = initial - len(df)
    if removed:
        logger.info(f"Removed {removed} duplicates")

    if df.empty or len(df) < 100:
        raise ValueError(f"Dataset too small after filtering: {len(df)} rows")

    attack = (df[cfg.label_col] == POS_LABEL).sum()
    benign = (df[cfg.label_col] == NEG_LABEL).sum()
    ratio = max(attack, benign) / max(1, min(attack, benign))
    if ratio > 100:
        logger.warning(f"Severe class imbalance {ratio:.1f}:1 (benign={benign}, attack={attack})")

    logger.info(f"Dataset loaded: {len(df)} rows (attack={attack}, benign={benign})")
    return df


def encode_labels(df: pd.DataFrame, cfg: TrainConfig) -> np.ndarray:
    return (df[cfg.label_col].values == POS_LABEL).astype(np.int32)


# ═══════════════════════════════════════════════════════════════════════════
#  METRICS
# ═══════════════════════════════════════════════════════════════════════════

def safe_rates_from_cm(cm: np.ndarray) -> Dict[str, float]:
    tn, fp = int(cm[0, 0]), int(cm[0, 1])
    fn, tp = int(cm[1, 0]), int(cm[1, 1])
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1 = (2 * precision * tpr / (precision + tpr)) if (precision + tpr) > 0 else 0.0
    return {
        "fpr": float(fpr), "fnr": float(fnr), "tpr": float(tpr),
        "tnr": float(tnr), "precision": float(precision), "f1": float(f1),
    }


def pick_threshold_by_target_fpr_fast(
    y_true: np.ndarray,
    proba: np.ndarray,
    target_fpr: float,
    prefer_recall: bool = True,
) -> Tuple[float, Dict[str, float]]:
    y_true = y_true.astype(np.int32)
    proba = proba.astype(np.float64)
    neg_scores = proba[y_true == 0]

    if neg_scores.size == 0:
        return 0.999999, {"fpr": 1.0, "fnr": 1.0, "tpr": 0.0, "tnr": 0.0, "precision": 0.0, "f1": 0.0}

    q = min(max(1.0 - float(target_fpr), 0.0), 1.0)
    thr = float(np.quantile(neg_scores, q, method="higher"))

    candidates = sorted(set([
        thr,
        float(np.nextafter(thr, 0.0)),
        float(np.nextafter(thr, 1.0)),
        float(np.quantile(neg_scores, min(1.0, q + 0.001), method="higher")),
        float(np.quantile(neg_scores, max(0.0, q - 0.001), method="higher")),
        float(np.quantile(neg_scores, min(1.0, q + 0.0005), method="higher")),
        float(np.quantile(neg_scores, max(0.0, q - 0.0005), method="higher")),
    ]))

    best_thr, best_info = thr, None
    for t in candidates:
        pred = (proba >= t).astype(np.int32)
        cm = confusion_matrix(y_true, pred, labels=[0, 1])
        rates = safe_rates_from_cm(cm)
        if rates["fpr"] <= target_fpr:
            if best_info is None:
                best_thr, best_info = float(t), rates
                continue
            if prefer_recall:
                if rates["tpr"] > best_info["tpr"] or (
                    rates["tpr"] == best_info["tpr"] and rates["precision"] > best_info["precision"]
                ):
                    best_thr, best_info = float(t), rates
            else:
                if rates["precision"] > best_info["precision"] or (
                    rates["precision"] == best_info["precision"] and rates["tpr"] > best_info["tpr"]
                ):
                    best_thr, best_info = float(t), rates

    if best_info is None:
        best_thr = float(np.max(neg_scores) + 1e-12)
        pred = (proba >= best_thr).astype(np.int32)
        cm = confusion_matrix(y_true, pred, labels=[0, 1])
        best_info = safe_rates_from_cm(cm)

    return best_thr, best_info


def evaluate(y_true: np.ndarray, proba: np.ndarray, thr: float) -> Dict:
    pred = (proba >= thr).astype(np.int32)
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    rates = safe_rates_from_cm(cm)
    uniq = np.unique(y_true)
    roc_auc = float(roc_auc_score(y_true, proba)) if len(uniq) > 1 else float("nan")
    ap = float(average_precision_score(y_true, proba)) if len(uniq) > 1 else float("nan")
    return {
        "threshold": float(thr),
        "roc_auc": roc_auc,
        "avg_precision": ap,
        "confusion_matrix": cm.tolist(),
        "rates": rates,
    }

# Evasion test
def test_evasion_techniques(
    model: XGBClassifier,
    vectorizer: TfidfVectorizer,
    selector: Optional[SelectKBest],
    threshold: float,
    strip_param_names: bool = True,
) -> Dict[str, Dict]:
    logger.info("\n=== Testing Evasion Techniques ===")

    evasions = {
        "baseline":             "http://site.com/page.php?id=1' OR '1'='1",
        "comment_injection":    "http://site.com/page.php?id=1'/**/OR/**/'1'='1",
        "comment_suffix":       "http://site.com/page.php?id=1' OR '1'='1'--",
        "tab_encoding":         "http://site.com/page.php?id=1'%09OR%09'1'='1",
        "double_encoding":      "http://site.com/page.php?id=1'%2509OR%2509'1'='1",
        "case_variation":       "http://site.com/page.php?id=1' oR '1'='1",
        "whitespace_mix":       "http://site.com/page.php?id=1'  OR  '1'='1",
        "null_byte":            "http://site.com/page.php?id=1'%00OR%00'1'='1",
        "union_select":         "http://site.com/page.php?id=1' UNION SELECT null,null,null--",
        "union_obfuscated":     "http://site.com/page.php?id=1'/**/UnIoN/**/SeLeCt/**/null--",
        "time_based":           "http://site.com/page.php?id=1' AND SLEEP(5)--",
        "boolean_based":        "http://site.com/page.php?id=1' AND 1=1--",
        "stacked_query":        "http://site.com/page.php?id=1'; DROP TABLE users--",
        "error_based":          "http://site.com/page.php?id=1' AND extractvalue(0,0)--",
        # testing for raw payload
        "raw_payload":          "1' OR '1'='1",
        "raw_union":            "1' UNION SELECT username,password FROM users--",
    }

    results = {}
    for name, payload in evasions.items():
        clean = extract_payload_values(payload, strip_param_names)
        vec = vectorizer.transform([clean])
        if selector is not None:
            vec = selector.transform(vec)
        prob = model.predict_proba(vec)[0, 1]
        blocked = prob >= threshold
        results[name] = {"payload": payload, "clean": clean, "probability": float(prob), "blocked": bool(blocked)}
        status = "✓ BLOCKED" if blocked else "✗ MISSED"
        logger.info(f"  {name:22s}: {prob:.6f} {status}  (clean: {clean[:60]})")

    rate = sum(1 for r in results.values() if r["blocked"]) / len(results)
    logger.info(f"\nEvasion Detection Rate: {rate:.2%}")
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  FEATURE IMPORTANCE
# ═══════════════════════════════════════════════════════════════════════════

def show_feature_importance(
    model: XGBClassifier,
    vectorizer: TfidfVectorizer,
    selector: Optional[SelectKBest],
    top_k: int = 30,
) -> List[Dict]:
    logger.info(f"\n=== Top {top_k} Attack Indicators ===")
    importances = model.feature_importances_

    if selector is not None:
        selected_indices = selector.get_support(indices=True)
        features = vectorizer.get_feature_names_out()[selected_indices]
    else:
        features = vectorizer.get_feature_names_out()

    top_idx = np.argsort(importances)[-top_k:][::-1]
    feature_list = []
    for rank, idx in enumerate(top_idx, 1):
        name = features[idx]
        imp = importances[idx]
        feature_list.append({"rank": rank, "feature": name, "importance": float(imp)})
        disp = name if len(name) <= 20 else name[:17] + "..."
        logger.info(f"  {rank:2d}. {disp:20s} -> {imp:.6f}")

    return feature_list


# ═══════════════════════════════════════════════════════════════════════════
#  HYPERPARAMETER SEARCH
# ═══════════════════════════════════════════════════════════════════════════

def hyperparameter_search(
    X_train, y_train, X_val, y_val,
    cfg: TrainConfig, scale_pos_weight: float,
) -> Dict:
    from sklearn.model_selection import RandomizedSearchCV

    logger.info(f"\n=== Hyperparameter Search ({cfg.hyperparam_trials} trials) ===")
    param_distributions = {
        "max_depth": [4, 5, 6, 7],
        "learning_rate": [0.03, 0.05, 0.07, 0.1],
        "min_child_weight": [1, 2, 3],
        "subsample": [0.8, 0.9, 1.0],
        "colsample_bytree": [0.6, 0.7, 0.8],
        "reg_lambda": [1.0, 2.0, 3.0],
        "reg_alpha": [0.0, 0.1, 0.5],
    }
    base = XGBClassifier(
        n_estimators=300, objective="binary:logistic", eval_metric="logloss",
        tree_method=cfg.tree_method, scale_pos_weight=scale_pos_weight,
        random_state=cfg.seed, n_jobs=cfg.n_jobs,
    )
    search = RandomizedSearchCV(
        base, param_distributions, n_iter=cfg.hyperparam_trials,
        scoring="average_precision", cv=3, random_state=cfg.seed, n_jobs=1, verbose=1,
    )
    X_arr = X_train.toarray() if hasattr(X_train, "toarray") else X_train
    search.fit(X_arr, y_train)
    logger.info(f"Best params: {search.best_params_}")
    logger.info(f"Best CV score: {search.best_score_:.6f}")
    return search.best_params_


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN TRAIN
# ═══════════════════════════════════════════════════════════════════════════

def train(cfg: TrainConfig) -> None:
    logger.info("=== SQLi IPS Model Training (Fixed - Payload-Aware) ===")
    logger.info(f"XGBoost version: {xgboost.__version__}")
    logger.info(f"Preprocessing: strip_param_names={cfg.strip_param_names}, "
                f"max_decode_passes={cfg.max_decode_passes}")

    # Load data
    df = load_dataset(cfg)
    y = encode_labels(df, cfg)
    X_text = df[cfg.text_col].values

    # ── QA: tampilkan sampel preprocessing ────────────────────────────────
    show_preprocessing_samples(df, cfg, n=6)

    # ── Split SEBELUM preprocessing (hindari data leakage) ────────────────
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_text, y, test_size=cfg.test_size, random_state=cfg.seed, stratify=y
    )
    val_ratio = cfg.val_size / (1.0 - cfg.test_size)
    X_train_raw, X_val_raw, y_train, y_val = train_test_split(
        X_train_raw, y_train, test_size=val_ratio, random_state=cfg.seed, stratify=y_train
    )

    logger.info(
        f"\nDataset: {len(df)} total | "
        f"Train: {len(y_train)} | Val: {len(y_val)} | Test: {len(y_test)}"
    )

    # ── Preprocessing: ekstrak payload bersih ─────────────────────────────
    logger.info("\n=== Preprocessing Payloads ===")
    X_train_text = preprocess_texts(X_train_raw, cfg.strip_param_names)
    X_val_text   = preprocess_texts(X_val_raw,   cfg.strip_param_names)
    X_test_text  = preprocess_texts(X_test_raw,  cfg.strip_param_names)

    # Sanity check: berapa persen yang berbeda dari raw?
    changed = sum(1 for a, b in zip(X_train_raw, X_train_text) if a != b)
    logger.info(
        f"Preprocessing changed {changed}/{len(X_train_raw)} "
        f"({changed/max(1,len(X_train_raw)):.1%}) train samples"
    )

    # ── TF-IDF ────────────────────────────────────────────────────────────
    logger.info("\n=== TF-IDF Vectorization ===")
    vectorizer = TfidfVectorizer(
        analyzer=cfg.analyzer,
        ngram_range=(cfg.ngram_min, cfg.ngram_max),
        min_df=cfg.min_df,
        max_features=cfg.max_features,
        lowercase=cfg.lowercase,
        # sublinear_tf mengurangi dominasi fitur frekuensi tinggi
        sublinear_tf=True,
    )
    X_train = vectorizer.fit_transform(X_train_text)
    X_val   = vectorizer.transform(X_val_text)
    X_test  = vectorizer.transform(X_test_text)
    logger.info(f"Initial features: {X_train.shape[1]:,}")

    # ── Feature selection ─────────────────────────────────────────────────
    selector = None
    if cfg.use_feature_selection and X_train.shape[1] > cfg.n_selected_features:
        logger.info(f"\n=== Feature Selection (top {cfg.n_selected_features:,}) ===")
        selector = SelectKBest(chi2, k=cfg.n_selected_features)
        X_train = selector.fit_transform(X_train, y_train)
        X_val   = selector.transform(X_val)
        X_test  = selector.transform(X_test)
        logger.info(f"Selected features: {X_train.shape[1]:,}")

    # ── Class weight ──────────────────────────────────────────────────────
    pos = max(1, int(y_train.sum()))
    neg = max(1, int((y_train == 0).sum()))
    scale_pos_weight = float(neg / pos)
    logger.info(
        f"\nClass balance: benign={neg} | attack={pos} | "
        f"scale_pos_weight={scale_pos_weight:.4f}"
    )

    # ── Hyperparameter search (opsional) ──────────────────────────────────
    best_params: Dict = {}
    if cfg.run_hyperparam_search:
        best_params = hyperparameter_search(X_train, y_train, X_val, y_val, cfg, scale_pos_weight)

    # ── Build & train model ───────────────────────────────────────────────
    model_params = {
        "n_estimators":    cfg.n_estimators,
        "learning_rate":   best_params.get("learning_rate",   cfg.learning_rate),
        "max_depth":       best_params.get("max_depth",       cfg.max_depth),
        "min_child_weight":best_params.get("min_child_weight",cfg.min_child_weight),
        "subsample":       best_params.get("subsample",       cfg.subsample),
        "colsample_bytree":best_params.get("colsample_bytree",cfg.colsample_bytree),
        "reg_lambda":      best_params.get("reg_lambda",      cfg.reg_lambda),
        "reg_alpha":       best_params.get("reg_alpha",       cfg.reg_alpha),
        "gamma":           cfg.gamma,
        "n_jobs":          cfg.n_jobs,
        "objective":       "binary:logistic",
        "eval_metric":     "logloss",
        "tree_method":     cfg.tree_method,
        "scale_pos_weight":scale_pos_weight,
        "random_state":    cfg.seed,
    }

    logger.info("\n=== Training XGBoost ===")
    logger.info(
        f"Parameters: n_estimators={cfg.n_estimators}, "
        f"max_depth={model_params['max_depth']}, "
        f"learning_rate={model_params['learning_rate']}"
    )

    if XGBOOST_MAJOR >= 3:
        model_params["early_stopping_rounds"] = cfg.early_stopping_rounds
        model = XGBClassifier(**model_params)
        model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=100)
    else:
        model = XGBClassifier(**model_params)
        model.fit(
            X_train, y_train,
            early_stopping_rounds=cfg.early_stopping_rounds,
            eval_set=[(X_val, y_val)],
            verbose=100,
        )

    logger.info(f"Training complete. Best iteration: {getattr(model, 'best_iteration', 'N/A')}")

    # ── Predictions ───────────────────────────────────────────────────────
    logger.info("\n=== Generating Predictions ===")
    proba_train = model.predict_proba(X_train)[:, 1]
    proba_val   = model.predict_proba(X_val)[:, 1]
    proba_test  = model.predict_proba(X_test)[:, 1]

    # ── Threshold tuning ──────────────────────────────────────────────────
    logger.info("\n=== Threshold Tuning ===")
    thr, thr_info = pick_threshold_by_target_fpr_fast(
        y_val, proba_val, cfg.target_fpr, cfg.prefer_recall
    )
    logger.info(
        f"Threshold: {thr:.6f} | "
        f"FPR={thr_info['fpr']:.6f} | TPR={thr_info['tpr']:.6f} | "
        f"F1={thr_info['f1']:.4f}"
    )

    # ── Evaluate ──────────────────────────────────────────────────────────
    train_metrics = evaluate(y_train, proba_train, thr)
    val_metrics   = evaluate(y_val,   proba_val,   thr)
    test_metrics  = evaluate(y_test,  proba_test,  thr)

    logger.info("\n=== Validation Metrics ===")
    for k in ("roc_auc", "avg_precision"):
        logger.info(f"  {k}: {val_metrics[k]:.4f}")
    for k in ("fpr", "tpr", "f1"):
        logger.info(f"  {k}: {val_metrics['rates'][k]:.6f}")

    logger.info("\n=== Test Metrics ===")
    for k in ("roc_auc", "avg_precision"):
        logger.info(f"  {k}: {test_metrics[k]:.4f}")
    for k in ("fpr", "tpr", "f1"):
        logger.info(f"  {k}: {test_metrics['rates'][k]:.6f}")

    # ── Feature importance ─────────────────────────────────────────────────
    top_features = show_feature_importance(model, vectorizer, selector, cfg.show_top_features)

    # ── Evasion tests ─────────────────────────────────────────────────────
    evasion_results = None
    if cfg.run_evasion_tests:
        evasion_results = test_evasion_techniques(
            model, vectorizer, selector, thr, cfg.strip_param_names
        )

    # ── Save artifacts ────────────────────────────────────────────────────
    logger.info("\n=== Saving Artifacts ===")
    joblib.dump(vectorizer, cfg.out_vectorizer)
    logger.info(f"✓ {cfg.out_vectorizer}")

    if selector is not None:
        joblib.dump(selector, cfg.out_selector)
        logger.info(f"✓ {cfg.out_selector}")

    joblib.dump(model, cfg.out_model)
    logger.info(f"✓ {cfg.out_model}")

    meta = {
        "pos_label": POS_LABEL,
        "neg_label": NEG_LABEL,
        "threshold": float(thr),
        "threshold_policy": f"target_fpr={cfg.target_fpr}, prefer_recall={cfg.prefer_recall}",
        "scale_pos_weight": float(scale_pos_weight),
        "best_iteration": getattr(model, "best_iteration", None),
        "best_score": getattr(model, "best_score", None),
        "xgboost_version": xgboost.__version__,
        "preprocessing": {
            "strip_param_names": cfg.strip_param_names,
            "max_decode_passes": cfg.max_decode_passes,
        },
        "n_features_initial": int(len(vectorizer.get_feature_names_out())),
        "n_features_selected": int(X_train.shape[1]) if selector is not None else None,
        "vectorizer": {
            "analyzer": cfg.analyzer,
            "ngram_range": [cfg.ngram_min, cfg.ngram_max],
            "min_df": cfg.min_df,
            "max_features": cfg.max_features,
            "lowercase": cfg.lowercase,
            "sublinear_tf": True,
        },
        "feature_selection": {
            "enabled": cfg.use_feature_selection,
            "n_selected": cfg.n_selected_features if selector else None,
        },
        "hyperparameter_search": {
            "enabled": cfg.run_hyperparam_search,
            "best_params": best_params if best_params else None,
        },
        "top_features": top_features,
        "evasion_tests": evasion_results,
        "metrics": {"train": train_metrics, "val": val_metrics, "test": test_metrics},
        "config": asdict(cfg),
    }
    Path(cfg.out_meta).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    logger.info(f"✓ {cfg.out_meta}")

    logger.info("\n=== Training Complete ===")
    logger.info(
        f"Final Test: FPR={test_metrics['rates']['fpr']:.6f} | "
        f"TPR={test_metrics['rates']['tpr']:.6f} | "
        f"F1={test_metrics['rates']['f1']:.4f} | "
        f"AUC={test_metrics['roc_auc']:.4f}"
    )


# ═══════════════════════════════════════════════════════════════════════════
#  INFERENCE HELPER  (untuk deployment / testing manual)
# ═══════════════════════════════════════════════════════════════════════════

class SQLiDetector:
    """
    Wrapper inference yang konsisten dengan pipeline training.
    Gunakan ini di production / WAF integration.

    Contoh:
        detector = SQLiDetector.load("model_meta.json", "tfidf_vectorizer.pkl",
                                      "xgb_sqli_model.pkl", "feature_selector.pkl")
        result = detector.predict("http://site.com/page.php?id=1' OR '1'='1")
        print(result)  # {"blocked": True, "probability": 0.998, "clean_payload": "1' or '1'='1"}
    """

    def __init__(
        self,
        vectorizer: TfidfVectorizer,
        model: XGBClassifier,
        threshold: float,
        selector: Optional[SelectKBest] = None,
        strip_param_names: bool = True,
    ):
        self.vectorizer = vectorizer
        self.model = model
        self.threshold = threshold
        self.selector = selector
        self.strip_param_names = strip_param_names

    @classmethod
    def load(
        cls,
        meta_path: str,
        vectorizer_path: str,
        model_path: str,
        selector_path: Optional[str] = None,
    ) -> "SQLiDetector":
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        vectorizer = joblib.load(vectorizer_path)
        model = joblib.load(model_path)
        selector = joblib.load(selector_path) if selector_path and Path(selector_path).exists() else None
        strip = meta.get("preprocessing", {}).get("strip_param_names", True)
        return cls(vectorizer, model, meta["threshold"], selector, strip)

    def predict(self, raw_input: str) -> Dict:
        clean = extract_payload_values(raw_input, self.strip_param_names)
        vec = self.vectorizer.transform([clean])
        if self.selector is not None:
            vec = self.selector.transform(vec)
        prob = float(self.model.predict_proba(vec)[0, 1])
        return {
            "blocked": prob >= self.threshold,
            "probability": prob,
            "clean_payload": clean,
            "raw_input": raw_input,
        }

    def predict_batch(self, inputs: List[str]) -> List[Dict]:
        cleaned = [extract_payload_values(x, self.strip_param_names) for x in inputs]
        vecs = self.vectorizer.transform(cleaned)
        if self.selector is not None:
            vecs = self.selector.transform(vecs)
        probs = self.model.predict_proba(vecs)[:, 1]
        return [
            {
                "blocked": float(p) >= self.threshold,
                "probability": float(p),
                "clean_payload": c,
                "raw_input": r,
            }
            for r, c, p in zip(inputs, cleaned, probs)
        ]


# ═══════════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> TrainConfig:
    p = argparse.ArgumentParser(
        description="Train TF-IDF + XGBoost SQLi IPS (Fixed - Payload-Aware Preprocessing)"
    )
    p.add_argument("--data", default="dataset-balanced.csv")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--test-size", type=float, default=0.15)
    p.add_argument("--val-size",  type=float, default=0.15)

    # Preprocessing (BARU)
    p.add_argument(
        "--no-strip-param-names", action="store_true",
        help="Sertakan nama parameter (key=value) bukan hanya nilai. Default: strip (hanya nilai)",
    )
    p.add_argument("--max-decode-passes", type=int, default=3)

    # TF-IDF
    p.add_argument("--min-df",        type=int,   default=2)
    p.add_argument("--max-features",  type=int,   default=30000)
    p.add_argument("--ngram-min",     type=int,   default=2)
    p.add_argument("--ngram-max",     type=int,   default=5)

    # Feature selection
    p.add_argument("--use-feature-selection", action="store_true", default=True)
    p.add_argument("--n-selected-features",   type=int, default=15000)

    # XGBoost
    p.add_argument("--n-estimators",          type=int,   default=1000)
    p.add_argument("--learning-rate",         type=float, default=0.05)
    p.add_argument("--max-depth",             type=int,   default=6)
    p.add_argument("--early-stopping-rounds", type=int,   default=50)

    # IPS policy
    p.add_argument("--target-fpr",      type=float, default=0.001)
    p.add_argument("--prefer-precision",action="store_true")
    p.add_argument("--use-cv-threshold",action="store_true")
    p.add_argument("--cv-folds",        type=int,   default=3)

    # Testing
    p.add_argument("--run-evasion-tests",  action="store_true", default=True)
    p.add_argument("--show-top-features",  type=int, default=30)

    # Optimization
    p.add_argument("--run-hyperparam-search", action="store_true")
    p.add_argument("--hyperparam-trials",     type=int, default=10)

    # Output
    p.add_argument("--out-vectorizer", default="tfidf_vectorizer.pkl")
    p.add_argument("--out-selector",   default="feature_selector.pkl")
    p.add_argument("--out-model",      default="xgb_sqli_model.pkl")
    p.add_argument("--out-meta",       default="model_meta.json")

    args = p.parse_args()
    return TrainConfig(
        dataset_path=args.data,
        seed=args.seed,
        test_size=args.test_size,
        val_size=args.val_size,
        strip_param_names=(not args.no_strip_param_names),
        max_decode_passes=args.max_decode_passes,
        min_df=args.min_df,
        max_features=args.max_features,
        ngram_min=args.ngram_min,
        ngram_max=args.ngram_max,
        use_feature_selection=args.use_feature_selection,
        n_selected_features=args.n_selected_features,
        n_estimators=args.n_estimators,
        learning_rate=args.learning_rate,
        max_depth=args.max_depth,
        target_fpr=args.target_fpr,
        prefer_recall=(not args.prefer_precision),
        use_cv_threshold=args.use_cv_threshold,
        cv_folds=args.cv_folds,
        early_stopping_rounds=args.early_stopping_rounds,
        run_evasion_tests=args.run_evasion_tests,
        show_top_features=args.show_top_features,
        run_hyperparam_search=args.run_hyperparam_search,
        hyperparam_trials=args.hyperparam_trials,
        out_vectorizer=args.out_vectorizer,
        out_selector=args.out_selector,
        out_model=args.out_model,
        out_meta=args.out_meta,
    )


if __name__ == "__main__":
    cfg = parse_args()
    train(cfg)
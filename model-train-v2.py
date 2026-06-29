#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLi IPS Model Training - v2 (Enhanced Recall)
================================================
Perbaikan v2 (vs v1):
  1. Dual TF-IDF: word n-gram (1-3) + char n-gram (2-5) digabung
     -> Model belajar kata kunci utuh (UNION, SELECT, SLEEP) sekaligus pola karakter
  2. Threshold dipilih berdasarkan F1-Score maksimal (bukan FPR target)
     -> Keseimbangan Precision/Recall lebih baik untuk dataset baru
  3. Preprocessing lebih lunak: strip_param_names=False (default)
     -> Konteks nama parameter (id=, name=) tetap tersimpan sebagai fitur
  4. Fitur keyword SQL manual (biner) ditambahkan ke feature matrix
"""

from __future__ import annotations
import argparse, json, logging, os, re, warnings
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, unquote_plus, urlparse

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp
import xgboost
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

warnings.filterwarnings("ignore", category=FutureWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)

POS_LABEL = "attack"
NEG_LABEL = "benign"
XGBOOST_MAJOR = int(xgboost.__version__.split(".")[0])

_RE_HTTP_LINE   = re.compile(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", re.IGNORECASE)
_RE_PATH_PREFIX = re.compile(r"^(?:/[^?#]*)?\?", re.IGNORECASE)
_RE_VALID_KEY   = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\.]*$")

# ── Bias artifact removal ─────────────────────────────────────────────────
# Parameter names yang berperilaku sebagai konfounding (muncul 100% di satu kelas)
# Submit=Submit: hanya ada di dataset DVWA attack, tidak di benign → pure bias
# ua=...: user-agent string, tidak relevan untuk SQL injection detection
_BIAS_PARAM_KEYS = re.compile(
    r"(?:^|&)Submit=[^&]*",  # parameter Submit (DVWA artifact)
    re.IGNORECASE
)
_UA_SUFFIX = re.compile(
    r"\s+ua=\S+.*$",  # trailing ' ua=Mozilla/5.0' yang sering ditambahkan logger
    re.IGNORECASE
)

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


def strip_bias_artifacts(text: str) -> str:
    """
    Buang token-token yang bersifat konfounding (menyebabkan bias dataset):
    1. Parameter Submit=Submit (DVWA artifact - muncul 100% di attack, 0% di benign)
    2. Suffix ' ua=Mozilla/5.0 ...' yang ditambahkan logger (bukan bagian dari payload)
    Operasi ini dilakukan SEBELUM URL parsing agar bersih dari awal.
    """
    # Buang suffix ua= (misalnya: ...Submit ua=Mozilla/5.0)
    text = _UA_SUFFIX.sub("", text).strip()
    # Buang parameter Submit dari query string jika ada
    # Handle encoded (%26Submit%3DSubmit) maupun plain (&Submit=Submit)
    if "Submit" in text or "submit" in text:
        # Decode dulu untuk menangkap yang masih encoded
        decoded_check = text
        try:
            from urllib.parse import unquote
            decoded_check = unquote(text)
        except Exception:
            pass
        # Buang &Submit=... atau Submit=... di awal query string
        text = re.sub(r'(?:&|(?<=\?))[Ss]ubmit=[^&\s#]*', '', text)
        # Cleanup double && atau trailing &
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

    # ── Buang artifact yang menyebabkan bias dataset ───────────────────────
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
                    parts = []
                    for vals in params.values():
                        for v in vals:
                            decoded = normalize_encoded(v)
                            if decoded:
                                parts.append(decoded)
                    if parts:
                        return " ".join(parts)
                else:
                    parts = []
                    for k, vals in params.items():
                        for v in vals:
                            parts.append(f"{normalize_encoded(k)} {normalize_encoded(v)}")
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


def preprocess_texts(texts, strip_param_names: bool = False) -> List[str]:
    return [extract_payload_text(t, strip_param_names) for t in texts]


@dataclass
class TrainConfig:
    dataset_path: str
    text_col: str = "payload"
    label_col: str = "label"
    seed: int = 42
    strip_param_names: bool = True
    max_decode_passes: int = 3
    test_size: float = 0.15
    val_size: float = 0.15
    word_ngram_min: int = 1
    word_ngram_max: int = 3
    word_max_features: int = 20000
    char_ngram_min: int = 2
    char_ngram_max: int = 5
    char_max_features: int = 20000
    min_df: int = 1
    lowercase: bool = True
    use_feature_selection: bool = True
    n_selected_features: int = 20000
    n_estimators: int = 1000
    learning_rate: float = 0.05
    max_depth: int = 7
    min_child_weight: float = 1.0
    subsample: float = 0.85
    colsample_bytree: float = 0.7
    reg_lambda: float = 1.0
    reg_alpha: float = 0.1
    gamma: float = 0.0
    n_jobs: int = max(1, os.cpu_count() or 1)
    tree_method: str = "hist"
    threshold_strategy: str = "f1_max"
    target_fpr: float = 0.01
    prefer_recall: bool = True
    early_stopping_rounds: int = 50
    run_evasion_tests: bool = True
    show_top_features: int = 30
    run_hyperparam_search: bool = False
    hyperparam_trials: int = 10
    out_vectorizer: str = "tfidf_vectorizer.pkl"
    out_selector: str = "feature_selector.pkl"
    out_model: str = "xgb_sqli_model.pkl"
    out_meta: str = "model_meta.json"


def load_dataset(cfg: TrainConfig) -> pd.DataFrame:
    path = Path(cfg.dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path.resolve()}")
    for enc in ["utf-8", "latin-1", "iso-8859-1"]:
        try:
            df = pd.read_csv(path, encoding=enc, on_bad_lines="skip")
            logger.info(f"Loaded dataset with {enc} encoding")
            break
        except Exception as e:
            logger.warning(f"Failed ({enc}): {e}")
            df = None
    if df is None:
        raise ValueError("Could not load dataset")
    for col in (cfg.text_col, cfg.label_col):
        if col not in df.columns:
            raise ValueError(f"Missing column '{col}'. Found: {list(df.columns)}")
    df[cfg.label_col] = df[cfg.label_col].astype(str).str.strip().str.lower()
    df = df[df[cfg.label_col].isin([NEG_LABEL, POS_LABEL])].copy()
    df[cfg.text_col] = df[cfg.text_col].astype(str)
    df = df[df[cfg.text_col].str.len() > 0].copy()
    initial = len(df)
    df = df.drop_duplicates(subset=[cfg.text_col, cfg.label_col]).reset_index(drop=True)
    removed = initial - len(df)
    if removed:
        logger.info(f"Removed {removed} duplicates")
    attack = (df[cfg.label_col] == POS_LABEL).sum()
    benign = (df[cfg.label_col] == NEG_LABEL).sum()
    logger.info(f"Dataset loaded: {len(df)} rows (attack={attack}, benign={benign})")
    return df


def encode_labels(df: pd.DataFrame, cfg: TrainConfig) -> np.ndarray:
    return (df[cfg.label_col].values == POS_LABEL).astype(np.int32)


def safe_rates_from_cm(cm: np.ndarray) -> Dict[str, float]:
    tn, fp = int(cm[0, 0]), int(cm[0, 1])
    fn, tp = int(cm[1, 0]), int(cm[1, 1])
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1 = (2 * precision * tpr / (precision + tpr)) if (precision + tpr) > 0 else 0.0
    return {"fpr": float(fpr), "tpr": float(tpr), "tnr": float(tnr),
            "precision": float(precision), "f1": float(f1),
            "tn": tn, "fp": fp, "fn": fn, "tp": tp}


def pick_threshold_f1_max(y_true: np.ndarray, proba: np.ndarray) -> Tuple[float, Dict]:
    thresholds = np.unique(np.percentile(proba, np.linspace(1, 99, 300)))
    best_thr, best_f1, best_info = 0.5, -1.0, {}
    for thr in thresholds:
        pred = (proba >= thr).astype(np.int32)
        cm = confusion_matrix(y_true, pred, labels=[0, 1])
        rates = safe_rates_from_cm(cm)
        if rates["f1"] > best_f1:
            best_f1 = rates["f1"]
            best_thr = float(thr)
            best_info = rates
    logger.info(f"F1-Max: threshold={best_thr:.6f} | F1={best_f1:.4f} | FPR={best_info.get('fpr',0):.4f} | TPR={best_info.get('tpr',0):.4f}")
    return best_thr, best_info


def pick_threshold_fpr(y_true, proba, target_fpr, prefer_recall=True):
    neg_scores = proba[y_true == 0]
    if neg_scores.size == 0:
        return 0.999, {}
    q = min(max(1.0 - float(target_fpr), 0.0), 1.0)
    thr = float(np.quantile(neg_scores, q, method="higher"))
    pred = (proba >= thr).astype(np.int32)
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    rates = safe_rates_from_cm(cm)
    logger.info(f"FPR-Target: thr={thr:.6f} | FPR={rates['fpr']:.4f} | TPR={rates['tpr']:.4f} | F1={rates['f1']:.4f}")
    return thr, rates


def evaluate(y_true, proba, thr):
    pred = (proba >= thr).astype(np.int32)
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    rates = safe_rates_from_cm(cm)
    uniq = np.unique(y_true)
    roc_auc = float(roc_auc_score(y_true, proba)) if len(uniq) > 1 else float("nan")
    ap = float(average_precision_score(y_true, proba)) if len(uniq) > 1 else float("nan")
    acc = (rates["tn"] + rates["tp"]) / max(1, rates["tn"] + rates["fp"] + rates["fn"] + rates["tp"])
    return {"threshold": float(thr), "roc_auc": roc_auc, "avg_precision": ap, "accuracy": acc,
            "confusion_matrix": cm.tolist(), "rates": rates}


def build_features(texts, word_vec, char_vec, fit=False):
    if fit:
        X_word = word_vec.fit_transform(texts)
        X_char = char_vec.fit_transform(texts)
    else:
        X_word = word_vec.transform(texts)
        X_char = char_vec.transform(texts)
    X_kw = extract_sql_keyword_features(texts)
    return sp.hstack([X_word, X_char, X_kw], format="csr")


def show_feature_importance(model, feature_names, top_k=30):
    logger.info(f"\n=== Top {top_k} Attack Indicators ===")
    importances = model.feature_importances_
    top_idx = np.argsort(importances)[-top_k:][::-1]
    feature_list = []
    for rank, idx in enumerate(top_idx, 1):
        name = feature_names[idx] if idx < len(feature_names) else f"feat_{idx}"
        imp = importances[idx]
        feature_list.append({"rank": rank, "feature": name, "importance": float(imp)})
        logger.info(f"  {rank:2d}. {name[:22]:22s} -> {imp:.6f}")
    return feature_list


def train(cfg: TrainConfig) -> None:
    logger.info("=== SQLi IPS Model Training v2 (Enhanced Recall) ===")
    logger.info(f"XGBoost: {xgboost.__version__} | Strategy: {cfg.threshold_strategy}")
    logger.info(f"Preprocessing: strip_param_names={cfg.strip_param_names}")

    df = load_dataset(cfg)
    y = encode_labels(df, cfg)
    X_text = df[cfg.text_col].values

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_text, y, test_size=cfg.test_size, random_state=cfg.seed, stratify=y)
    val_ratio = cfg.val_size / (1.0 - cfg.test_size)
    X_train_raw, X_val_raw, y_train, y_val = train_test_split(
        X_train_raw, y_train, test_size=val_ratio, random_state=cfg.seed, stratify=y_train)
    logger.info(f"\nDataset: {len(df)} total | Train: {len(y_train)} | Val: {len(y_val)} | Test: {len(y_test)}")

    logger.info("\n=== Preprocessing Payloads ===")
    X_train_text = preprocess_texts(X_train_raw, cfg.strip_param_names)
    X_val_text   = preprocess_texts(X_val_raw,   cfg.strip_param_names)
    X_test_text  = preprocess_texts(X_test_raw,  cfg.strip_param_names)

    logger.info("\n=== Building Dual TF-IDF (Word + Char) + SQL Keywords ===")
    word_vec = TfidfVectorizer(
        analyzer="word", ngram_range=(cfg.word_ngram_min, cfg.word_ngram_max),
        min_df=cfg.min_df, max_features=cfg.word_max_features,
        lowercase=cfg.lowercase, sublinear_tf=True, token_pattern=r"(?u)\b\w+\b")
    char_vec = TfidfVectorizer(
        analyzer="char", ngram_range=(cfg.char_ngram_min, cfg.char_ngram_max),
        min_df=cfg.min_df, max_features=cfg.char_max_features,
        lowercase=cfg.lowercase, sublinear_tf=True)

    X_train = build_features(X_train_text, word_vec, char_vec, fit=True)
    X_val   = build_features(X_val_text,   word_vec, char_vec)
    X_test  = build_features(X_test_text,  word_vec, char_vec)
    logger.info(f"Feature matrix: {X_train.shape} (word + char + {len(SQL_KEYWORDS)} SQL keywords)")

    selector = None
    total_feats = X_train.shape[1]
    if cfg.use_feature_selection and total_feats > cfg.n_selected_features:
        logger.info(f"\n=== Feature Selection (top {cfg.n_selected_features:,} dari {total_feats:,}) ===")
        selector = SelectKBest(chi2, k=cfg.n_selected_features)
        X_train = selector.fit_transform(X_train, y_train)
        X_val   = selector.transform(X_val)
        X_test  = selector.transform(X_test)
        logger.info(f"Selected features: {X_train.shape[1]:,}")

    pos = max(1, int(y_train.sum()))
    neg = max(1, int((y_train == 0).sum()))
    scale_pos_weight = float(neg / pos)
    logger.info(f"\nClass balance: benign={neg} | attack={pos} | scale_pos_weight={scale_pos_weight:.4f}")

    model_params = {
        "n_estimators": cfg.n_estimators, "learning_rate": cfg.learning_rate,
        "max_depth": cfg.max_depth, "min_child_weight": cfg.min_child_weight,
        "subsample": cfg.subsample, "colsample_bytree": cfg.colsample_bytree,
        "reg_lambda": cfg.reg_lambda, "reg_alpha": cfg.reg_alpha, "gamma": cfg.gamma,
        "n_jobs": cfg.n_jobs, "objective": "binary:logistic", "eval_metric": "logloss",
        "tree_method": cfg.tree_method, "scale_pos_weight": scale_pos_weight,
        "random_state": cfg.seed,
    }

    logger.info("\n=== Training XGBoost ===")
    logger.info(f"n_estimators={cfg.n_estimators}, max_depth={cfg.max_depth}, lr={cfg.learning_rate}")

    if XGBOOST_MAJOR >= 3:
        model_params["early_stopping_rounds"] = cfg.early_stopping_rounds
        model = XGBClassifier(**model_params)
        model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=100)
    else:
        model = XGBClassifier(**model_params)
        model.fit(X_train, y_train, early_stopping_rounds=cfg.early_stopping_rounds,
                  eval_set=[(X_val, y_val)], verbose=100)

    logger.info(f"Training complete. Best iteration: {getattr(model, 'best_iteration', 'N/A')}")

    proba_val  = model.predict_proba(X_val)[:, 1]
    proba_test = model.predict_proba(X_test)[:, 1]

    logger.info("\n=== Threshold Tuning ===")
    if cfg.threshold_strategy == "f1_max":
        thr, thr_info = pick_threshold_f1_max(y_val, proba_val)
    else:
        thr, thr_info = pick_threshold_fpr(y_val, proba_val, cfg.target_fpr, cfg.prefer_recall)

    val_metrics  = evaluate(y_val,  proba_val,  thr)
    test_metrics = evaluate(y_test, proba_test, thr)

    logger.info("\n=== Validation Metrics ===")
    logger.info(f"  AUC={val_metrics['roc_auc']:.4f} | Acc={val_metrics['accuracy']:.4f} | P={val_metrics['rates']['precision']:.4f} | R={val_metrics['rates']['tpr']:.4f} | F1={val_metrics['rates']['f1']:.4f}")
    logger.info(f"  CM: TN={val_metrics['rates']['tn']} FP={val_metrics['rates']['fp']} FN={val_metrics['rates']['fn']} TP={val_metrics['rates']['tp']}")

    logger.info("\n=== Test Metrics ===")
    logger.info(f"  AUC={test_metrics['roc_auc']:.4f} | Acc={test_metrics['accuracy']:.4f} | P={test_metrics['rates']['precision']:.4f} | R={test_metrics['rates']['tpr']:.4f} | F1={test_metrics['rates']['f1']:.4f}")
    logger.info(f"  CM: TN={test_metrics['rates']['tn']} FP={test_metrics['rates']['fp']} FN={test_metrics['rates']['fn']} TP={test_metrics['rates']['tp']}")

    word_names = list(word_vec.get_feature_names_out())
    char_names = list(char_vec.get_feature_names_out())
    kw_names   = [f"kw_{kw}" for kw in SQL_KEYWORDS]
    all_names  = word_names + char_names + kw_names
    if selector is not None:
        sel_idx = selector.get_support(indices=True)
        sel_names = [all_names[i] if i < len(all_names) else f"feat_{i}" for i in sel_idx]
    else:
        sel_names = all_names
    top_features = show_feature_importance(model, sel_names, cfg.show_top_features)

    logger.info("\n=== Saving Artifacts ===")
    joblib.dump({"word": word_vec, "char": char_vec, "version": 2}, cfg.out_vectorizer)
    logger.info(f"✓ {cfg.out_vectorizer} (dual vectorizer v2)")
    if selector is not None:
        joblib.dump(selector, cfg.out_selector)
        logger.info(f"✓ {cfg.out_selector}")
    joblib.dump(model, cfg.out_model)
    logger.info(f"✓ {cfg.out_model}")

    meta = {
        "version": 2, "pos_label": POS_LABEL, "neg_label": NEG_LABEL,
        "threshold": float(thr), "threshold_strategy": cfg.threshold_strategy,
        "scale_pos_weight": float(scale_pos_weight),
        "best_iteration": getattr(model, "best_iteration", None),
        "xgboost_version": xgboost.__version__,
        "preprocessing": {"strip_param_names": cfg.strip_param_names, "max_decode_passes": cfg.max_decode_passes},
        "vectorizer": {"type": "dual_v2",
                       "word": {"ngram_range": [cfg.word_ngram_min, cfg.word_ngram_max], "max_features": cfg.word_max_features},
                       "char": {"ngram_range": [cfg.char_ngram_min, cfg.char_ngram_max], "max_features": cfg.char_max_features},
                       "sql_keywords_count": len(SQL_KEYWORDS)},
        "top_features": top_features,
        "metrics": {"val": val_metrics, "test": test_metrics},
        "config": asdict(cfg),
    }
    Path(cfg.out_meta).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    logger.info(f"✓ {cfg.out_meta}")

    logger.info("\n=== Training Complete ===")
    logger.info(
        f"Final Test: Accuracy={test_metrics['accuracy']:.4f} | "
        f"Precision={test_metrics['rates']['precision']:.4f} | "
        f"Recall={test_metrics['rates']['tpr']:.4f} | "
        f"F1={test_metrics['rates']['f1']:.4f} | "
        f"AUC={test_metrics['roc_auc']:.4f}"
    )


def parse_args() -> TrainConfig:
    p = argparse.ArgumentParser(description="Train SQLi IPS Model v2")
    p.add_argument("--data", default="dataset-balanced.csv")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--test-size",  type=float, default=0.15)
    p.add_argument("--val-size",   type=float, default=0.15)
    p.add_argument("--keep-param-names", dest="strip_param_names", action="store_false", default=True)
    p.add_argument("--max-decode-passes", type=int, default=3)
    p.add_argument("--word-max-features", type=int, default=20000)
    p.add_argument("--char-max-features", type=int, default=20000)
    p.add_argument("--min-df",            type=int, default=1)
    p.add_argument("--n-selected-features", type=int, default=20000)
    p.add_argument("--n-estimators",      type=int,   default=1000)
    p.add_argument("--learning-rate",     type=float, default=0.05)
    p.add_argument("--max-depth",         type=int,   default=7)
    p.add_argument("--early-stopping-rounds", type=int, default=50)
    p.add_argument("--threshold-strategy", default="f1_max", choices=["f1_max", "target_fpr"])
    p.add_argument("--target-fpr",        type=float, default=0.01)
    p.add_argument("--run-evasion-tests", action="store_true", default=True)
    p.add_argument("--show-top-features", type=int, default=30)
    p.add_argument("--out-vectorizer", default="tfidf_vectorizer.pkl")
    p.add_argument("--out-selector",   default="feature_selector.pkl")
    p.add_argument("--out-model",      default="xgb_sqli_model.pkl")
    p.add_argument("--out-meta",       default="model_meta.json")
    args = p.parse_args()
    return TrainConfig(
        dataset_path=args.data, seed=args.seed,
        test_size=args.test_size, val_size=args.val_size,
        strip_param_names=args.strip_param_names,
        max_decode_passes=args.max_decode_passes,
        word_max_features=args.word_max_features,
        char_max_features=args.char_max_features,
        min_df=args.min_df,
        n_selected_features=args.n_selected_features,
        n_estimators=args.n_estimators,
        learning_rate=args.learning_rate,
        max_depth=args.max_depth,
        early_stopping_rounds=args.early_stopping_rounds,
        threshold_strategy=args.threshold_strategy,
        target_fpr=args.target_fpr,
        run_evasion_tests=args.run_evasion_tests,
        show_top_features=args.show_top_features,
        out_vectorizer=args.out_vectorizer,
        out_selector=args.out_selector,
        out_model=args.out_model,
        out_meta=args.out_meta,
    )


if __name__ == "__main__":
    cfg = parse_args()
    train(cfg)

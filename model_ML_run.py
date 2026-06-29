#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Active IPS (Layer-2) using TF-IDF + XGBoost model on NFQUEUE (default: queue 3).

Pipeline assumption:
  iptables -> NFQUEUE 2 (Suricata IPS layer 1) -> Suricata nfq: route-queue 3 -> this script
Only inspects HTTP REQUEST payloads, not HTTP responses.

Artifacts expected (default names match your outputs):
  - model_meta.json
  - tfidf_vectorizer.pkl
  - xgb_sqli_model.pkl
  - feature_selector.pkl (optional but you have it)

Decision:
  prob_attack >= threshold  => DROP
  else                     => ACCEPT
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import joblib
from netfilterqueue import NetfilterQueue

# scapy for parsing and extract TCP payloads
from scapy.all import IP, TCP

# logging
LOG = logging.getLogger("model_ML_run")

def setup_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

# preprocessing func
from urllib.parse import parse_qs, unquote_plus, urlparse

_RE_HTTP_LINE   = re.compile(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", re.IGNORECASE)
_RE_PATH_PREFIX = re.compile(r"^(?:/[^?#]*)?\?", re.IGNORECASE)
_RE_VALID_KEY   = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\.]*$")

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")
HTTP_RESP_PREFIX = b"HTTP/"

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
    text = _UA_SUFFIX.sub("", text).strip()
    if "Submit" in text or "submit" in text:
        text = re.sub(r'(?:&|(?<=\?))[Ss]ubmit=[^&\s#]*', '', text)
        text = re.sub(r'&{2,}', '&', text)
        text = re.sub(r'[?&]$', '', text).strip()
    return text

def extract_payload_values(raw: str, strip_param_names: bool = True, max_decode_passes: int = 3) -> str:
    if not raw or not isinstance(raw, str):
        return ""

    text = raw.strip()
    text = _RE_HTTP_LINE.sub("", text).strip()

    if " HTTP/" in text:
        text = text.split(" HTTP/")[0]
        
    text = strip_bias_artifacts(text)

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
                                f"{normalize_encoded(k, max_passes=max_decode_passes)} "
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

import scipy.sparse as sp

def extract_sql_keyword_features(texts: list) -> sp.csr_matrix:
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

# ──────────────────────────────────────────────────────────────────────────────
# Model artifacts loader
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Artifacts:
    threshold: float
    strip_param_names: bool
    max_decode_passes: int
    word_vec: object
    char_vec: object
    selector: Optional[object]
    model: object

def load_artifacts(meta_path: str, vectorizer_path: str, model_path: str, selector_path: Optional[str]) -> Artifacts:
    meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))

    vec_data = joblib.load(vectorizer_path)
    if isinstance(vec_data, dict) and "word" in vec_data:
        word_vec = vec_data["word"]
        char_vec = vec_data["char"]
    else:
        word_vec = vec_data
        char_vec = None
        
    model = joblib.load(model_path)

    selector = None
    if selector_path:
        sp_path = Path(selector_path)
        if sp_path.exists():
            selector = joblib.load(str(sp_path))

    thr = float(meta["threshold"])
    preprocessing = meta.get("preprocessing", {})
    strip_param_names = bool(preprocessing.get("strip_param_names", True))
    max_decode_passes = int(preprocessing.get("max_decode_passes", 3))

    return Artifacts(
        threshold=thr,
        strip_param_names=strip_param_names,
        max_decode_passes=max_decode_passes,
        word_vec=word_vec,
        char_vec=char_vec,
        selector=selector,
        model=model,
    )

# ──────────────────────────────────────────────────────────────────────────────
# HTTP request parsing and feature string builder
# ──────────────────────────────────────────────────────────────────────────────

_RE_HEADER_UA = re.compile(r"(?im)^User-Agent:\s*(.+)$")
_RE_HEADER_HOST = re.compile(r"(?im)^Host:\s*(.+)$")

def is_http_request_payload(tcp_payload: bytes) -> bool:
    if not tcp_payload:
        return False
    if tcp_payload.startswith(HTTP_RESP_PREFIX):
        return False
    return tcp_payload.startswith(HTTP_METHODS)

def parse_http_request(tcp_payload: bytes) -> Optional[Tuple[str, str, str, str]]:
    """
    Returns (method, path_with_query, host, user_agent)
    host and user_agent can be empty string if not found.
    """
    try:
        # Split headers from body
        header_blob = tcp_payload.split(b"\r\n\r\n", 1)[0]
        header_text = header_blob.decode("iso-8859-1", errors="ignore")
        lines = header_text.split("\r\n")
        if not lines:
            return None

        # Request line: METHOD SP PATH SP HTTP/x
        req = lines[0].strip()
        parts = req.split()
        if len(parts) < 2:
            return None
        method = parts[0].upper()
        path = parts[1]

        host = ""
        ua = ""

        m_host = _RE_HEADER_HOST.search(header_text)
        if m_host:
            host = m_host.group(1).strip()

        m_ua = _RE_HEADER_UA.search(header_text)
        if m_ua:
            ua = m_ua.group(1).strip()

        return method, path, host, ua
    except Exception:
        return None

def build_model_input(method: str, path: str, host: str, ua: str) -> str:
    """
    Build string close to your dataset style:
      "GET http://<HOST>/<PATH>?... ua=Mozilla/5.0"
    If host is missing, we keep it empty but still stable.
    """
    # path may be absolute-form url in proxies, handle if it has scheme already
    if "://" in path:
        url = path
    else:
        # Ensure path begins with /
        if not path.startswith("/"):
            path = "/" + path
        if host:
            url = f"http://{host}{path}"
        else:
            url = f"http://{path}"

    if ua:
        return f"{method} {url} ua={ua}"
    return f"{method} {url}"

# ──────────────────────────────────────────────────────────────────────────────
# IPS engine
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Stats:
    total: int = 0
    inspected: int = 0
    accepted: int = 0
    dropped: int = 0
    errors: int = 0
    last_report_ts: float = 0.0

class MLIPS:
    def __init__(
        self,
        art: Artifacts,
        inspect_ports: Tuple[int, ...],
        dry_run: bool,
        report_every: int,
        log_payloads: bool,
        max_log_len: int,
    ):
        self.art = art
        self.inspect_ports = inspect_ports
        self.dry_run = dry_run
        self.report_every = report_every
        self.log_payloads = log_payloads
        self.max_log_len = max_log_len
        self.stats = Stats()

    def should_inspect(self, ip_pkt: IP, tcp_pkt: TCP, tcp_payload: bytes) -> bool:
        # Only TCP with payload
        if not tcp_payload:
            return False

        # Only inspect requests toward server ports (request direction is usually dport = 80/8080)
        if self.inspect_ports and int(tcp_pkt.dport) not in self.inspect_ports:
            return False

        # Only HTTP request signature
        return is_http_request_payload(tcp_payload)

    def classify(self, model_input: str) -> Tuple[float, bool, str]:
        # Apply SAME preprocessing extractor as training (payload-aware extraction)
        clean = extract_payload_values(
            model_input,
            strip_param_names=self.art.strip_param_names,
            max_decode_passes=self.art.max_decode_passes,
        )
        if self.art.char_vec is not None:
            X = build_features([clean], self.art.word_vec, self.art.char_vec)
        else:
            X = self.art.word_vec.transform([clean])
            
        if self.art.selector is not None:
            X = self.art.selector.transform(X)
        proba = float(self.art.model.predict_proba(X)[0, 1])
        blocked = proba >= float(self.art.threshold)
        return proba, blocked, clean

    def _maybe_report(self) -> None:
        if self.report_every <= 0:
            return
        if self.stats.total % self.report_every != 0:
            return
        LOG.info(
            "STATS total=%d inspected=%d accept=%d drop=%d errors=%d",
            self.stats.total, self.stats.inspected, self.stats.accepted, self.stats.dropped, self.stats.errors
        )

    def on_packet(self, nfpacket) -> None:
        self.stats.total += 1
        try:
            payload = nfpacket.get_payload()
            ip_pkt = IP(payload)

            # Only IPv4 TCP packets
            if not ip_pkt.haslayer(TCP):
                nfpacket.accept()
                self.stats.accepted += 1
                self._maybe_report()
                return

            tcp_pkt = ip_pkt[TCP]
            tcp_payload = bytes(tcp_pkt.payload) if tcp_pkt.payload else b""

            # Skip responses and non-request packets
            if not self.should_inspect(ip_pkt, tcp_pkt, tcp_payload):
                nfpacket.accept()
                self.stats.accepted += 1
                self._maybe_report()
                return

            parsed = parse_http_request(tcp_payload)
            if not parsed:
                nfpacket.accept()
                self.stats.accepted += 1
                self._maybe_report()
                return

            method, path, host, ua = parsed
            model_input = build_model_input(method, path, host, ua)

            self.stats.inspected += 1
            proba, blocked, clean = self.classify(model_input)

            src = f"{ip_pkt.src}:{tcp_pkt.sport}"
            dst = f"{ip_pkt.dst}:{tcp_pkt.dport}"

            if blocked:
                self.stats.dropped += 1
                if self.log_payloads:
                    LOG.warning(
                        "DROP proba=%.6f src=%s dst=%s method=%s path=%s ua=%s clean=%s",
                        proba, src, dst, method, path[:120], ua[:120], clean[: self.max_log_len]
                    )
                else:
                    LOG.warning("DROP proba=%.6f src=%s dst=%s method=%s path=%s", proba, src, dst, method, path[:200])

                if self.dry_run:
                    nfpacket.accept()
                    self.stats.accepted += 1
                else:
                    nfpacket.drop()
            else:
                self.stats.accepted += 1
                if self.log_payloads:
                    LOG.info(
                        "ACCEPT proba=%.6f src=%s dst=%s method=%s path=%s ua=%s clean=%s",
                        proba, src, dst, method, path[:120], ua[:120], clean[: self.max_log_len]
                    )
                nfpacket.accept()

            self._maybe_report()

        except Exception as e:
            self.stats.errors += 1
            # fail-open behavior: accept on error
            LOG.error("ERROR processing packet: %s", e, exc_info=True)
            try:
                nfpacket.accept()
                self.stats.accepted += 1
            except Exception:
                pass
            self._maybe_report()

# ──────────────────────────────────────────────────────────────────────────────
# CLI and main
# ──────────────────────────────────────────────────────────────────────────────

def parse_args():
    ap = argparse.ArgumentParser(description="Run ML IPS on NFQUEUE (queue 3 by default).")
    ap.add_argument("--queue", type=int, default=3, help="NFQUEUE number to bind (default: 3).")

    ap.add_argument("--meta", default="model_meta.json")
    ap.add_argument("--vectorizer", default="tfidf_vectorizer.pkl")
    ap.add_argument("--model", default="xgb_sqli_model.pkl")
    ap.add_argument("--selector", default="feature_selector.pkl")
    ap.add_argument("--no-selector", action="store_true", help="Ignore selector even if file exists.")

    ap.add_argument("--ports", default="80,8080,8000", help="Comma-separated destination ports to inspect (HTTP).")
    ap.add_argument("--dry-run", action="store_true", help="Do not DROP, only log what would be dropped.")
    ap.add_argument("--log-level", default="INFO", help="DEBUG/INFO/WARNING/ERROR")
    ap.add_argument("--log-payloads", action="store_true", help="Log cleaned payload (may contain sensitive data).")
    ap.add_argument("--max-log-len", type=int, default=180, help="Max chars for clean payload log.")
    ap.add_argument("--report-every", type=int, default=2000, help="Print stats every N packets (0 to disable).")

    return ap.parse_args()

def require_root():
    if os.geteuid() != 0:
        print("ERROR: must run as root (required for NFQUEUE).", file=sys.stderr)
        sys.exit(1)

def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)

    require_root()

    # Validate artifacts exist
    for f in (args.meta, args.vectorizer, args.model):
        if not Path(f).exists():
            LOG.error("Missing required file: %s", Path(f).resolve())
            return 2

    selector_path = None if args.no_selector else args.selector
    if selector_path and (not Path(selector_path).exists()):
        LOG.warning("Selector not found, continuing without selector: %s", selector_path)
        selector_path = None

    art = load_artifacts(args.meta, args.vectorizer, args.model, selector_path)
    LOG.info("Loaded artifacts. threshold=%.8f strip_param_names=%s max_decode_passes=%d selector=%s",
             art.threshold, art.strip_param_names, art.max_decode_passes, "yes" if art.selector else "no")

    # Parse ports
    ports: Tuple[int, ...] = tuple(
        int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()
    )
    if not ports:
        LOG.warning("No ports parsed from --ports. Script will inspect nothing.")
    else:
        LOG.info("Inspecting destination ports: %s", ports)

    ips = MLIPS(
        art=art,
        inspect_ports=ports,
        dry_run=args.dry_run,
        report_every=args.report_every,
        log_payloads=args.log_payloads,
        max_log_len=args.max_log_len,
    )

    nfq = NetfilterQueue()

    stop_flag = {"stop": False}

    def _handle_signal(signum, frame):
        stop_flag["stop"] = True
        LOG.info("Signal %s received, stopping...", signum)
        try:
            nfq.unbind()
        except Exception:
            pass

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    LOG.info("Binding to NFQUEUE %d ... (dry_run=%s)", args.queue, args.dry_run)
    nfq.bind(args.queue, ips.on_packet)

    try:
        nfq.run()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            nfq.unbind()
        except Exception:
            pass

    LOG.info(
        "FINAL STATS total=%d inspected=%d accept=%d drop=%d errors=%d",
        ips.stats.total, ips.stats.inspected, ips.stats.accepted, ips.stats.dropped, ips.stats.errors
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

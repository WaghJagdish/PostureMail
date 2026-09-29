"""End-to-end PCAP session extractor using production PS159 parser components.

Takes a PCAP file and extracts sessions -> RawSessionFeatures -> 94-D feature vectors
identically to the production Celery pipeline.
"""

from __future__ import annotations

import io
from pathlib import Path
import struct
from typing import Any

import numpy as np

from pecff.crypto.cipher_db import cipher_db
from pecff.crypto.risk_engine import NISTDeterministicRiskScorer, SessionCryptoParameters
from pecff.crypto.x509_parser import X509Parser
from pecff.ingest.reader import PcapReader
from pecff.ingest.reassembly import StreamReassembler
from pecff.ml.features import (
    RawSessionFeatures,
    SessionFeatureExtractor,
    SessionFeatureVectorizer,
)
from pecff.ml.fingerprints import calculate_ja3, calculate_ja4
from pecff.parse.classify import ProtocolClassifier
from pecff.parse.starttls_fsm import Direction, StarttlsFSM
from pecff.parse.tls_decoder import (
    TLSHandshakeDecoder,
    TLSHandshakeSummary,
)
from pecff.tasks.pipeline import resolve_protocol_version


def extract_features_from_pcap(
    pcap_path: Path, extractor: SessionFeatureExtractor
) -> list[tuple[dict[str, Any], RawSessionFeatures]]:
  """Parses a PCAP file using production PS159 components and extracts raw session features."""
  reader = PcapReader(pcap_path)
  reassembler = StreamReassembler()
  classifier = ProtocolClassifier()
  risk_scorer = NISTDeterministicRiskScorer()

  # Feed packets to reassembler
  for pkt in reader:
    reassembler.process_packet(pkt)

  streams = reassembler.flush_all()
  results: list[tuple[dict[str, Any], RawSessionFeatures]] = []

  for stream in streams:
    c2s_bytes = stream.c2s_payload
    s2c_bytes = stream.s2c_payload

    classification = classifier.classify_stream(
        server_port=stream.server_port,
        s2c_initial_bytes=s2c_bytes[:64],
        c2s_initial_bytes=c2s_bytes[:64],
    )

    fsm = StarttlsFSM(
        protocol=classification.protocol, mode=classification.mode
    )
    if classification.protocol in (
        "SMTP",
        "IMAP",
        "POP3",
    ) and classification.mode == "EXPLICIT":
      if s2c_bytes:
        fsm.feed(Direction.S2C, s2c_bytes, 0, stream.first_seen)
      if c2s_bytes:
        fsm.feed(Direction.C2S, c2s_bytes, 0, stream.first_seen)

    tls_decoder = TLSHandshakeDecoder()
    if c2s_bytes:
      tls_decoder.process_c2s_record_bytes(c2s_bytes)
    if s2c_bytes:
      tls_decoder.process_s2c_record_bytes(s2c_bytes)
    tls_summary = tls_decoder.summary

    ver_str = resolve_protocol_version(tls_summary, fsm)
    cipher_id = None
    cipher_info = None
    if tls_summary.server_hello and tls_summary.server_hello.selected_cipher:
      cipher_id = f"0x{tls_summary.server_hello.selected_cipher:04X}"
      cipher_info = cipher_db.get(cipher_id)

    kex_alg = "ECDHE"
    if cipher_info and cipher_info.kex and cipher_info.kex != "UNKNOWN":
      kex_alg = cipher_info.kex

    leaf_cert = None
    if tls_summary.certificates_der:
      try:
        leaf_cert = X509Parser.parse_der(tls_summary.certificates_der[0])
      except Exception:
        leaf_cert = None

    crypto_params = SessionCryptoParameters(
        protocol_version=ver_str,
        dst_port=stream.server_port,
        has_auth=False,
        cleartext_credentials_observed=False,
        handshake_completed=tls_summary.handshake_completed,
        cert_analysis_possible=tls_summary.cert_analysis_possible,
        cipher_id=cipher_id,
        cipher_info=cipher_info,
        encrypt_then_mac=False,
        extended_master_secret=False,
        secure_renegotiation=False,
        kex_algorithm=kex_alg,
        named_group=None,
        leaf_certificate=leaf_cert,
    )
    risk_res = risk_scorer.score_session(crypto_params)

    dur = float(max(0.0, stream.last_seen - stream.first_seen))
    meta = {
        "client_ip": stream.client_ip,
        "client_port": stream.client_port,
        "server_ip": stream.server_ip,
        "server_port": stream.server_port,
        "first_seen": stream.first_seen,
        "duration_sec": dur,
        "protocol_version": ver_str,
        "risk_score": float(risk_res.score),
        "c2s_bytes": stream.c2s_bytes,
        "s2c_bytes": stream.s2c_bytes,
        "sni": (
            tls_summary.client_hello.server_name
            if tls_summary.client_hello
            else None
        ),
    }

    raw_feat = extractor.extract_features(
        handshake_summary=tls_summary,
        leaf_cert=leaf_cert,
        risk_score=float(risk_res.score),
        starttls_state=fsm.state.value
        if hasattr(fsm.state, "value")
        else str(fsm.state),
        dst_port=stream.server_port,
        c2s_bytes=stream.c2s_bytes,
        s2c_bytes=stream.s2c_bytes,
        duration_sec=dur,
        is_periodic=False,
        src_ip_session_count=1,
        distinct_sni_count=1,
    )


    results.append((meta, raw_feat))

  return results

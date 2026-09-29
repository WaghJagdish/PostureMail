"""Unit tests for cipher suite database and cryptographic classification."""

from __future__ import annotations

from pecff.crypto.cipher_db import cipher_db


class TestCipherDatabase:
    """Validate IANA cipher lookup, NIST classification, and unknown fallbacks."""

    def test_tls13_ciphers_approved(self) -> None:
        c1301 = cipher_db.get(0x1301)
        assert c1301.name == "TLS_AES_128_GCM_SHA256"
        assert c1301.is_approved is True
        assert c1301.aead is True
        assert c1301.pfs is True
        assert c1301.enc_bits == 128

        c1302 = cipher_db.get("0x1302")
        assert c1302.name == "TLS_AES_256_GCM_SHA384"
        assert c1302.enc_bits == 256
        assert c1302.is_approved is True

    def test_legacy_cbc_ciphers(self) -> None:
        c002f = cipher_db.get(0x002F)
        assert c002f.name == "TLS_RSA_WITH_AES_128_CBC_SHA"
        assert c002f.is_legacy is True
        assert c002f.pfs is False
        assert c002f.aead is False

    def test_prohibited_and_broken_ciphers(self) -> None:
        # 3DES
        c000a = cipher_db.get(0x000A)
        assert c000a.name == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        assert c000a.is_prohibited is True

        # RC4
        c0005 = cipher_db.get(0x0005)
        assert c0005.name == "TLS_RSA_WITH_RC4_128_SHA"
        assert c0005.is_prohibited is True

        # EXPORT 40-bit
        c0003 = cipher_db.get(0x0003)
        assert c0003.export is True
        assert c0003.is_prohibited is True

        # NULL encryption
        c0001 = cipher_db.get(0x0001)
        assert c0001.null_enc is True
        assert c0001.enc_bits == 0
        assert c0001.is_prohibited is True

        # Anonymous DH
        c0018 = cipher_db.get(0x0018)
        assert c0018.anon is True
        assert c0018.is_prohibited is True

    def test_unknown_cipher_id_fallback(self) -> None:
        """Unknown cipher IDs must resolve to a safe unknown record without crashing."""
        unknown = cipher_db.get(0xDEAD)
        assert unknown.id == "0xdead"
        assert unknown.name == "TLS_UNKNOWN_CIPHER_0xdead"
        assert unknown.nist_status == "unknown"
        assert unknown.is_approved is False
        assert unknown.enc_bits == 0

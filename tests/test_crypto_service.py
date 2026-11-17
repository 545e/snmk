"""
SNMK Enterprise Cybersecurity Platform — Cryptography Workbench Microservice Tests (Phase 8)
Verifies encoding, hashing, authenticated symmetric encryption (AES-GCM, ChaCha20-Poly1305),
asymmetric encryption & signing (RSA-OAEP, RSA-PSS), key derivation (PBKDF2),
recipe pipeline execution, and anti-tamper rejection.
"""

from __future__ import annotations

import base64
import os
import secrets
import unittest

from fastapi.testclient import TestClient
from services.crypto_service.engine import crypto_engine
from services.crypto_service.main import app


class TestCryptoWorkbench(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    # 1. Encodings
    def test_01_base64_and_hex_encodings(self):
        msg = "SNMK-Cyber-Workbench-2026"
        b64 = crypto_engine.encode(msg, scheme="base64")
        self.assertEqual(crypto_engine.decode(b64["output"], scheme="base64")["output"], msg)

        hx = crypto_engine.encode(msg, scheme="hex")
        self.assertEqual(crypto_engine.decode(hx["output"], scheme="hex")["output"], msg)

        rot13 = crypto_engine.encode(msg, scheme="rot13")
        self.assertEqual(crypto_engine.decode(rot13["output"], scheme="rot13")["output"], msg)

    # 2. Cryptographic Hashes
    def test_02_cryptographic_hashes(self):
        data = b"confidential payload"
        h256 = crypto_engine.compute_hash(data, algorithm="sha256")
        self.assertEqual(len(h256["hex_digest"]), 64)

        h512 = crypto_engine.compute_hash(data, algorithm="sha512")
        self.assertEqual(len(h512["hex_digest"]), 128)

        h_sha3 = crypto_engine.compute_hash(data, algorithm="sha3_256")
        self.assertEqual(len(h_sha3["hex_digest"]), 64)

        h_blake = crypto_engine.compute_hash(data, algorithm="blake2b")
        self.assertEqual(len(h_blake["hex_digest"]), 128)

    # 3. Authenticated Symmetric Encryption (AES-GCM)
    def test_03_aes_gcm_roundtrip_and_tamper_rejection(self):
        plaintext = "Enterprise Top Secret Defense Intel"
        key = secrets.token_bytes(32)

        enc = crypto_engine.encrypt_aes_gcm(plaintext.encode("utf-8"), key=key)
        self.assertIn("ciphertext", enc)
        self.assertIn("nonce", enc)

        # Successful decryption
        dec_bytes = crypto_engine.decrypt_aes_gcm(
            enc["ciphertext"],
            key=key,
            nonce_b64=enc["nonce"]
        )
        self.assertEqual(dec_bytes.decode("utf-8"), plaintext)

        # Tampered ciphertext must fail authentication
        tampered_bytes = bytearray(base64.b64decode(enc["ciphertext"]))
        tampered_bytes[0] ^= 0xFF
        tampered_b64 = base64.b64encode(tampered_bytes).decode("ascii")

        with self.assertRaises(ValueError):
            crypto_engine.decrypt_aes_gcm(
                tampered_b64,
                key=key,
                nonce_b64=enc["nonce"]
            )

    # 4. ChaCha20-Poly1305
    def test_04_chacha20_roundtrip(self):
        plaintext = "High Speed Mobile Channel Stream"
        key = secrets.token_bytes(32)

        enc = crypto_engine.encrypt_chacha20(plaintext.encode("utf-8"), key=key)
        dec_bytes = crypto_engine.decrypt_chacha20(enc["ciphertext"], key=key, nonce_b64=enc["nonce"])
        self.assertEqual(dec_bytes.decode("utf-8"), plaintext)

    # 5. RSA OAEP & RSA-PSS Signatures
    def test_05_rsa_encryption_and_signatures(self):
        pair = crypto_engine.generate_rsa_keypair(key_size=2048)
        self.assertIn("-----BEGIN PRIVATE KEY-----", pair["private_key"])
        self.assertIn("-----BEGIN PUBLIC KEY-----", pair["public_key"])

        # OAEP
        msg = "Secret session token"
        enc = crypto_engine.rsa_encrypt(msg.encode("utf-8"), public_key_pem=pair["public_key"])
        dec_bytes = crypto_engine.rsa_decrypt(enc, private_key_pem=pair["private_key"])
        self.assertEqual(dec_bytes.decode("utf-8"), msg)

        # PSS Sign / Verify
        sig = crypto_engine.rsa_sign(msg.encode("utf-8"), private_key_pem=pair["private_key"])
        valid = crypto_engine.rsa_verify(msg.encode("utf-8"), signature_b64=sig, public_key_pem=pair["public_key"])
        self.assertTrue(valid)

        invalid = crypto_engine.rsa_verify(b"altered message", signature_b64=sig, public_key_pem=pair["public_key"])
        self.assertFalse(invalid)

    # 6. Key Derivation & HMAC
    def test_06_pbkdf2_and_hmac(self):
        salt = os.urandom(16)
        key_bytes = crypto_engine.derive_key_pbkdf2("super_secret_passphrase", salt=salt, iterations=50000)
        self.assertEqual(len(key_bytes), 32)

        mac = crypto_engine.compute_hmac(key=key_bytes, message=b"authenticated body", algorithm="sha256")
        self.assertEqual(len(mac), 64)

    # 7. CyberChef-Style Recipe Pipeline
    def test_07_recipe_pipeline(self):
        recipe = [
            {"op": "to_base64"},
            {"op": "reverse"},
            {"op": "to_hex"}
        ]
        result = crypto_engine.run_recipe("Attack Vector 101", operations=recipe)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["steps"]), 3)

    # 8. API Endpoints
    def test_08_api_endpoints(self):
        res_h = self.client.get("/health")
        self.assertEqual(res_h.status_code, 200)
        self.assertEqual(res_h.json()["status"], "HEALTHY")

        res_enc = self.client.post("/api/v1/crypto/encode", json={"text": "test", "scheme": "base64"})
        self.assertEqual(res_enc.status_code, 200)
        self.assertEqual(res_enc.json()["output"], "dGVzdA==")

        res_hash = self.client.post("/api/v1/crypto/hash", json={"data": "test", "algorithm": "sha256"})
        self.assertEqual(res_hash.status_code, 200)
        self.assertEqual(len(res_hash.json()["hex_digest"]), 64)


if __name__ == "__main__":
    unittest.main()

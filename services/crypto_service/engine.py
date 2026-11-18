"""
SNMK — Cryptography Workbench Processing Engine (Phase 8)
Implements:
1. Encoding & Decoding (Base64, Base32, Hex, URL, HTML, Binary, ROT13, Caesar)
2. Cryptographic Hashing (SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2b, legacy MD5/SHA-1 identification)
3. Authenticated Encryption (AES-GCM, ChaCha20-Poly1305, RSA-OAEP, RSA Signatures)
4. Key Derivation (PBKDF2, HKDF, HMAC)
5. Recipe Pipeline Processor (CyberChef-style multi-step transformations)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import os
import secrets
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


class CryptoWorkbenchEngine:
    """Core cryptographic engine executing high-assurance operations."""

    # =========================================================================
    # 1. Encoding and Decoding
    # =========================================================================

    def encode(self, text: str, scheme: str) -> Dict[str, Any]:
        scheme = scheme.lower().replace("-", "").replace("_", "")
        raw_bytes = text.encode("utf-8")

        if scheme == "base64":
            res = base64.b64encode(raw_bytes).decode("ascii")
        elif scheme == "base32":
            res = base64.b32encode(raw_bytes).decode("ascii")
        elif scheme in ("hex", "hexadecimal"):
            res = raw_bytes.hex()
        elif scheme == "url":
            res = urllib.parse.quote(text, safe="")
        elif scheme == "html":
            res = html.escape(text)
        elif scheme in ("bin", "binary"):
            res = " ".join(f"{b:08b}" for b in raw_bytes)
        elif scheme == "rot13":
            res = self._rot13(text)
        elif scheme == "caesar":
            res = self._caesar(text, shift=3)
        elif scheme == "morse":
            res = self._to_morse(text)
        else:
            raise ValueError(f"Unsupported encoding scheme: {scheme}")

        return {"scheme": scheme, "input_length": len(text), "output": res}

    def decode(self, text: str, scheme: str) -> Dict[str, Any]:
        scheme = scheme.lower().replace("-", "").replace("_", "")

        try:
            if scheme == "base64":
                raw = base64.b64decode(text.strip())
                res = raw.decode("utf-8", errors="replace")
            elif scheme == "base32":
                raw = base64.b32decode(text.strip())
                res = raw.decode("utf-8", errors="replace")
            elif scheme in ("hex", "hexadecimal"):
                clean_hex = text.strip().replace(" ", "").replace("0x", "")
                raw = bytes.fromhex(clean_hex)
                res = raw.decode("utf-8", errors="replace")
            elif scheme == "url":
                res = urllib.parse.unquote(text)
            elif scheme == "html":
                res = html.unescape(text)
            elif scheme in ("bin", "binary"):
                bits = text.strip().split()
                raw = bytes(int(b, 2) for b in bits)
                res = raw.decode("utf-8", errors="replace")
            elif scheme == "rot13":
                res = self._rot13(text)
            elif scheme == "caesar":
                res = self._caesar(text, shift=-3)
            elif scheme == "morse":
                res = self._from_morse(text)
            else:
                raise ValueError(f"Unsupported decoding scheme: {scheme}")
        except Exception as e:
            raise ValueError(f"Failed to decode data using {scheme}: {str(e)}")

        return {"scheme": scheme, "input_length": len(text), "output": res}

    # =========================================================================
    # 2. Cryptographic Hashing
    # =========================================================================

    def compute_hash(self, data: bytes, algorithm: str = "sha256") -> Dict[str, Any]:
        algo = algorithm.lower().replace("-", "")
        h = None
        warning = None

        if algo == "sha256":
            h = hashlib.sha256(data).hexdigest()
        elif algo == "sha384":
            h = hashlib.sha384(data).hexdigest()
        elif algo == "sha512":
            h = hashlib.sha512(data).hexdigest()
        elif algo in ("sha3", "sha3_256"):
            h = hashlib.sha3_256(data).hexdigest()
        elif algo in ("sha3_512", "sha3512"):
            h = hashlib.sha3_512(data).hexdigest()
        elif algo == "blake2b":
            h = hashlib.blake2b(data).hexdigest()
        elif algo == "blake2s":
            h = hashlib.blake2s(data).hexdigest()
        elif algo == "md5":
            h = hashlib.md5(data).hexdigest()
            warning = "LEGACY ALGORITHM: MD5 is cryptographically broken and vulnerable to collision attacks. Suitable only for legacy checksums, never for passwords or integrity guarantees."
        elif algo == "sha1":
            h = hashlib.sha1(data).hexdigest()
            warning = "LEGACY ALGORITHM: SHA-1 is vulnerable to collision attacks (SHAttered). Not permitted for modern signatures or security-critical validation."
        else:
            raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

        return {
            "algorithm": algorithm.upper(),
            "data_bytes": len(data),
            "hex_digest": h,
            "is_one_way": True,
            "warning": warning,
            "note": "Cryptographic hashes are one-way irreversible transformations."
        }

    # =========================================================================
    # 3. Modern Authenticated Encryption & Decryption
    # =========================================================================

    def encrypt_aes_gcm(self, plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Dict[str, str]:
        """Authenticated AES-GCM encryption with fresh cryptographic nonce generation."""
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Invalid key length: {len(key)} bytes. AES requires 16 (128-bit), 24 (192-bit), or 32 (256-bit) bytes.")

        # Always generate a cryptographically random 96-bit (12-byte) nonce
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        # Ciphertext contains encrypted data + 16-byte authentication tag
        return {
            "algorithm": f"AES-{len(key)*8}-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "format": "base64"
        }

    def decrypt_aes_gcm(self, ciphertext_b64: str, key: bytes, nonce_b64: str, associated_data: Optional[bytes] = None) -> bytes:
        """Authenticated AES-GCM decryption with tag validation."""
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
        except Exception:
            raise ValueError("Invalid Base64 encoding for ciphertext or nonce")

        if len(nonce) != 12:
            raise ValueError(f"Invalid AES-GCM nonce length: {len(nonce)} bytes. Expected 12 bytes.")

        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise ValueError("Decryption failed: Authentication tag verification failed. Ciphertext or associated data has been tampered with.")

    def encrypt_chacha20(self, plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Dict[str, str]:
        """ChaCha20-Poly1305 authenticated encryption."""
        if len(key) != 32:
            raise ValueError(f"ChaCha20-Poly1305 requires a 32-byte (256-bit) key, got {len(key)} bytes.")

        nonce = secrets.token_bytes(12)
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, plaintext, associated_data)

        return {
            "algorithm": "ChaCha20-Poly1305",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "format": "base64"
        }

    def decrypt_chacha20(self, ciphertext_b64: str, key: bytes, nonce_b64: str, associated_data: Optional[bytes] = None) -> bytes:
        """ChaCha20-Poly1305 authenticated decryption with tag validation."""
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        chacha = ChaCha20Poly1305(key)
        try:
            return chacha.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise ValueError("Decryption failed: Poly1305 MAC tag validation failed. Tampered data detected.")

    def generate_rsa_keypair(self, key_size: int = 2048) -> Dict[str, str]:
        """Generates an RSA keypair with PKCS#8 private and SubjectPublicKeyInfo public PEM encoding."""
        if key_size not in (2048, 3072, 4096):
            raise ValueError("RSA key size must be 2048, 3072, or 4096 bits.")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        pem_private = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ).decode("ascii")

        pem_public = private_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

        return {"key_size": key_size, "private_key": pem_private, "public_key": pem_public}

    def rsa_encrypt(self, plaintext: bytes, public_key_pem: str) -> str:
        """RSA-OAEP encryption with SHA-256 and MGF1."""
        pub_key = load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(pub_key, rsa.RSAPublicKey):
            raise ValueError("Provided key is not an RSA public key.")

        ciphertext = pub_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode("ascii")

    def rsa_decrypt(self, ciphertext_b64: str, private_key_pem: str) -> bytes:
        """RSA-OAEP decryption with SHA-256."""
        priv_key = load_pem_private_key(private_key_pem.encode("ascii"), password=None)
        if not isinstance(priv_key, rsa.RSAPrivateKey):
            raise ValueError("Provided key is not an RSA private key.")

        ciphertext = base64.b64decode(ciphertext_b64)
        return priv_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_sign(self, data: bytes, private_key_pem: str) -> str:
        """RSA PSS digital signature with SHA-256."""
        priv_key = load_pem_private_key(private_key_pem.encode("ascii"), password=None)
        sig = priv_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(sig).decode("ascii")

    def rsa_verify(self, data: bytes, signature_b64: str, public_key_pem: str) -> bool:
        """RSA PSS digital signature verification."""
        pub_key = load_pem_public_key(public_key_pem.encode("ascii"))
        sig = base64.b64decode(signature_b64)
        try:
            pub_key.verify(
                sig,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    # =========================================================================
    # 4. Key Derivation & Authentication
    # =========================================================================

    def derive_key_pbkdf2(self, password: str, salt: bytes, length: int = 32, iterations: int = 100000) -> bytes:
        """PBKDF2-HMAC-SHA256 key derivation."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    def compute_hmac(self, key: bytes, message: bytes, algorithm: str = "sha256") -> str:
        """HMAC calculation."""
        hash_func = getattr(hashlib, algorithm.lower(), hashlib.sha256)
        return hmac.new(key, message, hash_func).hexdigest()

    # =========================================================================
    # 5. CyberChef-Style Recipe Pipeline Processor
    # =========================================================================

    def run_recipe(self, input_data: str, operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Executes a sequential chain of cryptographic operations."""
        current_data = input_data
        step_results = []

        for idx, op in enumerate(operations, 1):
            op_name = op.get("op", "").lower()
            params = op.get("params", {})
            step_output = ""

            try:
                if op_name in ("base64_encode", "to_base64"):
                    step_output = self.encode(current_data, "base64")["output"]
                elif op_name in ("base64_decode", "from_base64"):
                    step_output = self.decode(current_data, "base64")["output"]
                elif op_name in ("hex_encode", "to_hex"):
                    step_output = self.encode(current_data, "hex")["output"]
                elif op_name in ("hex_decode", "from_hex"):
                    step_output = self.decode(current_data, "hex")["output"]
                elif op_name in ("url_encode", "to_url"):
                    step_output = self.encode(current_data, "url")["output"]
                elif op_name in ("url_decode", "from_url"):
                    step_output = self.decode(current_data, "url")["output"]
                elif op_name in ("rot13",):
                    step_output = self.encode(current_data, "rot13")["output"]
                elif op_name in ("reverse", "invert"):
                    step_output = current_data[::-1]
                elif op_name.startswith("hash_") or op_name in ("sha256", "sha512", "md5", "sha1"):
                    algo = op_name.replace("hash_", "")
                    step_output = self.compute_hash(current_data.encode("utf-8"), algorithm=algo)["hex_digest"]
                else:
                    raise ValueError(f"Unknown pipeline operation: '{op_name}'")

                step_results.append({
                    "step": idx,
                    "operation": op_name,
                    "status": "SUCCESS",
                    "output_preview": step_output[:80] + ("..." if len(step_output) > 80 else "")
                })
                current_data = step_output
            except Exception as e:
                step_results.append({
                    "step": idx,
                    "operation": op_name,
                    "status": "FAILED",
                    "error": str(e)
                })
                raise ValueError(f"Step {idx} ({op_name}) failed: {str(e)}")

        return {
            "success": True,
            "total_steps": len(operations),
            "final_output": current_data,
            "steps": step_results
        }

    # -------------------------------------------------------------------------
    # Helper ciphers
    # -------------------------------------------------------------------------
    def _rot13(self, text: str) -> str:
        trans = str.maketrans(
            "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
            "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
        )
        return text.translate(trans)

    def _caesar(self, text: str, shift: int = 3) -> str:
        res = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                res.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                res.append(ch)
        return "".join(res)

    def _to_morse(self, text: str) -> str:
        morse_table = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
            '9': '----.', '0': '-----', ' ': '/'
        }
        return " ".join(morse_table.get(c.upper(), '') for c in text if c.upper() in morse_table)

    def _from_morse(self, text: str) -> str:
        rev_morse = {v: k for k, v in {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
            '9': '----.', '0': '-----', ' ': '/'
        }.items()}
        return "".join(rev_morse.get(code, '') for code in text.strip().split())


crypto_engine = CryptoWorkbenchEngine()

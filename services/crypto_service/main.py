"""
SNMK — Independent Cryptography Workbench Microservice (Phase 8)
Standalone Service Entrypoint running on port 8001 (or mounted within gateway).
Provides high-assurance cryptographic operations, recipe execution, and key derivation.
"""

from __future__ import annotations

import base64
import datetime
import os
import secrets
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

# Ensure project root in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from services.crypto_service.engine import crypto_engine
from core.error_sanitizer import safe_error

app = FastAPI(
    title="SNMK Cryptography Workbench Service",
    description="Independent High-Assurance Cryptography & Data Transformation Backend Microservice",
    version="1.0.0"
)

router = APIRouter(prefix="/api/v1/crypto", tags=["Cryptography Workbench"])


# --- Schemas ---

class EncodeRequest(BaseModel):
    text: str
    scheme: str = "base64"


class DecodeRequest(BaseModel):
    text: str
    scheme: str = "base64"


class HashRequest(BaseModel):
    data: str
    algorithm: str = "sha256"
    is_hex_input: bool = False


class EncryptRequest(BaseModel):
    plaintext: str
    algorithm: str = "aes-gcm"  # aes-gcm, chacha20
    key_hex: Optional[str] = None
    passphrase: Optional[str] = None
    associated_data: Optional[str] = None


class DecryptRequest(BaseModel):
    ciphertext_b64: str
    nonce_b64: str
    algorithm: str = "aes-gcm"
    key_hex: Optional[str] = None
    passphrase: Optional[str] = None
    associated_data: Optional[str] = None


class RsaGenerateRequest(BaseModel):
    key_size: int = 2048


class RsaEncryptRequest(BaseModel):
    plaintext: str
    public_key_pem: str


class RsaDecryptRequest(BaseModel):
    ciphertext_b64: str
    private_key_pem: str


class RsaSignRequest(BaseModel):
    data: str
    private_key_pem: str


class RsaVerifyRequest(BaseModel):
    data: str
    signature_b64: str
    public_key_pem: str


class KeyDeriveRequest(BaseModel):
    password: str
    salt_hex: Optional[str] = None
    iterations: int = 100000
    length: int = 32


class RecipeStep(BaseModel):
    op: str
    params: Dict[str, Any] = Field(default_factory=dict)


class RecipeRequest(BaseModel):
    input_data: str
    operations: List[RecipeStep]


# --- Health & Readiness ---

@app.get("/health")
@router.get("/health")
async def crypto_health_check():
    """Independent service health and readiness endpoint."""
    return {
        "service": "snmk-crypto-workbench",
        "status": "HEALTHY",
        "version": "1.0.0",
        "algorithms": ["AES-GCM", "ChaCha20-Poly1305", "RSA-OAEP", "SHA-256", "SHA-512", "SHA-3", "BLAKE2b", "PBKDF2"],
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


# --- Endpoints ---

@router.post("/encode")
async def encode_endpoint(req: EncodeRequest):
    try:
        return crypto_engine.encode(req.text, req.scheme)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=safe_error("Invalid cryptographic request.", e))


@router.post("/decode")
async def decode_endpoint(req: DecodeRequest):
    try:
        return crypto_engine.decode(req.text, req.scheme)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=safe_error("Invalid cryptographic request.", e))


@router.post("/hash")
async def hash_endpoint(req: HashRequest):
    try:
        if req.is_hex_input:
            data_bytes = bytes.fromhex(req.data.replace(" ", "").replace("0x", ""))
        else:
            data_bytes = req.data.encode("utf-8")
        return crypto_engine.compute_hash(data_bytes, algorithm=req.algorithm)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=safe_error("Invalid cryptographic request.", e))


@router.post("/encrypt")
async def encrypt_endpoint(req: EncryptRequest):
    try:
        plaintext_bytes = req.plaintext.encode("utf-8")
        ad_bytes = req.associated_data.encode("utf-8") if req.associated_data else None

        # Derive or parse key
        if req.key_hex:
            key_bytes = bytes.fromhex(req.key_hex.strip())
        elif req.passphrase:
            salt = secrets.token_bytes(16)
            key_bytes = crypto_engine.derive_key_pbkdf2(req.passphrase, salt=salt, length=32)
        else:
            # Generate fresh cryptographic 256-bit key
            key_bytes = secrets.token_bytes(32)

        algo = req.algorithm.lower().replace("-", "").replace("_", "")
        if "chacha" in algo:
            res = crypto_engine.encrypt_chacha20(plaintext_bytes, key_bytes, ad_bytes)
        else:
            res = crypto_engine.encrypt_aes_gcm(plaintext_bytes, key_bytes, ad_bytes)

        # Return key in hex so caller can decrypt (never store key on server!)
        res["key_hex"] = key_bytes.hex()
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=safe_error("Invalid cryptographic request.", e))


@router.post("/decrypt")
async def decrypt_endpoint(req: DecryptRequest):
    try:
        ad_bytes = req.associated_data.encode("utf-8") if req.associated_data else None

        if req.key_hex:
            key_bytes = bytes.fromhex(req.key_hex.strip())
        elif req.passphrase:
            raise HTTPException(status_code=400, detail="Key hex required for authenticated decryption.")
        else:
            raise HTTPException(status_code=400, detail="Missing decryption key")

        algo = req.algorithm.lower().replace("-", "").replace("_", "")
        if "chacha" in algo:
            decrypted = crypto_engine.decrypt_chacha20(req.ciphertext_b64, key_bytes, req.nonce_b64, ad_bytes)
        else:
            decrypted = crypto_engine.decrypt_aes_gcm(req.ciphertext_b64, key_bytes, req.nonce_b64, ad_bytes)

        return {
            "status": "SUCCESS",
            "plaintext": decrypted.decode("utf-8", errors="replace"),
            "bytes_length": len(decrypted)
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=safe_error("Invalid cryptographic request.", e))


@router.post("/rsa/generate-keys")
async def rsa_generate_endpoint(req: RsaGenerateRequest):
    try:
        return crypto_engine.generate_rsa_keypair(key_size=req.key_size)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=safe_error("Invalid cryptographic request.", e))


@router.post("/rsa/encrypt")
async def rsa_encrypt_endpoint(req: RsaEncryptRequest):
    try:
        b64 = crypto_engine.rsa_encrypt(req.plaintext.encode("utf-8"), req.public_key_pem)
        return {"ciphertext_b64": b64, "algorithm": "RSA-OAEP-SHA256"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=safe_error("RSA encryption failed.", e))


@router.post("/rsa/decrypt")
async def rsa_decrypt_endpoint(req: RsaDecryptRequest):
    try:
        dec = crypto_engine.rsa_decrypt(req.ciphertext_b64, req.private_key_pem)
        return {"plaintext": dec.decode("utf-8", errors="replace"), "bytes_length": len(dec)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=safe_error("RSA decryption failed.", e))


@router.post("/rsa/sign")
async def rsa_sign_endpoint(req: RsaSignRequest):
    try:
        sig = crypto_engine.rsa_sign(req.data.encode("utf-8"), req.private_key_pem)
        return {"signature_b64": sig, "algorithm": "RSA-PSS-SHA256"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=safe_error("RSA signing failed.", e))


@router.post("/rsa/verify")
async def rsa_verify_endpoint(req: RsaVerifyRequest):
    try:
        valid = crypto_engine.rsa_verify(req.data.encode("utf-8"), req.signature_b64, req.public_key_pem)
        return {"valid": valid, "status": "VERIFIED" if valid else "SIGNATURE_MISMATCH"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=safe_error("RSA verification failed.", e))


@router.post("/derive-key")
async def derive_key_endpoint(req: KeyDeriveRequest):
    salt = bytes.fromhex(req.salt_hex) if req.salt_hex else secrets.token_bytes(16)
    k = crypto_engine.derive_key_pbkdf2(req.password, salt=salt, length=req.length, iterations=req.iterations)
    return {
        "algorithm": "PBKDF2-HMAC-SHA256",
        "key_hex": k.hex(),
        "salt_hex": salt.hex(),
        "iterations": req.iterations,
        "length_bytes": req.length
    }


@router.post("/recipe")
async def run_recipe_endpoint(req: RecipeRequest):
    try:
        ops = [step.model_dump() for step in req.operations]
        return crypto_engine.run_recipe(req.input_data, ops)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=safe_error("Invalid cryptographic request.", e))


app.include_router(router)

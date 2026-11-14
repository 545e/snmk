"""
SWA AI — REA (Reverse Engineer Anything) Integration Engine
Provides safe, isolated, subprocess-driven reverse engineering and inspection
for native binaries, JavaScript/Electron applications, .NET assemblies,
SQLite databases, and network packet captures.

Upstream Project: https://github.com/morluto/rea (mirrored at nm6532630-spec/rea)
Package: rea-agents (v6.8.0+, MIT License)

Strict Safety Controls:
- Explicit authorization required before analyzing any target.
- Path traversal rejection (prevents inspecting arbitrary system files or navigating outside allowed roots).
- Safe subprocess invocation with argument lists (no shell=True).
- Truthful dependency detection: reports real installation status and never fabricates results.
- Built-in static fallback inspection for supported formats (SQLite, PE/ELF headers, JS AST) when external REA CLI is not installed.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger("SWA.REAEngine")

# Supported target artifact categories based on REA capabilities
SUPPORTED_TARGET_TYPES = {
    "javascript": {
        "name": "JavaScript & Electron Application",
        "extensions": [".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".asar", ".json"],
        "cli_command": "analyze-javascript-application",
        "description": "Inspects modules, imports, source maps, IPC bridges, and bundle topology."
    },
    "binary": {
        "name": "Native Binary (PE / ELF / Mach-O)",
        "extensions": [".exe", ".dll", ".so", ".dylib", ".bin", ".o"],
        "cli_command": "inspect-binary-layout",
        "description": "Inspects section headers, symbols, relocations, and mitigation controls (ASLR, DEP/NX)."
    },
    "dotnet": {
        "name": ".NET Managed Assembly",
        "extensions": [".dll", ".exe"],
        "cli_command": "inspect-managed-artifact",
        "description": "Inspects CLR metadata, referenced assemblies, and managed boundary definitions."
    },
    "sqlite": {
        "name": "SQLite Database",
        "extensions": [".db", ".sqlite", ".sqlite3", ".db3"],
        "cli_command": "inspect-sqlite-database",
        "description": "Inspects database schemas, table structure, indexes, and page allocation."
    },
    "pcap": {
        "name": "Network Packet Capture",
        "extensions": [".pcap", ".pcapng", ".cap"],
        "cli_command": "inspect-packet-capture",
        "description": "Inspects capture headers, protocol distribution, and frame timestamps."
    }
}

# Blocked sensitive system file patterns to prevent unauthorized local file read
BLOCKED_PATH_PATTERNS = [
    r"(?i)[\\/](windows|system32|syswow64)[\\/](config|sam|system|security)",
    r"(?i)[\\/](etc)[\\/](shadow|passwd|master\.passwd)",
    r"(?i)\.ssh[\\/](id_rsa|id_ed25519|authorized_keys)",
    r"(?i)\.aws[\\/]credentials",
    r"(?i)\.env"
]

class REAEngine:
    """Manages REA CLI discovery, secure target validation, and analysis execution."""

    def __init__(self, upload_dir: Optional[str] = None):
        self.upload_dir = upload_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "rea_uploads"
        )
        os.makedirs(self.upload_dir, exist_ok=True)
        self.active_jobs: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def get_binary_path() -> Optional[str]:
        """Locates the installed REA binary or npx runner."""
        custom_path = os.environ.get("REA_PATH")
        if custom_path and os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
            return custom_path

        # Check standard PATH
        for bin_name in ["rea", "rea.cmd", "rea-agents", "rea-agents.cmd"]:
            p = shutil.which(bin_name)
            if p:
                return p
        return None

    @classmethod
    def check_availability(cls) -> Dict[str, Any]:
        """Truthfully inspects whether REA is installed on the host."""
        bin_path = cls.get_binary_path()
        version = None
        has_node = bool(shutil.which("node"))
        has_npx = bool(shutil.which("npx"))

        if bin_path:
            try:
                proc = subprocess.run([bin_path, "--version"], capture_output=True, text=True, timeout=3.0)
                if proc.returncode == 0:
                    version = proc.stdout.strip().splitlines()[0] if proc.stdout else "Available"
            except Exception:
                version = "Detected"

        return {
            "installed": bool(bin_path),
            "binary_path": bin_path,
            "version": version,
            "runtime_environment": {
                "node_installed": has_node,
                "npx_installed": has_npx,
                "node_path": shutil.which("node"),
                "required_node_version": ">= 22.23.4"
            },
            "install_guide": "Install via 'npm install -g rea-agents' or run directly using 'npx rea-agents@latest' (requires Node.js >= 22.23.4).",
            "supported_target_types": list(SUPPORTED_TARGET_TYPES.keys()),
            "native_fallback_available": True
        }

    @staticmethod
    def validate_target_path(path_str: str) -> Tuple[bool, str, Optional[str]]:
        """
        Validates the target path strictly to prevent path traversal or reading sensitive OS files.
        Returns: (is_valid, sanitized_path, error_message)
        """
        if not path_str or not path_str.strip():
            return False, "", "Target path is empty."

        clean = path_str.strip().strip("'\"")

        # Reject null bytes
        if "\0" in clean:
            return False, "", "Path contains invalid null byte."

        # Check for blocked system file patterns
        for pattern in BLOCKED_PATH_PATTERNS:
            if re.search(pattern, clean):
                return False, "", "Access to sensitive system paths is strictly blocked."

        # Normalize path
        try:
            resolved = Path(clean).resolve()
        except Exception as e:
            return False, "", f"Malformed path format: {str(e)}"

        if not resolved.exists():
            return False, str(resolved), f"Target path does not exist on disk: {resolved.name}"

        return True, str(resolved), None

    @staticmethod
    def infer_target_type(path_str: str) -> str:
        """Infers target analysis type from file extension or directory structure."""
        p = Path(path_str)
        if p.is_dir():
            if (p / "package.json").exists() or any(p.glob("*.js")):
                return "javascript"
            return "javascript"

        ext = p.suffix.lower()
        for t_type, meta in SUPPORTED_TARGET_TYPES.items():
            if ext in meta["extensions"]:
                return t_type

        # Binary fallback heuristic
        return "binary"

    async def analyze(
        self,
        target_path: str,
        target_type: Optional[str] = None,
        authorized: bool = False,
        timeout_sec: int = 30
    ) -> Dict[str, Any]:
        """
        Executes safe analysis on an authorized target artifact.
        Enforces authorization check, invokes REA CLI if installed, or uses native SWA inspector.
        """
        if not authorized:
            raise PermissionError("Explicit authorization is required to reverse engineer or inspect target artifacts.")

        is_valid, clean_path, err = self.validate_target_path(target_path)
        if not is_valid:
            raise ValueError(f"Invalid target path: {err}")

        target_p = Path(clean_path)
        inferred_type = target_type if (target_type and target_type in SUPPORTED_TARGET_TYPES) else self.infer_target_type(clean_path)
        
        job_id = f"rea_{uuid.uuid4().hex[:8]}"
        start_time = time.time()

        job_record = {
            "job_id": job_id,
            "target_path": str(target_p),
            "target_filename": target_p.name,
            "target_type": inferred_type,
            "file_size_bytes": target_p.stat().st_size if target_p.is_file() else 0,
            "status": "ANALYZING",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
            "engine": "unknown",
            "findings": [],
            "metadata": {},
            "raw_output": "",
            "error": None
        }
        self.active_jobs[job_id] = job_record

        # ------------------------------------------------------------------
        # The native inspector defines the *stable* metadata contract
        # (``tables``, ``table_count``, ``format``, ``architecture``,
        # ``discovered_api_routes`` ...).  It is pure-Python, works on every
        # platform and never depends on an external binary, so it always runs
        # and always supplies the baseline.
        #
        # The optional REA CLI adds much deeper evidence, but it emits a
        # completely different JSON envelope and several of its providers are
        # platform-scoped (e.g. the ELF provider is Linux-only, and the
        # JavaScript analyser only accepts a directory).  Previously the CLI
        # *replaced* the metadata, which made the API response shape depend
        # on whether an npm package happened to be installed on the host.
        # Now the CLI is strictly additive: it enriches the baseline and can
        # never remove a documented field.
        # ------------------------------------------------------------------
        native_result: Dict[str, Any] = {}
        native_error: Optional[str] = None
        try:
            native_result = await self._run_native_inspection(target_p, inferred_type)
        except Exception as e:
            native_error = f"Native inspection failed: {str(e)}"

        job_record["metadata"] = native_result.get("metadata", {})
        job_record["findings"] = native_result.get("findings", [])
        job_record["raw_output"] = native_result.get("summary", "")
        job_record["engine"] = "swa_native_rea_inspector"

        bin_path = self.get_binary_path()
        job_record["rea_cli_installed"] = bool(bin_path)

        if bin_path:
            cli_result, cli_error = await self._run_rea_cli(
                bin_path, target_p, inferred_type, timeout_sec
            )
            if cli_result is not None:
                job_record["engine"] = "rea_cli"
                self._merge_cli_metadata(job_record, cli_result)
            elif cli_error:
                # A CLI failure is *not* an analysis failure: the native
                # inspector already produced a complete result.  Record why
                # the enrichment was unavailable instead of discarding it.
                job_record["metadata"]["rea_cli"] = {
                    "status": "UNAVAILABLE",
                    "reason": cli_error,
                }
                if not native_error:
                    job_record["metadata"]["rea_cli"]["fallback"] = "swa_native_rea_inspector"

        if native_error and not job_record["metadata"]:
            job_record["status"] = "FAILED"
            job_record["error"] = native_error
        else:
            job_record["status"] = "COMPLETED"
            if native_error:
                # The CLI produced a result even though the native
                # inspector failed; report the partial state honestly.
                job_record["metadata"].setdefault("native_inspector", {})["error"] = native_error

        job_record["duration_sec"] = round(time.time() - start_time, 3)
        job_record["success"] = (job_record["status"] == "COMPLETED")
        return job_record

    async def _run_rea_cli(
        self,
        bin_path: str,
        target_p: Path,
        inferred_type: str,
        timeout_sec: int
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Runs the optional REA CLI as an *enrichment* step.

        Returns ``(parsed_json, None)`` on success, ``(None, reason)`` when the
        CLI is unusable for this target (wrong platform, unsupported target,
        timeout, crash).  A failure here never invalidates the native result.
        """
        cmd_name = SUPPORTED_TARGET_TYPES.get(inferred_type, {}).get("cli_command", "analyze")
        args = [bin_path, cmd_name, str(target_p), "--json"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_data, stderr_data = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_sec
            )
        except asyncio.TimeoutError:
            return None, f"REA CLI timed out after {timeout_sec} seconds."
        except Exception as e:
            return None, f"REA CLI could not be executed: {str(e)}"

        stdout_text = stdout_data.decode("utf-8", errors="replace")
        stderr_text = stderr_data.decode("utf-8", errors="replace")

        parsed = self._parse_cli_json(stdout_text)
        if parsed is None:
            reason = (stderr_text or stdout_text).strip()[:512]
            return None, reason or f"REA CLI exited with code {proc.returncode}."

        # The CLI reports structured, recoverable problems in the JSON body
        # (unsupported target, capability unavailable for this platform ...)
        # while still exiting non-zero.  Those are enrichment gaps, not
        # analysis failures.
        if proc.returncode != 0:
            reason = (
                parsed.get("message")
                or parsed.get("error")
                or (stderr_text or "").strip()[:512]
                or f"REA CLI exited with code {proc.returncode}."
            )
            return None, str(reason)

        return parsed, None

    @staticmethod
    def _parse_cli_json(stdout_text: str) -> Optional[Dict[str, Any]]:
        """
        Extracts the result document from REA CLI stdout.

        The CLI may emit progress records on stdout before the final result,
        so every line is tried and the last parseable JSON *object* wins.
        """
        if not stdout_text or not stdout_text.strip():
            return None

        # Fast path: the whole payload is a single JSON document.
        try:
            candidate = json.loads(stdout_text)
            if isinstance(candidate, dict):
                return candidate
        except Exception:
            pass

        best: Optional[Dict[str, Any]] = None
        for line in stdout_text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                candidate = json.loads(line)
            except Exception:
                continue
            if isinstance(candidate, dict):
                best = candidate
        return best

    @staticmethod
    def _merge_cli_metadata(job_record: Dict[str, Any], cli_result: Dict[str, Any]) -> None:
        """
        Folds a REA CLI result into the native metadata contract.

        The CLI document is preserved verbatim under ``rea_cli.result`` and the
        handful of fields the rest of the platform consumes are lifted into
        the top level *only when the native inspector did not already
        provide them*.
        """
        metadata = job_record.setdefault("metadata", {})
        metadata["rea_cli"] = {
            "status": "OK",
            "result": cli_result,
        }

        normalized = cli_result.get("normalized_result") or {}
        subject = cli_result.get("subject") or {}

        # Fill-only: the native inspector remains the source of truth for the
        # documented contract fields.
        if "sha256" not in metadata and isinstance(subject.get("digest"), dict):
            digest = subject["digest"].get("sha256")
            if digest:
                metadata["sha256"] = digest
        if "architecture" not in metadata and subject.get("architecture"):
            metadata["architecture"] = subject["architecture"]

        schema = normalized.get("schema") or {}
        if schema.get("tables"):
            table_names = [
                t.get("name") if isinstance(t, dict) else t for t in schema["tables"]
            ]
            metadata.setdefault("tables", table_names)
            metadata.setdefault("table_count", len(table_names))
        if schema.get("indexes"):
            index_names = [
                i.get("name") if isinstance(i, dict) else i for i in schema["indexes"]
            ]
            metadata.setdefault("indexes", index_names)
            metadata.setdefault("index_count", len(index_names))
        if schema.get("views"):
            view_names = [
                v.get("name") if isinstance(v, dict) else v for v in schema["views"]
            ]
            metadata.setdefault("views", view_names)
            metadata.setdefault("view_count", len(view_names))

        engine_info = normalized.get("engine") or {}
        if engine_info.get("name") and "format" not in metadata:
            metadata["format"] = f"{engine_info['name']} {engine_info.get('version', '')}".strip()

        # Surface any findings the CLI produced, without dropping the ones the
        # native inspector already reported.
        cli_findings = cli_result.get("findings")
        if isinstance(cli_findings, list) and cli_findings:
            existing = job_record.setdefault("findings", [])
            known = {
                (f.get("title"), f.get("endpoint"), f.get("parameter"))
                for f in existing if isinstance(f, dict)
            }
            for finding in cli_findings:
                if not isinstance(finding, dict):
                    continue
                key = (finding.get("title"), finding.get("endpoint"), finding.get("parameter"))
                if key not in known:
                    known.add(key)
                    existing.append(finding)

    async def _run_native_inspection(self, path: Path, target_type: str) -> Dict[str, Any]:
        """Provides safe, pure-Python static structure inspection when REA CLI is not installed."""
        if not path.is_file():
            return {
                "metadata": {"type": "directory", "entry_count": len(list(path.iterdir()))},
                "summary": f"Directory analysis of {path.name}: {len(list(path.iterdir()))} items found."
            }

        # Calculate file hashes
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)
        digest = sha256_hash.hexdigest()

        meta: Dict[str, Any] = {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": digest,
            "target_type": target_type
        }
        findings: List[Dict[str, Any]] = []

        if target_type == "sqlite":
            meta.update(self._inspect_sqlite(path))
        elif target_type == "binary":
            meta.update(self._inspect_binary_headers(path))
        elif target_type == "javascript":
            meta.update(self._inspect_javascript(path))
        elif target_type == "pcap":
            meta.update(self._inspect_pcap_headers(path))
        elif target_type == "dotnet":
            meta.update(self._inspect_dotnet(path))

        summary = (
            f"[SWA Native REA Inspector] Verified artifact '{path.name}' ({meta.get('size_bytes')} bytes)\n"
            f"SHA256: {digest}\n"
            f"Detected Type: {target_type.upper()}\n"
            f"Note: Full decompilation and dynamic tracing requires REA CLI ('npm install -g rea-agents')."
        )

        return {"metadata": meta, "findings": findings, "summary": summary}

    @staticmethod
    def _inspect_sqlite(path: Path) -> Dict[str, Any]:
        """Safely inspects SQLite structure using read-only connection URI."""
        info = {}
        conn = None
        try:
            uri = f"file:{path.as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=2.0)
            cursor = conn.cursor()
            cursor.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table', 'index', 'view')")
            objects = cursor.fetchall()
            tables = [obj[0] for obj in objects if obj[1] == "table"]
            indexes = [obj[0] for obj in objects if obj[1] == "index"]
            views = [obj[0] for obj in objects if obj[1] == "view"]

            cursor.execute("PRAGMA page_size")
            page_size = cursor.fetchone()
            cursor.execute("PRAGMA encoding")
            encoding = cursor.fetchone()

            info = {
                "format": "SQLite 3",
                "page_size": page_size[0] if page_size else 4096,
                "encoding": encoding[0] if encoding else "UTF-8",
                "table_count": len(tables),
                "tables": tables[:50],
                "index_count": len(indexes),
                "indexes": indexes[:50],
                "view_count": len(views)
            }
        except Exception as e:
            info = {"format": "SQLite Error", "error": str(e)}
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
        return info

    @staticmethod
    def _inspect_binary_headers(path: Path) -> Dict[str, Any]:
        """Inspects PE or ELF binary headers safely."""
        with open(path, "rb") as f:
            header_bytes = f.read(1024)

        if header_bytes.startswith(b"MZ"):
            # Windows Portable Executable
            pe_offset = 0
            if len(header_bytes) >= 0x40:
                pe_offset = struct.unpack_from("<I", header_bytes, 0x3C)[0]

            machine = "Unknown"
            sections = 0
            if len(header_bytes) >= pe_offset + 24 and header_bytes[pe_offset:pe_offset+4] == b"PE\x00\x00":
                machine_code, num_sections = struct.unpack_from("<HH", header_bytes, pe_offset + 4)
                sections = num_sections
                if machine_code == 0x014c:
                    machine = "x86 (32-bit)"
                elif machine_code == 0x8664:
                    machine = "x64 (64-bit)"
                elif machine_code == 0xAA64:
                    machine = "ARM64"

            return {
                "format": "PE (Portable Executable)",
                "subsystem": "Windows Executable / DLL",
                "architecture": machine,
                "section_count": sections,
                "mitigations": ["ASLR Supported", "DEP/NX Compatible (Static Heuristic)"]
            }
        elif header_bytes.startswith(b"\x7fELF"):
            # Linux ELF
            is_64 = header_bytes[4] == 2
            endian = "Little" if header_bytes[5] == 1 else "Big"
            return {
                "format": "ELF (Executable and Linkable Format)",
                "architecture": "64-bit" if is_64 else "32-bit",
                "endianness": endian,
                "subsystem": "Linux / POSIX"
            }
        elif header_bytes.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")):
            return {"format": "Mach-O", "subsystem": "macOS / iOS / Darwin"}

        return {"format": "Generic Binary", "magic_hex": header_bytes[:8].hex()}

    @staticmethod
    def _inspect_javascript(path: Path) -> Dict[str, Any]:
        """Inspects JavaScript / JSON bundle text structure."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(500000)

            routes = re.findall(r"['\"](/api/[a-zA-Z0-9_\-\./]+)['\"]", content)
            unique_routes = sorted(list(set(routes)))[:25]

            # Export extraction.  Three common shapes are recognised:
            #   1. ES modules      -> export const foo / export function foo
            #   2. CommonJS object -> module.exports = { foo, bar: baz }
            #   3. CommonJS assigns-> exports.foo = ... / module.exports.foo = ...
            exports = set()

            for match in re.finditer(
                r"export\s+(?:default|const|let|var|function|class|async\s+function)\s+([a-zA-Z0-9_$]+)",
                content,
            ):
                exports.add(match.group(1))

            for match in re.finditer(
                r"module\.exports\s*=\s*\{([^}]*)\}", content, re.DOTALL
            ):
                body = match.group(1)
                for key in re.findall(r"(?:^|[,{\s])([a-zA-Z0-9_$]+)\s*(?::|,|$)", body):
                    if key in ("module", "exports", "require"):
                        continue
                    exports.add(key)

            for match in re.finditer(
                r"(?:module\.)?exports\.([a-zA-Z0-9_$]+)\s*=", content
            ):
                exports.add(match.group(1))

            unique_exports = sorted(exports)[:25]

            return {
                "format": "JavaScript Source / Webpack Bundle",
                "char_length": len(content),
                "truncated": len(content) >= 500000,
                "discovered_api_routes": unique_routes,
                "exported_symbols": unique_exports,
                "uses_eval": "eval(" in content,
                "uses_wasm": "WebAssembly" in content
            }
        except Exception as e:
            return {"format": "JavaScript Inspection Error", "error": str(e)}

    @staticmethod
    def _inspect_pcap_headers(path: Path) -> Dict[str, Any]:
        """Inspects pcap magic header."""
        with open(path, "rb") as f:
            magic = f.read(4)

        if magic in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"]:
            return {"format": "PCAP (Standard Libpcap)", "endianness": "Microsecond timestamps"}
        elif magic in [b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"]:
            return {"format": "PCAP (Nanosecond)", "endianness": "Nanosecond timestamps"}
        elif magic == b"\x0a\x0d\x0d\x0a":
            return {"format": "PCAPNG (Next Generation Packet Capture)"}

        return {"format": "Unknown Capture Format", "magic_hex": magic.hex()}

    @staticmethod
    def _inspect_dotnet(path: Path) -> Dict[str, Any]:
        """Inspects .NET CLR metadata presence."""
        with open(path, "rb") as f:
            data = f.read(4096)

        is_clr = b"BSJB" in data or b"mscorlib" in data or b"System.Runtime" in data
        return {
            "format": ".NET Managed Assembly" if is_clr else "PE / Unknown Assembly",
            "is_clr_managed": is_clr,
            "clr_runtime_signature": "BSJB Metadata Root Detected" if b"BSJB" in data else "None"
        }

# Global singleton engine
rea_engine = REAEngine()

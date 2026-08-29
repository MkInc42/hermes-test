"""Validation and preparation rules for untrusted intake evidence."""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from email import policy
from email.parser import BytesParser
from pathlib import PurePath
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

MAX_URL_LENGTH = 4096
MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_OCR_CHARS = 100_000
MAX_SCREENSHOT_BYTES = 15 * 1024 * 1024


class IntakeValidationError(ValueError):
    """An intake failed a safe, client-correctable boundary."""


def normalize_url(value: str) -> str:
    """Validate and normalize an absolute HTTP(S) URL.

    Args:
        value: Untrusted URL text.

    Returns:
        The URL with a normalized scheme, host, and default path.

    Raises:
        IntakeValidationError: If the URL is unsafe, ambiguous, or malformed.
    """
    if not isinstance(value, str):
        raise IntakeValidationError("url must be a string")
    original = value
    value = value.strip(" \t\r\n")
    if not value:
        raise IntakeValidationError("url must not be empty")
    if len(original) > MAX_URL_LENGTH:
        raise IntakeValidationError(f"url exceeds {MAX_URL_LENGTH} characters")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"} for char in value):
        raise IntakeValidationError("url contains control or formatting characters")
    if "\\" in value:
        raise IntakeValidationError("url contains ambiguous backslashes")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise IntakeValidationError("url is malformed or ambiguous") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise IntakeValidationError("only http and https URL schemes are allowed")
    if not parsed.netloc or parsed.hostname is None:
        raise IntakeValidationError("url requires an unambiguous host")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise IntakeValidationError("url userinfo is not allowed")
    if any(char.isspace() for char in parsed.netloc):
        raise IntakeValidationError("url host contains whitespace")
    host = parsed.hostname.rstrip(".")
    if not host:
        raise IntakeValidationError("url host is empty")
    try:
        ip = ipaddress.ip_address(host)
        ascii_host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    except ValueError:
        try:
            labels = host.split(".")
            if any(not label for label in labels):
                raise UnicodeError
            ascii_host = ".".join(label.encode("idna").decode("ascii") for label in labels).lower()
        except UnicodeError as exc:
            raise IntakeValidationError("url host is not valid IDN/DNS syntax") from exc
        if len(ascii_host) > 253 or any(len(label) > 63 for label in ascii_host.split(".")):
            raise IntakeValidationError("url host exceeds DNS length limits")
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
               for label in ascii_host.split(".")):
            raise IntakeValidationError("url host contains invalid DNS characters")
    netloc = ascii_host + (f":{port}" if port is not None else "")
    normalized = urlunsplit(SplitResult(parsed.scheme.lower(), netloc, parsed.path or "/",
                                        parsed.query, parsed.fragment))
    if len(normalized) > MAX_URL_LENGTH:
        raise IntakeValidationError(f"normalized url exceeds {MAX_URL_LENGTH} characters")
    return normalized


def safe_filename(filename: str | None) -> str | None:
    """Reduce an untrusted upload filename to a printable basename.

    Args:
        filename: Client-provided filename, if present.

    Returns:
        A bounded basename, or ``None`` when no safe name remains.
    """
    if not filename:
        return None
    name = PurePath(filename.replace("\\", "/")).name
    name = "".join(c for c in name if c.isprintable() and c not in "\x00/")[:255]
    return name or None


def prepare_email(
    data: bytes, filename: str, media_type: str
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate an email upload and derive inert EML headers.

    Args:
        data: Untrusted uploaded bytes.
        filename: Client-provided filename.
        media_type: Client-provided media type.

    Returns:
        The email kind, original artifact descriptors, and derived descriptors.

    Raises:
        IntakeValidationError: If upload boundaries or format checks fail.
    """
    if not data:
        raise IntakeValidationError("email artifact must not be empty")
    if len(data) > MAX_EMAIL_BYTES:
        raise IntakeValidationError(f"email artifact exceeds {MAX_EMAIL_BYTES} bytes")
    name = safe_filename(filename)
    extension = PurePath(name or "").suffix.lower()
    allowed = {
        ".eml": {"message/rfc822", "application/octet-stream"},
        ".msg": {"application/vnd.ms-outlook", "application/octet-stream"},
    }
    if extension not in allowed or media_type.lower().split(";", 1)[0] not in allowed[extension]:
        raise IntakeValidationError("email upload must be a matching .eml or .msg media type")
    kind = extension[1:]
    derived: list[dict[str, Any]] = []
    if kind == "eml":
        try:
            message = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
            headers = {key: message.get_all(key, []) for key in message.keys()}
            encoded = json.dumps(headers, ensure_ascii=False, sort_keys=True).encode("utf-8")
            derived.append({"derived_kind": "parsed_headers", "media_type": "application/json",
                            "data": encoded, "parent_key": "email"})
        except Exception as exc:
            raise IntakeValidationError("eml headers could not be parsed safely") from exc
    return kind, [{"key": "email", "artifact_type": kind, "media_type": media_type,
                   "original_filename": name, "data": data, "is_sensitive": True}], derived


def derive_pasted_headers(canonical: bytes) -> list[dict[str, Any]]:
    """Derive inert JSON headers from pasted RFC-style text.

    Args:
        canonical: Canonicalized pasted email bytes.

    Returns:
        A descriptor linking parsed headers to the original email artifact.

    Raises:
        IntakeValidationError: If the headers cannot be parsed safely.
    """
    try:
        message = BytesParser(policy=policy.default).parsebytes(canonical, headersonly=True)
        headers = {key: message.get_all(key, []) for key in message.keys()}
        encoded = json.dumps(headers, ensure_ascii=False, sort_keys=True).encode("utf-8")
    except Exception as exc:
        raise IntakeValidationError("pasted email headers could not be parsed safely") from exc
    return [{"derived_kind": "parsed_headers", "media_type": "application/json",
             "data": encoded, "parent_key": "email"}]


URL_RE = re.compile(r"https?://[^\s<>\]\[\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w])", re.I)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)")


def extract_ocr_indicators(text: str) -> list[dict[str, Any]]:
    """Extract deduplicated, unverified indicators from OCR text.

    Args:
        text: OCR-derived text to inspect without network access.

    Returns:
        Indicator descriptors marked with OCR provenance.
    """
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for kind, regex in (("url", URL_RE), ("domain", DOMAIN_RE), ("phone_number", PHONE_RE)):
        for match in regex.finditer(text):
            value = match.group(0).rstrip(".,;:!?)")
            if kind == "url":
                try:
                    value = normalize_url(value)
                except IntakeValidationError:
                    continue
            elif kind == "phone_number":
                digits = re.sub(r"\D", "", value)
                if not 8 <= len(digits) <= 15:
                    continue
            key = (kind, value.lower())
            if key not in seen:
                seen.add(key)
                found.append({"indicator_type": kind, "raw_value": value,
                              "provenance": "ocr_derived", "confidence": None})
    return found


def validate_ocr(text: str) -> bytes:
    """Validate OCR text and encode it for artifact storage.

    Args:
        text: Untrusted OCR text.

    Returns:
        UTF-8 encoded OCR text.

    Raises:
        IntakeValidationError: If the text is empty or exceeds the size limit.
    """
    if not isinstance(text, str) or not text.strip():
        raise IntakeValidationError("ocr_text must not be empty")
    if len(text) > MAX_OCR_CHARS:
        raise IntakeValidationError(f"ocr_text exceeds {MAX_OCR_CHARS} characters")
    return text.encode("utf-8")


def validate_screenshot(data: bytes, filename: str, media_type: str) -> tuple[str, str]:
    """Validate screenshot evidence by size, extension, type, and signature.

    Args:
        data: Untrusted uploaded bytes.
        filename: Client-provided filename.
        media_type: Client-provided media type.

    Returns:
        The artifact kind and normalized media type.

    Raises:
        IntakeValidationError: If any evidence boundary check fails.
    """
    if not data:
        raise IntakeValidationError("screenshot evidence must not be empty")
    if len(data) > MAX_SCREENSHOT_BYTES:
        raise IntakeValidationError(f"screenshot evidence exceeds {MAX_SCREENSHOT_BYTES} bytes")
    media = media_type.lower().split(";", 1)[0]
    boundaries = {
        "image/png": (".png", b"\x89PNG\r\n\x1a\n", "screenshot"),
        "image/jpeg": ((".jpg", ".jpeg"), b"\xff\xd8\xff", "screenshot"),
        "image/webp": (".webp", b"RIFF", "screenshot"),
        "application/pdf": (".pdf", b"%PDF-", "pdf"),
    }
    if media not in boundaries:
        raise IntakeValidationError("only png, jpeg, webp, and pdf evidence is allowed")
    extensions, signature, kind = boundaries[media]
    extension = PurePath(safe_filename(filename) or "").suffix.lower()
    if extension not in ((extensions,) if isinstance(extensions, str) else extensions):
        raise IntakeValidationError("filename extension does not match screenshot media type")
    signature_ok = data.startswith(signature)
    if media == "image/webp":
        signature_ok = data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP"
    if not signature_ok:
        raise IntakeValidationError("file signature does not match screenshot media type")
    return kind, media

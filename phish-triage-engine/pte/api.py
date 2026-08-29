"""Tenant-scoped FastAPI intake endpoints. No endpoint performs network I/O."""

from __future__ import annotations

from typing import Annotated, Any

# WHY: FastAPI supplies the validated HTTP boundary and multipart primitives.
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
# WHY: Pydantic enforces strict, declarative schemas before intake data is persisted.
from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError
import psycopg

from .artifacts import ArtifactStorageError, ArtifactStore
from .db import DbConfig, connect
from .intake import (IntakeValidationError, derive_pasted_headers, extract_ocr_indicators, normalize_url,
                     prepare_email, safe_filename, validate_ocr, validate_screenshot)
from .services import compute_sha256, TenantRequiredError, ValidationError, create_intake_bundle


class Attested(BaseModel):
    """Common authorization attestations required for every intake."""

    model_config = ConfigDict(extra="forbid")
    tenant_uid: str = Field(min_length=1, max_length=255)
    authorization_attested: bool
    no_credentials_acknowledged: bool


class UrlIntake(Attested):
    """Validated request shape for a submitted URL."""

    url: str


class OcrIntake(Attested):
    """Validated request shape for OCR-derived message text."""

    ocr_text: str
    platform: str | None = Field(default=None, max_length=100)
    engine: str | None = Field(default=None, max_length=100)
    confidence: float | None = Field(default=None, ge=0, le=1)


class EmailPasteIntake(Attested):
    """Validated request shape for pasted email evidence."""

    mode: str
    raw_headers: str | None = None
    body: str


REQUEST_VALIDATION_DETAIL = "request validation failed"


def _attested_from_form(tenant_uid: str, authorization_attested: bool,
                        no_credentials_acknowledged: bool) -> Attested:
    """Validate multipart attestations without exposing submitted values."""
    try:
        return Attested(tenant_uid=tenant_uid, authorization_attested=authorization_attested,
                        no_credentials_acknowledged=no_credentials_acknowledged)
    except PydanticValidationError as exc:
        raise HTTPException(422, REQUEST_VALIDATION_DETAIL) from exc


def _cfg(request: Request) -> DbConfig:
    return request.app.state.db_config


def _accept(request: Request, common: Attested, *, source_type: str, fidelity: str,
            notes: str | None, envelope: dict[str, Any], policy: dict[str, Any],
            artifacts: list[dict[str, Any]], derived: list[dict[str, Any]] | None = None,
            indicators: list[dict[str, Any]] | None = None,
            response_policy: dict[str, Any] | None = None) -> dict[str, Any]:
    if not common.authorization_attested or not common.no_credentials_acknowledged:
        raise HTTPException(400, "authorization and no-credentials attestations must both be true")
    try:
        result = create_intake_bundle(
            _cfg(request), tenant_uid=common.tenant_uid, source_type=source_type,
            fidelity=fidelity, fidelity_notes=notes, envelope=envelope,
            policy_decisions=policy, artifacts=artifacts, derived_artifacts=derived,
            indicators=indicators, storage_writer=request.app.state.artifact_store.put,
            consent_authorized=common.authorization_attested,
            consent_no_credentials=common.no_credentials_acknowledged,
        )
    except (IntakeValidationError, ValidationError) as exc:
        raise HTTPException(422, str(exc)) from exc
    except TenantRequiredError as exc:
        raise HTTPException(404, str(exc)) from exc
    except psycopg.Error as exc:
        raise HTTPException(409, "intake could not be persisted") from exc
    except (ArtifactStorageError, OSError) as exc:
        raise HTTPException(503, "artifact storage unavailable") from exc
    submission, job = result["submission"], result["job"]
    return {"tenant_uid": common.tenant_uid, "submission_id": submission["submission_id"],
            "job_id": job["job_id"], "source_type": source_type, "state": job["state"],
            "fidelity": fidelity, "policy": response_policy if response_policy is not None else policy,
            "artifacts": result["artifacts"],
            "derived_artifacts": result["derived_artifacts"]}


def create_app(db_config: DbConfig | None = None, artifact_store: ArtifactStore | None = None) -> FastAPI:
    """Build the tenant-scoped intake application.

    Args:
        db_config: Database configuration, or environment-derived defaults.
        artifact_store: Artifact store, or the default local store.

    Returns:
        A configured FastAPI application.
    """
    app = FastAPI(title="Phish Triage Intake API", version="0.1.0")
    app.state.db_config = db_config or DbConfig.from_env()
    app.state.artifact_store = artifact_store or ArtifactStore()

    @app.exception_handler(RequestValidationError)
    async def redacted_request_validation_error(
        _request: Request, _exc: RequestValidationError
    ) -> JSONResponse:
        """Return a generic validation error without echoing submitted values."""
        return JSONResponse(status_code=422, content={"detail": REQUEST_VALIDATION_DETAIL})

    @app.get("/health")
    def health(request: Request) -> dict[str, str]:
        """Report readiness when the database accepts a trivial query."""
        try:
            with connect(_cfg(request)) as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        except psycopg.Error as exc:
            raise HTTPException(503, "database unavailable") from exc
        return {"status": "ok"}

    @app.post("/v1/intake/url", status_code=202)
    def intake_url(payload: UrlIntake, request: Request) -> dict[str, Any]:
        """Persist URL evidence without fetching it or returning its value."""
        try:
            normalized = normalize_url(payload.url)
        except IntakeValidationError as exc:
            raise HTTPException(422, str(exc)) from exc
        original = payload.url.encode("utf-8")
        normalization = {"applied": normalized != payload.url,
                         "sha256": compute_sha256(normalized.encode("utf-8"))}
        return _accept(request, payload, source_type="raw_url", fidelity="full", notes=None,
                       envelope={"input": "raw_url"},
                       policy={"network_fetch": False, "scheme_allowed": True,
                               "normalized_url": normalized},
                       artifacts=[{"artifact_type": "url_text", "media_type": "text/plain; charset=utf-8",
                                   "data": original, "is_sensitive": True}],
                       indicators=[{"indicator_type": "url", "raw_value": normalized,
                                    "provenance": "parsed"}],
                       response_policy={"network_fetch": False, "scheme_allowed": True,
                                        "normalization": normalization})

    @app.post("/v1/intake/email/paste", status_code=202)
    def intake_email_paste(payload: EmailPasteIntake, request: Request) -> dict[str, Any]:
        """Persist pasted email evidence and optionally derive inert headers."""
        if payload.mode not in {"headers_body", "forwarded_body"}:
            raise HTTPException(422, "mode must be headers_body or forwarded_body")
        if not payload.body:
            raise HTTPException(422, "body must not be empty")
        if payload.mode == "headers_body" and not payload.raw_headers:
            raise HTTPException(422, "raw_headers are required for headers_body mode")
        canonical = ((payload.raw_headers or "") + "\r\n\r\n" + payload.body).encode("utf-8")
        if len(canonical) > 10 * 1024 * 1024:
            raise HTTPException(413, "pasted email exceeds 10485760 bytes")
        full = payload.mode == "headers_body"
        try:
            derived = derive_pasted_headers(canonical) if full else None
        except IntakeValidationError as exc:
            raise HTTPException(422, str(exc)) from exc
        return _accept(request, payload, source_type="email_artifact",
                       fidelity="full" if full else "low",
                       notes=None if full else "Forwarded body lacks complete original headers; conclusions are limited.",
                       envelope={"mode": payload.mode},
                       policy={"remote_content_execution": False, "full_headers": full},
                       artifacts=[{"artifact_type": "raw_headers" if full else "forwarded_body",
                                   "key": "email",
                                   "media_type": "text/plain; charset=utf-8", "data": canonical,
                                   "is_sensitive": True}], derived=derived)

    @app.post("/v1/intake/email/upload", status_code=202)
    async def intake_email_upload(request: Request, tenant_uid: Annotated[str, Form()],
                                  authorization_attested: Annotated[bool, Form()],
                                  no_credentials_acknowledged: Annotated[bool, Form()],
                                  file: Annotated[UploadFile, File()]) -> dict[str, Any]:
        """Persist an uploaded EML or MSG file without rendering active content."""
        try:
            data = await file.read(10 * 1024 * 1024 + 1)
        except OSError as exc:
            raise HTTPException(503, "uploaded file could not be read") from exc
        common = _attested_from_form(tenant_uid, authorization_attested,
                                     no_credentials_acknowledged)
        try:
            kind, artifacts, derived = prepare_email(data, file.filename or "", file.content_type or "")
        except IntakeValidationError as exc:
            raise HTTPException(413 if "exceeds" in str(exc) else 422, str(exc)) from exc
        return _accept(request, common, source_type="email_artifact", fidelity="full", notes=None,
                       envelope={"mode": "upload", "format": kind},
                       policy={"remote_content_execution": False, "parsed_headers": kind == "eml",
                               "msg_preserved_only": kind == "msg"}, artifacts=artifacts, derived=derived)

    @app.post("/v1/intake/ocr", status_code=202)
    def intake_ocr(payload: OcrIntake, request: Request) -> dict[str, Any]:
        """Persist OCR text and store its unverified extracted indicators."""
        try:
            data = validate_ocr(payload.ocr_text)
        except IntakeValidationError as exc:
            raise HTTPException(422, str(exc)) from exc
        metadata = {"platform": payload.platform, "engine": payload.engine,
                    "confidence": payload.confidence}
        return _accept(request, payload, source_type="ocr_text_message", fidelity="partial",
                       notes="OCR-derived indicators are unverified and preserve transcription uncertainty.",
                       envelope={"metadata": metadata},
                       policy={"network_fetch": False, "account_contact": False,
                               "indicator_provenance": "ocr_derived"},
                       artifacts=[{"artifact_type": "ocr_text", "media_type": "text/plain; charset=utf-8",
                                   "data": data, "is_sensitive": True}],
                       indicators=extract_ocr_indicators(payload.ocr_text))

    @app.post("/v1/intake/screenshot", status_code=202)
    async def intake_screenshot(request: Request, tenant_uid: Annotated[str, Form()],
                                authorization_attested: Annotated[bool, Form()],
                                no_credentials_acknowledged: Annotated[bool, Form()],
                                file: Annotated[UploadFile, File()],
                                ocr_text: Annotated[str | None, Form()] = None) -> dict[str, Any]:
        """Persist inert screenshot evidence and optional OCR text."""
        try:
            data = await file.read(15 * 1024 * 1024 + 1)
        except OSError as exc:
            raise HTTPException(503, "uploaded file could not be read") from exc
        common = _attested_from_form(tenant_uid, authorization_attested,
                                     no_credentials_acknowledged)
        try:
            kind, media = validate_screenshot(data, file.filename or "", file.content_type or "")
            ocr_data = validate_ocr(ocr_text) if ocr_text is not None else None
        except IntakeValidationError as exc:
            raise HTTPException(413 if "exceeds" in str(exc) else 422, str(exc)) from exc
        artifacts = [{"artifact_type": kind, "key": "screenshot", "media_type": media,
                      "original_filename": safe_filename(file.filename), "data": data,
                      "is_sensitive": True}]
        derived = None
        if ocr_data is not None:
            derived = [{"derived_kind": "ocr_output", "parent_key": "screenshot",
                        "media_type": "text/plain; charset=utf-8", "data": ocr_data}]
        return _accept(request, common, source_type="screenshot_evidence",
                       fidelity="partial" if ocr_data else "full", notes=None,
                       envelope={"has_ocr": ocr_data is not None},
                       policy={"active_content_rendered": False, "network_fetch": False},
                       artifacts=artifacts, derived=derived,
                       indicators=extract_ocr_indicators(ocr_text or ""))
    return app


app = create_app()


def run() -> None:
    """Run the development API server on the loopback interface."""
    import uvicorn
    uvicorn.run("pte.api:app", host="127.0.0.1", port=8000)

"""Shared pytest fixtures.

Each test run gets a fresh, isolated Postgres database (phish_triage_test)
with migrations applied once per session, then per-test tenant data is
cleaned between tests so cases stay independent.
"""

from __future__ import annotations

import os

import psycopg
import pytest

from pte.db import DbConfig, apply_migrations, connect, ensure_database


@pytest.fixture(scope="session")
def cfg() -> DbConfig:
    """Database config; honors PTE_* env vars with local defaults."""
    return DbConfig.from_env()


@pytest.fixture(scope="session")
def test_db(cfg: DbConfig) -> DbConfig:
    """Create a throwaway test database and apply the full migration set."""
    test_name = os.environ.get("PTE_TEST_DB_NAME", "phish_triage_test")
    # Drop leftovers from any previous failed run, then recreate clean.
    with connect(cfg, dbname="postgres") as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
                " WHERE datname = %s AND pid <> pg_backend_pid()",
                (test_name,),
            )
            cur.execute('DROP DATABASE IF EXISTS "%s"' % test_name.replace('"', ""))
            cur.execute('CREATE DATABASE "%s"' % test_name.replace('"', ""))
    test_cfg = DbConfig(
        host=cfg.host, port=cfg.port, dbname=test_name,
        user=cfg.user, password=cfg.password,
    )
    applied = apply_migrations(test_cfg)
    assert applied, "migrations must apply on a fresh test database"
    return test_cfg


@pytest.fixture()
def db(test_db: DbConfig):
    """Yield a connection after truncating all business tables (tenant-isolated tests)."""
    with connect(test_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                TRUNCATE submissions, submission_envelopes, jobs, input_artifacts,
                         derived_artifacts, indicators, scan_events, risk_scores,
                         reports, enrichment_observations, source_status, tenants,
                         audit_events CASCADE
                """
            )
        conn.commit()
    yield test_db


@pytest.fixture()
def tenant_a(db: DbConfig) -> str:
    from pte.services import ensure_tenant
    ensure_tenant(db, "cust_TEST_TENANT_A", "Test Tenant A")
    return "cust_TEST_TENANT_A"


@pytest.fixture()
def tenant_b(db: DbConfig) -> str:
    from pte.services import ensure_tenant
    ensure_tenant(db, "cust_TEST_TENANT_B", "Test Tenant B")
    return "cust_TEST_TENANT_B"

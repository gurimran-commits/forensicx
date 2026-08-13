"""Unit tests for Threat Intelligence provider isolation."""

from __future__ import annotations

from pathlib import Path

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.evidence.models import Evidence, EvidenceStatus
from forensicx.modules.ioc.models import Ioc
from forensicx.modules.threat_intelligence.models import ThreatSource
from forensicx.modules.threat_intelligence.repository import ThreatIntelRepository
from forensicx.modules.threat_intelligence.service import ThreatIntelService
from forensicx.platform.config import Settings
from forensicx.platform.database import configure_session_factory


class _SuccessfulProvider:
    def lookup(self, ioc: Ioc) -> dict:
        return {
            "verdict": "malicious",
            "score": 7,
            "details": {"matches": 7},
        }


class _FailingProvider:
    def lookup(self, ioc: Ioc) -> dict:
        raise RuntimeError("provider credential must not be persisted")


class _ProviderRegistry:
    def all(self):
        return (
            (ThreatSource.VIRUSTOTAL, _FailingProvider()),
            (ThreatSource.OTX, _SuccessfulProvider()),
        )


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_path=tmp_path / "forensicx.sqlite3",
        storage_path=tmp_path / "storage",
        max_upload_size=1024,
        allowed_extensions=(".txt",),
        jwt_secret="test",
        access_token_minutes=1,
        cors_origins=[],
        environment="test",
        log_level="WARNING",
        request_limit_per_minute=10,
    )


def test_enrich_ioc_continues_after_provider_lookup_failure(tmp_path: Path) -> None:
    """A failed provider is persisted without preventing later providers."""

    session = configure_session_factory(_settings(tmp_path))()
    try:
        case = CaseModel(
            case_number="CASE-2026-0001",
            title="Test",
            description="Test",
            priority="low",
            status="open",
            lead_investigator="tester",
        )
        session.add(case)
        session.flush()
        evidence = Evidence(
            case_id=case.id,
            original_filename="sample.txt",
            stored_filename="sample.txt",
            storage_path="/tmp/sample.txt",
            file_extension=".txt",
            mime_type="text/plain",
            magic_type=None,
            file_size=1,
            md5="0" * 32,
            sha1="0" * 40,
            sha256="1" * 64,
            uploaded_by="tester",
            status=EvidenceStatus.UPLOADED,
        )
        session.add(evidence)
        session.flush()
        ioc = Ioc(evidence_id=evidence.id, indicator_type="ipv4", value="203.0.113.42")
        session.add(ioc)
        session.flush()

        service = ThreatIntelService(session, _settings(tmp_path))
        service._registry = _ProviderRegistry()

        results = service.enrich_ioc(ioc.id)

        assert [(result.source, result.verdict) for result in results] == [
            (ThreatSource.VIRUSTOTAL, "error"),
            (ThreatSource.OTX, "malicious"),
        ]
        persisted = ThreatIntelRepository(session).list_by_ioc(ioc.id)
        assert {(result.source, result.verdict, result.score) for result in persisted} == {
            (ThreatSource.VIRUSTOTAL, "error", 0),
            (ThreatSource.OTX, "malicious", 7),
        }
        failed = next(result for result in persisted if result.source == ThreatSource.VIRUSTOTAL)
        assert failed.details == {"error": "Provider lookup failed"}
    finally:
        session.close()

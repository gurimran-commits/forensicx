"""Unit tests for the forensic plugin boundary."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from forensicx.modules.forensic_engine.analyzers.base import BaseAnalyzer
from forensicx.modules.forensic_engine.analyzers.magic import MagicAnalyzer
from forensicx.modules.forensic_engine.domain import AnalysisStatus, AnalyzerOutput
from forensicx.modules.forensic_engine.registry import AnalyzerRegistry
from forensicx.modules.forensic_engine.service import ForensicAnalysisService

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.chain_of_custody.models import ChainOfCustody


def test_registry_discovers_builtin_analyzers() -> None:
    """Built-ins are discovered without a hand-maintained registry list."""
    names = {analyzer.name for analyzer in AnalyzerRegistry().discover()}
    assert {"archives", "images", "magic", "metadata", "pe"} <= names


def test_magic_analyzer_identifies_extension_mismatch(tmp_path: Path) -> None:
    """Signature inspection flags a file whose suffix conflicts with its bytes."""
    path = tmp_path / "suspect.exe"
    path.write_bytes(b"%PDF-1.7\n")
    result = MagicAnalyzer().analyze(path)
    assert result.status is AnalysisStatus.SUCCESS
    assert result.findings["detected_type"] == "pdf"
    assert result.findings["extension_matches"] is False


class _ExplodingAnalyzer(BaseAnalyzer):
    name = "exploding"

    def analyze(self, evidence_path: Path) -> AnalyzerOutput:
        raise RuntimeError("test isolation")


class _WorkingAnalyzer(BaseAnalyzer):
    name = "working"

    def analyze(self, evidence_path: Path) -> AnalyzerOutput:
        return AnalyzerOutput(self.name, self.version, AnalysisStatus.SUCCESS, {"inspected": evidence_path.name})

class _FakeIocService:
    def extract(self, _evidence_id: str) -> list:
        return []

def test_service_isolates_analyzer_failure(tmp_path: Path) -> None:
    """A failed plugin produces one failed record while subsequent plugins run."""
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"data")
    evidence = SimpleNamespace(id="evidence-1", storage_path=str(path))
    evidence_repository = SimpleNamespace(get_by_id=lambda _id: evidence)
    captured: list[object] = []
    result_repository = SimpleNamespace(add_all=lambda records: (captured.extend(records), records)[1])
    registry = SimpleNamespace(discover=lambda: [_ExplodingAnalyzer(), _WorkingAnalyzer()])
    results = ForensicAnalysisService(evidence_repository, result_repository, registry, tmp_path,_FakeIocService(),).analyze("evidence-1", "tester")
    assert [result.status for result in results] == [AnalysisStatus.FAILED, AnalysisStatus.SUCCESS]
    assert len(captured) == 2

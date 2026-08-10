"""Application service that executes forensic plugins safely."""
from __future__ import annotations

import logging
from pathlib import Path

from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.forensic_engine.domain import AnalysisStatus, AnalyzerOutput
from forensicx.modules.forensic_engine.models import ForensicAnalysisResult
from forensicx.modules.forensic_engine.registry import AnalyzerRegistry
from forensicx.modules.forensic_engine.repository import ForensicAnalysisRepository
from forensicx.platform.errors import ForensicXError

from forensicx.modules.ioc.service import IocExtractionService

LOGGER = logging.getLogger(__name__)


class ForensicAnalysisService:
    """Run independently-failing analyzers against immutable stored evidence."""
    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        repository: ForensicAnalysisRepository,
        registry: AnalyzerRegistry,
        storage_root: Path,
        ioc_service: IocExtractionService,
    ) -> None:
        self._evidence_repository, self._repository, self._registry = evidence_repository, repository, registry
        self._storage_root = storage_root.resolve()
        self._ioc_service = ioc_service

    def analyze(self, evidence_id: str, analyzed_by: str) -> list[ForensicAnalysisResult]:
        """Run all discovered analyzers, recording failure instead of aborting the run."""
        evidence = self._evidence_repository.get_by_id(evidence_id)
        if evidence is None:
            raise ForensicXError("Evidence not found", 404)
        path = Path(evidence.storage_path).resolve()
        if not path.is_file() or self._storage_root not in path.parents:
            raise ForensicXError("Evidence file is unavailable", 404)
        outputs: list[AnalyzerOutput] = []
        for analyzer in self._registry.discover():
            try:
                outputs.append(analyzer.analyze(path))
            except Exception as exc:  # isolation is deliberate at a plugin boundary
                LOGGER.exception("Forensic analyzer %s failed for evidence %s", analyzer.name, evidence_id)
                outputs.append(AnalyzerOutput(analyzer.name, analyzer.version, AnalysisStatus.FAILED, {}, "Analyzer execution failed"))
        records = [ForensicAnalysisResult(evidence_id=evidence.id, analyzer_name=output.analyzer_name, analyzer_version=output.analyzer_version, status=output.status, findings=output.findings, error_message=output.error_message, analyzed_by=analyzed_by) for output in outputs]
        persisted = self._repository.add_all(records)
        self._ioc_service.extract(evidence.id)
        return persisted

    def history(self, evidence_id: str, *, offset: int, limit: int) -> list[ForensicAnalysisResult]:
        """Return persisted results after confirming evidence exists."""
        if self._evidence_repository.get_by_id(evidence_id) is None:
            raise ForensicXError("Evidence not found", 404)
        return self._repository.list_for_evidence(evidence_id, offset=offset, limit=limit)

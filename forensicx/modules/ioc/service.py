"""IOC extraction from safely resolved stored evidence."""

from __future__ import annotations

from pathlib import Path

from forensicx.modules.evidence.repository import EvidenceRepository
from forensicx.modules.ioc.extractors import extract_iocs
from forensicx.modules.ioc.models import Ioc
from forensicx.modules.ioc.repository import IocRepository
from forensicx.platform.errors import ForensicXError


class IocExtractionService:
    """Extract and persist supported indicators without modifying evidence."""

    def __init__(self, evidence_repository: EvidenceRepository, repository: IocRepository, storage_root: Path) -> None:
        self._evidence_repository = evidence_repository
        self._repository = repository
        self._storage_root = storage_root.resolve()

    def extract(self, evidence_id: str) -> list[Ioc]:
        """Read one stored evidence file and store newly discovered indicators."""
        evidence = self._evidence_repository.get_by_id(evidence_id)
        if evidence is None:
            raise ForensicXError("Evidence not found", 404)
        path = Path(evidence.storage_path).resolve()
        if not path.is_file() or self._storage_root not in path.parents:
            raise ForensicXError("Evidence file is unavailable", 404)
        text = path.read_bytes().decode("utf-8", errors="ignore")
        return self._repository.add_new(evidence.id, extract_iocs(text))

    def list(self, evidence_id: str, *, offset: int, limit: int) -> list[Ioc]:
        """List extracted indicators after confirming the evidence remains active."""
        if self._evidence_repository.get_by_id(evidence_id) is None:
            raise ForensicXError("Evidence not found", 404)
        return self._repository.list_for_evidence(evidence_id, offset=offset, limit=limit)

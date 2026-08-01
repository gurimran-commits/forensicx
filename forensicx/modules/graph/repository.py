"""
Repository for building investigation graphs.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.evidence.models import Evidence
from forensicx.modules.ioc.models import Ioc
from forensicx.modules.correlation.models import Correlation


class GraphRepository:

    def __init__(self, session: Session):
        self._session = session

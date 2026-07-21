"""
Import all ORM models so SQLAlchemy registers them before metadata creation.
"""

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.evidence.models import Evidence

# Future modules
from forensicx.modules.chain_of_custody.models import ChainOfCustody
from forensicx.modules.forensic_engine.models import ForensicAnalysisResult
from forensicx.modules.ioc.models import Ioc

__all__ = [
    "CaseModel",
    "Evidence",
    "ChainOfCustody",
    "ForensicAnalysisResult",
]

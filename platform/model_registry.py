"""
Import all ORM models so SQLAlchemy registers them before metadata creation.
"""

from forensicx.modules.cases.models import CaseModel
from forensicx.modules.evidence.models import Evidence

# Future modules
from forensicx.modules.chain_of_custody.models import ChainOfCustody

__all__ = [
    "CaseModel",
    "Evidence",
    "ChainOfCustody",
]

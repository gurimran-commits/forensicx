"""Persistence adapter for dashboard snapshots."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from forensicx.modules.dashboard.domain import DashboardSnapshot
from forensicx.modules.dashboard.models import DashboardSnapshotModel


LOGGER = logging.getLogger(__name__)


class DashboardRepository:
    """Repository for loading and saving dashboard snapshots."""

    def __init__(self, session: Session) -> None:
        """Create a repository backed by a SQLAlchemy session."""
        self._session = session

    def get_snapshot(self) -> DashboardSnapshot:
        """Return the current dashboard snapshot, seeding it when empty."""
        row = self._session.get(DashboardSnapshotModel, 1)
        if row is None:
            snapshot = self._default_snapshot()
            row = DashboardSnapshotModel(
                id=1,
                generated_at=snapshot.generated_at,
                payload_json=json.dumps(snapshot.payload, separators=(",", ":")),
            )
            self._session.add(row)
            self._session.flush()
            LOGGER.info("Seeded dashboard snapshot")
            return snapshot
        return DashboardSnapshot(generated_at=row.generated_at, payload=json.loads(row.payload_json))

    def _default_snapshot(self) -> DashboardSnapshot:
        """Build a production-shaped seed snapshot for local startup."""
        generated_at = datetime.now(UTC).isoformat()
        payload: dict[str, Any] = {
            "date_range": "May 27, 2025 - Jun 2, 2025",
            "kpis": [
                {"key": "active_cases", "label": "Active Cases", "value": "12", "delta": "4 high priority", "severity": "critical", "icon": "case", "points": [36, 30, 16, 24, 19, 22, 10, 17, 28, 20, 21, 9, 23, 24, 30, 14, 25, 15, 12]},
                {"key": "evidence_items", "label": "Evidence Items", "value": "2,547", "delta": "+156 this week", "severity": "success", "icon": "database", "points": [33, 28, 18, 29, 31, 27, 30, 20, 22, 12, 10, 19, 20, 27, 24, 14, 8, 20, 16]},
                {"key": "analyzed_files", "label": "Analyzed Files", "value": "8,912", "delta": "+23.5% this week", "severity": "success", "icon": "file", "points": [32, 28, 34, 31, 34, 26, 12, 20, 27, 25, 12, 6, 11, 10, 15, 13, 6, 7, 2]},
                {"key": "ioc_matches", "label": "IOC Matches", "value": "142", "delta": "+12 this week", "severity": "warning", "icon": "target", "points": [36, 30, 18, 21, 25, 18, 12, 9, 18, 20, 17, 23, 13, 8, 11, 22, 17, 8, 6]},
                {"key": "threat_detections", "label": "Threat Detections", "value": "27", "delta": "+5 this week", "severity": "critical", "icon": "alert", "points": [32, 34, 28, 36, 32, 26, 28, 21, 19, 9, 17, 16, 20, 25, 7, 20, 14, 8, 5]},
            ],
            "evidence": [
                {"label": "Documents", "count": 906, "percentage": 35.6, "color": "#7452ff"},
                {"label": "Images", "count": 732, "percentage": 28.7, "color": "#3e82ff"},
                {"label": "Videos", "count": 390, "percentage": 15.3, "color": "#30df78"},
                {"label": "Archives", "count": 260, "percentage": 10.2, "color": "#ffac32"},
                {"label": "Executables", "count": 171, "percentage": 6.7, "color": "#ff6540"},
                {"label": "Others", "count": 88, "percentage": 3.5, "color": "#c7557b"},
            ],
            "timeline": [
                {"label": "27 May", "events": 132},
                {"label": "28 May", "events": 146},
                {"label": "29 May", "events": 156},
                {"label": "30 May", "events": 168},
                {"label": "31 May", "events": 173},
                {"label": "1 Jun", "events": 202},
                {"label": "2 Jun", "events": 152},
            ],
            "timeline_metrics": [
                {"label": "Events", "value": 1327},
                {"label": "File Events", "value": 642},
                {"label": "User Events", "value": 327},
                {"label": "System Events", "value": 358},
            ],
            "ioc_matches": [
                {"indicator": "192.168.1.105", "indicator_type": "IP Address", "matches": 23},
                {"indicator": "malicious-domain.com", "indicator_type": "Domain", "matches": 18},
                {"indicator": "45.76.12.10", "indicator_type": "IP Address", "matches": 12},
                {"indicator": "badfile.exe", "indicator_type": "File Hash", "matches": 9},
                {"indicator": "phishing-site.net", "indicator_type": "Domain", "matches": 7},
            ],
            "recent_cases": [
                {"title": "Corporate Data Breach", "case_number": "CASE-2025-0012", "priority": "High", "age": "2h ago", "color": "#744cff"},
                {"title": "Insider Threat Investigation", "case_number": "CASE-2025-0011", "priority": "Medium", "age": "5h ago", "color": "#367cff"},
                {"title": "Phishing Attack Analysis", "case_number": "CASE-2025-0010", "priority": "Medium", "age": "1d ago", "color": "#24b86b"},
                {"title": "Malware Infection Case", "case_number": "CASE-2025-0009", "priority": "High", "age": "2d ago", "color": "#e64f56"},
                {"title": "Unauthorized Access", "case_number": "CASE-2025-0008", "priority": "Low", "age": "3d ago", "color": "#65a34c"},
            ],
            "attack_points": [
                {"region": "North America", "x": 16, "y": 35, "severity": "high"},
                {"region": "Europe", "x": 48, "y": 27, "severity": "critical"},
                {"region": "South Asia", "x": 66, "y": 43, "severity": "high"},
                {"region": "East Asia", "x": 80, "y": 34, "severity": "critical"},
                {"region": "South America", "x": 31, "y": 68, "severity": "medium"},
                {"region": "Australia", "x": 87, "y": 79, "severity": "high"},
            ],
            "system_statuses": [
                {"component": "Database", "status": "Operational", "detail": None, "healthy": True},
                {"component": "Storage", "status": "72% Used", "detail": "72", "healthy": True},
                {"component": "AI Engine", "status": "Operational", "detail": None, "healthy": True},
                {"component": "YARA Engine", "status": "Operational", "detail": None, "healthy": True},
                {"component": "Threat Intel Feeds", "status": "Operational", "detail": None, "healthy": True},
                {"component": "Background Tasks", "status": "All Running", "detail": None, "healthy": True},
            ],
            "system_uptime": "15d 7h 42m",
            "alerts": [
                {"message": "Malware detected in evidence.zip", "severity": "critical", "age": "2m ago"},
                {"message": "Suspicious PowerShell execution", "severity": "warning", "age": "15m ago"},
                {"message": "IOC match: malicious-domain.com", "severity": "critical", "age": "28m ago"},
                {"message": "Brute force login attempt detected", "severity": "warning", "age": "1h ago"},
                {"message": "Unusual data transfer detected", "severity": "critical", "age": "2h ago"},
            ],
        }
        return DashboardSnapshot(generated_at=generated_at, payload=payload)

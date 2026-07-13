"""Pydantic DTOs for dashboard API responses."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SparklinePoint(BaseModel):
    """Single sparkline data point."""

    value: int = Field(ge=0)


class KpiCard(BaseModel):
    """Dashboard KPI card."""

    key: str
    label: str
    value: str
    delta: str
    severity: str
    icon: str
    points: list[int]


class EvidenceCategory(BaseModel):
    """Evidence type summary."""

    label: str
    count: int = Field(ge=0)
    percentage: float = Field(ge=0, le=100)
    color: str


class TimelineBucket(BaseModel):
    """Timeline event bucket."""

    label: str
    events: int = Field(ge=0)


class TimelineMetric(BaseModel):
    """Timeline aggregate metric."""

    label: str
    value: int = Field(ge=0)


class IocMatch(BaseModel):
    """IOC match table row."""

    indicator: str
    indicator_type: str
    matches: int = Field(ge=0)


class RecentCase(BaseModel):
    """Recent case row."""

    title: str
    case_number: str
    priority: str
    age: str
    color: str


class AttackPoint(BaseModel):
    """Threat map point."""

    region: str
    x: float = Field(ge=0, le=100)
    y: float = Field(ge=0, le=100)
    severity: str


class SystemStatus(BaseModel):
    """System dependency status row."""

    component: str
    status: str
    detail: str | None = None
    healthy: bool


class AlertItem(BaseModel):
    """Recent alert row."""

    message: str
    severity: str
    age: str


class DashboardOverview(BaseModel):
    """Complete dashboard overview DTO."""

    generated_at: str
    date_range: str
    kpis: list[KpiCard]
    evidence: list[EvidenceCategory]
    timeline: list[TimelineBucket]
    timeline_metrics: list[TimelineMetric]
    ioc_matches: list[IocMatch]
    recent_cases: list[RecentCase]
    attack_points: list[AttackPoint]
    system_statuses: list[SystemStatus]
    system_uptime: str
    alerts: list[AlertItem]

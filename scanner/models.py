from dataclasses import dataclass
from typing import Optional, Set, Literal

Criticality = Literal["Critical", "High", "Medium", "Low"]

RiskType = Literal[
    "CVE",
    "SIGNATURE",
    "UNUSED_DEPENDENCY",
    "UNDECLARED_IMPORT",
]


@dataclass(frozen=True)
class Finding:
    # обязательные поля
    name: str
    version: str
    risk_type: RiskType
    description: str
    recommendation: str

    # дополнительные поля (необязательные)
    criticality: Optional[Criticality] = None
    reason: Optional[str] = None

    # только для сигнатурных находок (пакет/файл/строка)
    package: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None


@dataclass(frozen=True)
class ASTAnalysisResult:
    used_dependencies: Set[str]
    unused_declared_dependencies: Set[str]
    undeclared_imports: Set[str]

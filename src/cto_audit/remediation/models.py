"""
Modelli Pydantic per Remediation Knowledge Base e pipeline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    pass


class EffortRange(BaseModel):
    """Stima effort per una remediation."""
    min_hours: int = Field(..., ge=1, description="Ore minime stimate")
    max_hours: int = Field(..., ge=1, description="Ore massime stimate")
    t_shirt: str = Field(..., pattern=r"^(XS|S|M|L|XL)$", description="T-shirt sizing")

    @property
    def avg_hours(self) -> float:
        return (self.min_hours + self.max_hours) / 2.0


class StackSpecificRemediation(BaseModel):
    """Override remediation steps per un stack specifico."""
    remediation_steps: list[str] = Field(..., min_length=1)


class RemediationEntry(BaseModel):
    """Singola entry nella Knowledge Base di remediation."""
    rule_id: str = Field(..., description="ID della regola (es. INFRA-CICD-001)")
    risk_business: str = Field(..., min_length=10, description="Descrizione rischio business non-tecnica")
    remediation_steps: list[str] = Field(..., min_length=1, description="Step generici di remediation")
    effort_range: EffortRange = Field(..., description="Stima effort")
    priority_tier: int = Field(default=2, ge=1, le=3, description="1=subito, 2=presto, 3=pianificare")
    stack_specific: dict[str, StackSpecificRemediation] = Field(
        default_factory=dict, description="Override per stack"
    )
    references: list[str] = Field(default_factory=list, description="Riferimenti normativi")

    def get_steps_for_stack(self, stack: str | None) -> list[str]:
        """Restituisce gli step per lo stack specifico, o quelli generici."""
        if stack and stack in self.stack_specific:
            return self.stack_specific[stack].remediation_steps
        return self.remediation_steps


class WhatIfResult(BaseModel):
    """Risultato di una simulazione what-if per una singola regola."""
    rule_id: str
    current_score: float
    projected_score: float
    delta: float
    effort: EffortRange | None = None
    impact_effort_ratio: float = 0.0


class RemediationPipelineResult(BaseModel):
    """Risultato completo della pipeline di remediation."""
    context: Any = None  # ProjectContext, Any per evitare circular import
    whatif_results: list[WhatIfResult] = Field(default_factory=list)
    executive_summary: str | None = None
    risk_narrative: str | None = None
    llm_used: bool = False

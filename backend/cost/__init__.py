"""ThreatGuard Cost Intelligence & AWS Cost Optimization Package.

Provides decoupled modules for:
- Configurable regional AWS pricing dataset loading (`pricing.py`)
- Guarded Moto / AWS resource inventory collection (`inventory.py`)
- Assumption-transparent monthly/annual cost estimation (`estimator.py`)
- Evidence-based cost optimization findings & recommendations (`optimizer.py`)
- Human-in-the-loop remediation & verification integration (`remediation.py`)
- Text-based Cost Optimization Report generation & history (`reports.py`)
- REST API registration (`api.py`)
"""

from backend.cost.pricing import PricingCatalog, load_pricing_catalog
from backend.cost.inventory import collect_resource_inventory
from backend.cost.estimator import estimate_infrastructure_costs
from backend.cost.optimizer import analyze_cost_optimizations
from backend.cost.reports import generate_cost_report
from backend.cost.api import register_cost_api

__all__ = [
    "PricingCatalog",
    "load_pricing_catalog",
    "collect_resource_inventory",
    "estimate_infrastructure_costs",
    "analyze_cost_optimizations",
    "generate_cost_report",
    "register_cost_api",
]

"""Configurable AWS Pricing Dataset Loader & Lookup Engine.

Keeps pricing metadata, regional unit rates, effective dates, and estimation
assumptions cleanly separated from resource inventory and estimation logic.
"""
from dataclasses import dataclass, field
import json
import os
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_PRICING_PATH = os.path.join(os.path.dirname(__file__), "pricing_dataset.json")


@dataclass(frozen=True)
class PricingEntry:
    """Single regional unit-pricing rule for an AWS service and resource type."""

    service: str
    resource_type: str
    region: str
    pricing_unit: str
    unit_price: float
    currency: str
    pricing_source: str
    effective_date: str
    assumptions: str
    downsize_target: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "resource_type": self.resource_type,
            "region": self.region,
            "pricing_unit": self.pricing_unit,
            "unit_price": self.unit_price,
            "currency": self.currency,
            "pricing_source": self.pricing_source,
            "effective_date": self.effective_date,
            "assumptions": self.assumptions,
            "downsize_target": self.downsize_target,
        }


@dataclass
class PricingCatalog:
    """In-memory indexed pricing catalog loaded from configurable JSON/dict."""

    dataset_version: str
    effective_date: str
    currency: str
    pricing_source: str
    default_assumptions: Dict[str, Any] = field(default_factory=dict)
    entries: List[PricingEntry] = field(default_factory=list)
    _index: Dict[Tuple[str, str, str], PricingEntry] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        self._index = {}
        for entry in self.entries:
            key = (entry.service.lower(), entry.resource_type, entry.region.lower())
            self._index[key] = entry
            # Also store lowercased resource_type lookup for case-insensitive fallback
            key_lower = (entry.service.lower(), entry.resource_type.lower(), entry.region.lower())
            self._index.setdefault(key_lower, entry)

    def lookup(
        self,
        service: str,
        resource_type: Optional[str],
        region: Optional[str] = "us-east-1",
    ) -> Optional[PricingEntry]:
        """Look up exact regional pricing entry. Returns None if missing."""
        if not service or not resource_type:
            return None
        svc = service.strip().lower()
        rtype = str(resource_type).strip()
        reg = (region or "us-east-1").strip().lower()

        entry = self._index.get((svc, rtype, reg))
        if entry is not None:
            return entry
        entry = self._index.get((svc, rtype.lower(), reg))
        if entry is not None:
            return entry
        # Global service fallback (e.g. IAM)
        if svc == "iam":
            return self._index.get((svc, rtype.lower(), "global"))
        return None

    def list_regions(self) -> List[str]:
        return sorted({e.region for e in self.entries if e.region != "global"})

    def list_services(self) -> List[str]:
        return sorted({e.service for e in self.entries})

    def to_metadata_dict(self) -> Dict[str, Any]:
        return {
            "dataset_version": self.dataset_version,
            "effective_date": self.effective_date,
            "currency": self.currency,
            "pricing_source": self.pricing_source,
            "default_assumptions": dict(self.default_assumptions),
            "entry_count": len(self.entries),
            "supported_regions": self.list_regions(),
            "supported_services": self.list_services(),
        }

    def to_dict(self) -> Dict[str, Any]:
        meta = self.to_metadata_dict()
        meta["entries"] = [e.to_dict() for e in self.entries]
        return meta


def load_pricing_catalog(
    pricing_path: Optional[str] = None,
    override_data: Optional[Dict[str, Any]] = None,
) -> PricingCatalog:
    """Load configurable pricing dataset from a dictionary or JSON file."""
    if override_data is not None:
        raw = override_data
    else:
        target_path = pricing_path or os.getenv("CG_PRICING_DATASET_PATH") or DEFAULT_PRICING_PATH
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Pricing dataset file not found: {target_path}")
        with open(target_path, "r", encoding="utf-8") as fp:
            raw = json.load(fp)

    entries: List[PricingEntry] = []
    for item in raw.get("entries", []):
        if not isinstance(item, dict):
            continue
        entries.append(
            PricingEntry(
                service=str(item["service"]).lower(),
                resource_type=str(item["resource_type"]),
                region=str(item.get("region", "us-east-1")).lower(),
                pricing_unit=str(item.get("pricing_unit", "unit")),
                unit_price=float(item["unit_price"]),
                currency=str(item.get("currency", raw.get("currency", "USD"))),
                pricing_source=str(item.get("pricing_source", raw.get("pricing_source", "Configured Dataset"))),
                effective_date=str(item.get("effective_date", raw.get("effective_date", "unknown"))),
                assumptions=str(item.get("assumptions", "")),
                downsize_target=item.get("downsize_target"),
            )
        )

    return PricingCatalog(
        dataset_version=str(raw.get("dataset_version", "custom-v1")),
        effective_date=str(raw.get("effective_date", "unknown")),
        currency=str(raw.get("currency", "USD")),
        pricing_source=str(raw.get("pricing_source", "Configured Dataset")),
        default_assumptions=dict(raw.get("default_assumptions", {})),
        entries=entries,
    )

"""Normalized indicator record for ingested IOCs, plus its dedup key.

The `{indicator, type}` vocabulary mirrors the enrichment layer's, but is kept as a
small local copy rather than imported across the component boundary — ingestion and
enrichment-mcp are deliberately independent, exactly as the harness and enrichment-mcp
already are.
"""

from __future__ import annotations

from dataclasses import dataclass

# Indicator types this pipeline normalizes to. `file_hash` covers MD5/SHA-1/SHA-256.
INDICATOR_TYPES = ("url", "ip_address", "domain", "file_hash")


@dataclass(frozen=True)
class Indicator:
    """One normalized indicator with its provenance.

    Frozen so it can key a dict/set; `tags` is a tuple for the same reason.
    """

    indicator: str
    type: str
    source: str
    source_ref: str = ""
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.type not in INDICATOR_TYPES:
            raise ValueError(
                f"unknown indicator type {self.type!r}; "
                f"expected one of {', '.join(INDICATOR_TYPES)}"
            )
        if not self.indicator.strip():
            raise ValueError("indicator must be a non-empty string")

    @property
    def key(self) -> tuple[str, str]:
        """Dedup key: two records with the same (type, indicator) are the same IOC."""
        return (self.type, self.indicator)

    def merged_with(self, other: Indicator) -> Indicator:
        """Same-key merge: union tags, keep this record's source/source_ref (first seen).

        v1 provenance policy: the first source to surface an indicator owns its
        `source`/`source_ref`; later sources contribute only their tags. Richer
        multi-source provenance can come later without changing the store format.
        """
        tags = tuple(dict.fromkeys((*self.tags, *other.tags)))  # order-preserving union
        return Indicator(self.indicator, self.type, self.source, self.source_ref, tags)

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "type": self.type,
            "source": self.source,
            "source_ref": self.source_ref,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, d: dict) -> Indicator:
        try:
            return cls(
                indicator=str(d["indicator"]),
                type=str(d["type"]),
                source=str(d.get("source", "")),
                source_ref=str(d.get("source_ref", "")),
                tags=tuple(d.get("tags", ())),
            )
        except KeyError as e:
            raise ValueError(f"indicator record missing required field {e}") from e

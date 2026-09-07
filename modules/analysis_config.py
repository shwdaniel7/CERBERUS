from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class AnalysisConfig:
    blacklist: bool = False
    virustotal: bool = False
    strings: bool = False
    ioc_extract: bool = False
    entropy: bool = False
    magic_numbers: bool = False
    pe_analysis: bool = False
    gerar_report: bool = False
    report_format: str = "all"
    output_dir: str = "reports"
    quiet: bool = False
    workers: int = 1
    cache_enabled: bool = True
    max_file_size: int | None = None
    virustotal_suspicious_only: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, values: dict[str, Any]):
        known = {field for field in cls.__dataclass_fields__}
        return cls(**{key: value for key, value in values.items() if key in known})

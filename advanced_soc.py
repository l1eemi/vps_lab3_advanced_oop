import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Iterator, Callable
import functools

# 1. Декоратор audit_logger
def audit_logger(func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception:
            return None

    return wrapper

# 2. IPUtils
class IPUtils:
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True

    @staticmethod
    def is_private(ip: str) -> bool:
        if not IPUtils.is_valid_ip(ip):
            return False
        parts = [int(p) for p in ip.split(".")]
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False

    @staticmethod
    def mask_ip(ip: str) -> str:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
        return ip

# 3. SecurityEvent
class SecurityEvent:
    def __init__(self, timestamp: str, source_ip: str, event_type: str, severity: Any = 1) -> None:
        self.severity = severity
        self.timestamp: str = timestamp
        self.source_ip: str = source_ip
        self.event_type: str = event_type

    @property
    def severity(self) -> int:
        return self._severity

    @severity.setter
    def severity(self, value: Any) -> None:
        if type(value) is not int:
            raise ValueError("Severity must be an integer")
        if value < 1 or value > 5:
            raise ValueError("Severity must be between 1 and 5")
        self._severity = value

    @property
    def is_critical(self) -> bool:
        return self.severity >= 4

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        return cls(
            timestamp=data["timestamp"],
            source_ip=data.get("source_ip", data.get("ip", "")),
            event_type=data["event_type"],
            severity=data.get("severity", 1)
        )

    @classmethod
    def from_syslog(cls, raw: str) -> "SecurityEvent":
        # Извлекаем IP
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
        source_ip = ip_match.group(0) if ip_match else "0.0.0.0"

        # Извлекаем timestamp
        ts_match = re.search(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", raw)
        if not ts_match:
            ts_match = re.search(r"[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}", raw)
        timestamp = ts_match.group(0) if ts_match else "2026-01-01 00:00:00"

        raw_upper = raw.upper()

        # Тип события
        if "SSH" in raw_upper:
            event_type = "SSH"
        elif "HTTP" in raw_upper:
            event_type = "HTTP"
        else:
            event_type = "UNKNOWN"

        # Определяем severity:
        # Проверяем ключевые слова для критичности (5)
        is_crit = any(kw in raw_upper for kw in [
            "CRIT", "CRITICAL", "EMERG", "ALERT", "FATAL", "HIGH",
            "SEVERITY=5", "LEVEL=5", "CRIT_EVENT"
        ])

        # Проверяем syslog приоритет в кавычках/скобках типа <11> или <2>
        prio_match = re.search(r"<(\d+)>", raw)
        if prio_match:
            prio = int(prio_match.group(1)) % 8
            if prio in (0, 1, 2):  # Emergency, Alert, Critical
                is_crit = True

        if is_crit or ("CRIT" in raw_upper) or (
                event_type == "UNKNOWN" and "INFO" not in raw_upper and "DEBUG" not in raw_upper):
            severity = 5
        elif any(kw in raw_upper for kw in ["ERROR", "ERR", "FAIL", "FAILED", "WARN", "WARNING", "SSH", "HTTP"]):
            severity = 3
        else:
            severity = 1

        return cls(timestamp=timestamp, source_ip=source_ip, event_type=event_type, severity=severity)

    def __repr__(self) -> str:
        return (
            f"SecurityEvent(timestamp='{self.timestamp}', source_ip='{self.source_ip}', "
            f"event_type='{self.event_type}', severity={self.severity})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecurityEvent):
            return NotImplemented
        return (
                self.timestamp == other.timestamp
                and self.source_ip == other.source_ip
                and self.event_type == other.event_type
                and self.severity == other.severity
        )

# 4. BaseAnalyzer
class BaseAnalyzer(ABC):
    def __init__(self, name: str) -> None:
        self.name: str = name

    @abstractmethod
    def process_event(self, event: SecurityEvent) -> bool:
        pass

# 5. BruteForceAnalyzer
class BruteForceAnalyzer(BaseAnalyzer):
    def __init__(self, threshold: int = 3) -> None:
        super().__init__("BruteForceAnalyzer")
        self.threshold: int = threshold
        self._failed_attempts: Dict[str, int] = {}

    def process_event(self, event: SecurityEvent) -> bool:
        if "FAIL" in event.event_type.upper() or "FAILED" in event.event_type.upper():
            self._failed_attempts[event.source_ip] = self._failed_attempts.get(event.source_ip, 0) + 1
            if self._failed_attempts[event.source_ip] >= self.threshold:
                return True
        return False

# 6. BlacklistManager
class BlacklistManager:
    def __init__(self, initial_ips: Optional[List[str]] = None) -> None:
        self._blacklist: set[str] = set(initial_ips) if initial_ips else set()

    def add_ip(self, ip: str) -> None:
        self._blacklist.add(ip)

    def remove_ip(self, ip: str) -> None:
        self._blacklist.discard(ip)

    def __contains__(self, ip: object) -> bool:
        return ip in self._blacklist

    def __len__(self) -> int:
        return len(self._blacklist)

    def __iter__(self) -> Iterator[str]:
        return iter(self._blacklist)

    def __repr__(self) -> str:
        return f"BlacklistManager(count={len(self._blacklist)})"

# 7. SOCEngine
class SOCEngine:
    def __init__(self) -> None:
        self.analyzers: List[BaseAnalyzer] = []
        self.blacklist: BlacklistManager = BlacklistManager()
        self.alerts: List[Dict[str, Any]] = []

    def register_analyzer(self, analyzer: BaseAnalyzer) -> None:
        self.analyzers.append(analyzer)

    def process(self, event: SecurityEvent) -> None:
        if event.source_ip in self.blacklist:
            self.alerts.append({
                "event": event,
                "reason": "IP in blacklist",
                "analyzer": "BlacklistManager"
            })

        for analyzer in self.analyzers:
            if analyzer.process_event(event):
                self.blacklist.add_ip(event.source_ip)
                self.alerts.append({
                    "event": event,
                    "reason": f"Triggered by {analyzer.name}",
                    "analyzer": analyzer.name
                })
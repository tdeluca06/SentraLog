from dataclasses import dataclass
from typing import Protocol, ClassVar

from util.schema import Schema, DetectionResult


KEYWORDS: tuple = (
    "SELECT",
    "FROM",
    "WHERE",
    "GROUP BY",
    "HAVING",
    "ORDER BY",
    "UPDATE",
    "TABLE",
    "JOIN",
    "UNION"
)

SCAN_PATTERNS: tuple = (
    "Nmap",
    "dirb"
)

LOGIN_REQUESTS: tuple = (
    "POST",
)

@dataclass()
class Detector(Protocol):
    """
    Detector interface (Protocol) for NGINX access log threat detection.

    Implementations must provide a class-level name and detect method
    which accepts a dictionary with remote_addr as key and a list of
    Schemas (processed logs) as value.
    """
    name: ClassVar[str]

    def detect(self, logs: dict[str, list[Schema]]) -> DetectionResult:
        """
        Function to scan grouped logs and return detection results.
        :param logs: grouped logs to parse
        :return: a new DetectionResult with attempt details
        """
        ...


@dataclass()
class BruteForceDetector:
    """
    Detects brute force attempts in NGINX access logs by counting the number
    of failed login attempts per user, and creates a new DetectionResult with
    the details. If the amount of failed logins are greater than a given threshold,
    which defaults to 5, a brute force attempt is detected.
    """
    name: str = "brute_force"

    def detect(self, logs: dict[str, list[Schema]], *, threshold=5) -> DetectionResult:
        """
        Function to parse a given dict of grouped logs (remote_addr -> logs) in order
        to detect brute force attempts. Tracks login attempts per user in a dict and
        detects an attempt if there are more than the given threshold (default 5) POST
        requests with a status code that is not 200.
        :param logs: grouped logs to parse
        :param threshold: how many failed attempts for a bruteforce
        :return: a new DetectionResult with attempt details
        """
        matches: list[Schema] = []
        tracker: dict[str, list[Schema]] = {}
        freq: int = 0
        # how many failed logins needed to trigger detection
        entries: list = []
        for remote_addr, data in logs.items():
            for log in data:
                if log['status'] != 200 and any(REQ in log['request'] for REQ in LOGIN_REQUESTS):
                    entries.append(log)
                    tracker[remote_addr] = entries
                    if len(tracker) > threshold:
                        freq = len(tracker)
                        for entry in entries:
                            matches.append(entry)

        return {
            "name": self.name,
            "freq": freq,
            "matches": matches
        }


@dataclass()
class SQLiDetector:
    """
    Detects SQL injection attempts in NGINX access logs by scanning the
    given request for SQL keywords. If a SQL keyword is found in a request,
    the log containing it is detected.
    """
    name: str = "sql_injection"

    def detect(self, logs: dict[str, list[Schema]]) -> DetectionResult:
        """
        Function to parse a given dict of grouped logs (remote_addr -> logs) in order
        to detect SQL injection attempts. Tracks logs in a list that contain SQL words
        in their request, and returns all attempts.
        :param logs: grouped logs to parse
        :return: a new DetectionResult with attempt details
        """
        matches: list[Schema] = []
        freq: int = 0
        for remote_addr, data in logs.items():
            for entry in data:
                if any(KEYWORD in entry['request'] for KEYWORD in KEYWORDS):
                    freq += 1
                    matches.append(entry)

        return {
            "name": self.name,
            "freq": freq,
            "matches": matches
        }


@dataclass()
class ScanDetector:
    """
    Detects scanning patterns in NGINX access logs. Scanning patterns
    are defined as entries containing evidence of scanning behavior such
    as Nmap compatibility or dirb directory scans. If a scanning pattern
    is found, the log containing it will be detected.
    """
    name: str = "scan_pattern"

    def detect(self, logs: dict[str, list[Schema]]) -> DetectionResult:
        """
        Function to parse a dict of grouped logs (remote_addr -> logs) in order
        to detect scanning patterns. Parses each entry's user agent for various
        keywords, such as Nmap or dirb, that would imply the action was not taken
        by a user. If a keyword is found, the log containing it is detected.
        :param logs: grouped logs to parse
        :return: a new DetectionResult with attempt details
        """
        detected: list[Schema] = []
        freq: int = 0
        for remote_adr, data in logs.items():
            for entry in data:
                if any(KEYWORD in entry['http_user_agent'] for KEYWORD in SCAN_PATTERNS):
                    freq += 1
                    detected.append(entry)

        return {
            'name': self.name,
            'freq': freq,
            'matches': detected
        }
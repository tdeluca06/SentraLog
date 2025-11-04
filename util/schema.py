from enum import IntEnum
from typing import TypedDict, Required, Optional


class Severity(IntEnum):
    """
    A class to define severity types using IntEnum. IntEnum is used for natural behavior
    during serialization. Mapped to integers -1, 0, 1 in order to treat labels as ordinal
    for future ML compatibility.
    """

    LOW = -1
    MEDIUM = 0
    HIGH = 1


class Schema(TypedDict):
    """
    Normalized NGINX access log entry.

        Fields:
        - remote_addr: str
            IP that made the request.
        - remote_user: str | None
            Authenticated user if provided.
        - time_local: str
            Timestamp in NGINX access log format.
        - timestamp: str
            Timestamp in ISO08601 format.
        - request: str
            Full request line.
        - status: int
            HTTP status code returned.
        - body_bytes_sent: int | None
            Sent size in bytes if provided.
        - http_referer: str | None
            Referer header if provided.
        - http_user_agent: str | None
            User agent header if provided.
    """

    remote_addr: Required[str]
    remote_user: Optional[str]
    time_local: Required[str]
    timestamp: Required[str]          # time_local as ISO8601 str
    request: Required[str]
    status: Required[int]
    body_bytes_sent: Optional[int]
    http_referer: Optional[str]
    http_user_agent: Optional[str]


class DetectionResult(TypedDict):
    """
    Data structure to store detection results.

        Fields:
        - name: str
            Name of the rule being logged.
        - freq: int
            Frequency of the malicious log.
        - matches: list
            Violating logs to be reported.
        - severity: Severity
            Severity of the detection represented as an IntEnum. Defaults to LOW.
    """

    name: Required[str]
    freq: Required[int]
    matches: Required[list[Schema]]
    severity: Required[Severity]

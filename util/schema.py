from typing import TypedDict

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
    remote_addr: str
    remote_user: str | None
    time_local: str
    timestamp: str              # time_local as ISO8601 str
    request: str
    status: int
    body_bytes_sent: int | None
    http_referer: str | None
    http_user_agent: str | None

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
    """
    name: str
    freq: int
    matches: list[Schema]
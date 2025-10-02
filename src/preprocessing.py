from datetime import datetime
from typing import TypedDict, Pattern
import re

LOG_PATTERN: Pattern[str] = re.compile(
    r'(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<body_bytes_sent>\S+) '
    r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
)

class Schema(TypedDict):
    remote_addr: str
    remote_user: str | None
    time_local: str             # maybe not needed
    timestamp: str              # time_local as ISO8601 str
    request: str
    status: int
    body_bytes_sent: int | None
    http_referer: str | None
    http_user_agent: str | None

def load_data(fp: str) -> list[str]:
    """
    Function to load entire .log file by using readlines() built-in.
    :param fp: filepath to open as str
    :return: lines as list of str
    """
    if fp is None:
        raise FileNotFoundError("Couldn't resolve filepath input to preprocessor")

    with open(file=fp, mode='r', encoding='utf-8') as f:
        lines : list[str] = f.readlines()
        return lines

def build_schema(log: str) -> Schema | None:
    """
    Function to map an individual NGINX log line to the defined schema using regular
    expression pattern matching. Assumes NGINX default combined log format.

        Pattern components:
      - (?P<remote_addr>\S+)         -> client IP address
      - \S+                          -> ident field, ignored
      - (?P<remote_user>\S+)         -> authenticated user, or "-" if none
      - \[(?P<time_local>[^\]]+)\]   -> timestamp string inside [ ]
      - "(?P<request>[^"]*)"         -> full HTTP request
      - (?P<status>\d{3})            -> HTTP status code (3 digits)
      - (?P<body_bytes_sent>\S+)     -> size of response in bytes, or "-"
      - "(?P<http_referer>[^"]*)"    -> HTTP Referer header, or "-"
      - "(?P<http_user_agent>[^"]*)" -> User-Agent string

    :param log: line of the file to parse as str
    :return: a schema of the line
    """
    if not log.strip():
        print("Empty line encountered - skipping")
        return None

    match = LOG_PATTERN.match(log)
    if not match:
        raise ValueError(f"Could not parse log line: {log}")
    d = match.groupdict()

    dt = datetime.strptime(d["time_local"], "%d/%b/%Y:%H:%M:%S %z")
    iso_ts = dt.isoformat()

    return Schema(
        remote_addr=d["remote_addr"],
        remote_user=None if d["remote_user"] == "-" else d["remote_user"],
        time_local=d["time_local"],
        timestamp=iso_ts,
        request=d["request"],
        status=int(d["status"]),
        body_bytes_sent=None if d["body_bytes_sent"] == "-" else int(d["body_bytes_sent"]),
        http_referer=None if d["http_referer"] == "-" else d["http_referer"],
        http_user_agent=None if d["http_user_agent"] == "-" else d["http_user_agent"]
    )

def process_logs(logs: list[str]) -> list[Schema]:
    """
    Function to accumulate the processed schemas into a list of schemas.
    If an empty log is detected, it will skip that line and move onto the
    next.
    :param logs: a list of strings representing lines of a .log file
    :return: a list of logs represented as schemas
    """
    processed: list[Schema] = []
    for log in logs:
        processed_log: Schema = build_schema(log)
        if processed_log is not None:
            processed.append(processed_log)
    return processed

def print_schema(schema: Schema):
    for key, val in schema.items():
        print("{} : {}".format(key, val))

def print_list(schemas: list[Schema]):
    """
    Debugging function to clean output of the list of schemas for
    visual inspection. Prints which log it is interpreting based on
    line number in the given file.
    :param schemas:
    :return:
    """
    for i, schema in enumerate(schemas):
        print(f"Entry #{i + 1}")
        print_schema(schema)
        print("======================================================")

path: str = "../data/access.log"
test_logs: list[str] = load_data(fp=path)
output: list[Schema] = process_logs(logs=test_logs)
print_list(output)
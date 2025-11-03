# SentraLog

SentraLog is a cybersecurity tool meant to automatically detect
malicious actions present in NGINX access log datasets. Malicious
logs are detected with regular expression pattern matching and
established rulesets for each supported type of detection.

Currently, SentraLog outputs a Python dictionary mapping
individual IP addresses to malicious actions and the
severity of the action detected.

In the future, the program will output its results into an
automatically generated PDF report. 
---

## Rules

- **Brute Force Detection** - If there are a certain number of 
failed login attempts within a small timeframe, a brute force
attempt is detected.
- **SQL Injection Detection** - If SQL keywords or queries are
found in the request header, a SQL injection attempt is detected.
- **Scanning Pattern Detection** - If any known scanning keywords,
such as nmap or dirb are detected in the request header, a scanning
pattern attempt is detected.
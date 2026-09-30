# Security Log Analyser

A beginner Python cybersecurity project that reads login events from a CSV file, counts successful and failed logins, and flags IP addresses with repeated failures.


## Features

- Count successful and failed login attempts.
- Group results by IP address.
- Flag addresses with five or more failures (configurable).
- Validate timestamps, IP addresses, usernames and status values.
- Skip malformed rows and show their row numbers.
- Export a CSV report.



```bash
python3 analyser.py
```


To change the alert threshold:

```bash
python3 analyser.py --threshold 3
```

To analyse your own file:

```bash
python3 analyser.py --log your_log.csv --output your_report.csv
```

Input and output must be different files. The output directory must already exist. An existing output report is overwritten.

## Input format

The CSV needs these headers:

```csv
timestamp,username,ip_address,status
2026-09-30T09:00:00,student,192.0.2.10,SUCCESS
```

Use ISO timestamps and either SUCCESS or FAILED. This is a simplified teaching format, not a native Windows or Linux log parser.

## Expected sample results

- 3 successful logins
- 6 failed logins
- 1 invalid row skipped (row 11)
- 1 flagged IP: 198.51.100.23 with 5 failed attempts

The generated `report.csv` contains one row per valid IP address.

## How the code works

1. `analyse_log` reads and validates each event, then counts results with `Counter`.
2. `write_report` writes totals and an alert flag for each IP.
3. `main` handles command-line options, errors and the printed summary.

## Limitations

A flag means repeated failures, not proof of an attack. Counts cover the entire file; there is no time window or live monitoring. Shared IP addresses can produce false positives. This tool does not block traffic or change security settings.



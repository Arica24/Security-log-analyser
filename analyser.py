"""Analyse a simple CSV login log using only Python's standard library."""
import argparse
import csv
from collections import Counter
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path


def analyse_log(path):
    """Count valid events; record invalid rows rather than silently using them."""
    successes, failures = Counter(), Counter()
    invalid = []
    with Path(path).open(newline='', encoding='utf-8') as source:
        reader = csv.DictReader(source)
        required = {'timestamp', 'username', 'ip_address', 'status'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('Log must contain: timestamp, username, ip_address, status')
        for row in reader:
            try:
                datetime.fromisoformat(row['timestamp'])
                address = str(ip_address(row['ip_address'].strip()))
                status = row['status'].strip().upper()
                if not row['username'].strip() or status not in {'SUCCESS', 'FAILED'}:
                    raise ValueError('Invalid username or status')
            except (ValueError, TypeError, AttributeError):
                invalid.append(reader.line_num)
                continue
            if status == 'SUCCESS':
                successes[address] += 1
            else:
                failures[address] += 1
    return successes, failures, invalid


def write_report(path, successes, failures, threshold):
    """Write one row per IP address, including the simple alert flag."""
    with Path(path).open('w', newline='', encoding='utf-8') as output:
        writer = csv.writer(output)
        writer.writerow(['ip_address', 'successful_logins', 'failed_logins', 'flagged'])
        for address in sorted(successes.keys() | failures.keys()):
            writer.writerow([address, successes[address], failures[address],
                             failures[address] >= threshold])


def positive_number(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('Threshold must be at least 1')
    return number


def main():
    folder = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, default=folder / 'sample_log.csv')
    parser.add_argument('--output', type=Path, default=folder / 'report.csv')
    parser.add_argument('--threshold', type=positive_number, default=5,
                        help='Flag IPs with at least this many failures across the whole file')
    args = parser.parse_args()
    if args.log.resolve() == args.output.resolve():
        parser.error('Output must be different from the input log')
    try:
        successes, failures, invalid = analyse_log(args.log)
        write_report(args.output, successes, failures, args.threshold)
    except (OSError, ValueError, csv.Error) as error:
        parser.error(str(error))
    print('SECURITY LOG ANALYSER')
    print(f'Successful logins: {sum(successes.values())}')
    print(f'Failed logins: {sum(failures.values())}')
    print(f'Invalid rows skipped: {len(invalid)}')
    if invalid:
        print('Invalid row numbers:', ', '.join(map(str, invalid)))
    flagged = sorted(ip for ip, count in failures.items() if count >= args.threshold)
    print(f'Flagged IP addresses: {len(flagged)}')
    for address in flagged:
        print(f'  {address}: {failures[address]} failed attempts')
    print(f'Report saved to: {args.output}')


if __name__ == '__main__':
    main()

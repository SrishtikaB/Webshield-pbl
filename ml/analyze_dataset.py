"""Inspect an existing labelled URL CSV. Does not generate or invent labels."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

URL_COLUMN_ALIASES = ("url", "urls", "link", "website", "uri")
LABEL_COLUMN_ALIASES = ("label", "class", "result", "type", "status", "phishing", "target")

REQUIRED_SCHEMA = "url,label"
LABEL_HELP = (
    "label values should be binary and explicit, for example: "
    "0/1, legitimate/phishing, benign/phish, or good/bad."
)


def required_schema_message() -> str:
    return (
        "No suitable labelled URL dataset was found in this repository.\n"
        "Do not generate fake training rows. Provide a real CSV with header:\n"
        f"  {REQUIRED_SCHEMA}\n"
        f"{LABEL_HELP}\n"
        "Example (schema only, not training data):\n"
        "  url,label\n"
        "  https://example.com,legitimate\n"
        "  http://192.0.2.1/login,phishing\n"
        "Place the file at data/urls.csv (project root) or pass --csv PATH."
    )


def resolve_columns(fieldnames: list[str] | None) -> tuple[str | None, str | None]:
    if not fieldnames:
        return None, None
    lowered = {name.strip().lower(): name for name in fieldnames if name and name.strip()}
    url_col = next((lowered[alias] for alias in URL_COLUMN_ALIASES if alias in lowered), None)
    label_col = next((lowered[alias] for alias in LABEL_COLUMN_ALIASES if alias in lowered), None)
    return url_col, label_col


def is_invalid_url(raw_url: str | None) -> bool:
    text = (raw_url or "").strip()
    if not text:
        return True
    candidate = text if "://" in text else "http://" + text
    try:
        parsed = urlparse(candidate)
    except Exception:
        return True
    host = (parsed.hostname or "").strip()
    if not host:
        return True
    stripped = host.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return False
    except ValueError:
        pass
    if "." not in host:
        return True
    return False


def _read_csv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = [dict(row) for row in reader]
    return fieldnames, rows


def analyze_csv(path: Path) -> dict:
    fieldnames, rows = _read_csv_rows(path)
    url_col, label_col = resolve_columns(fieldnames)

    missing_by_column: dict[str, int] = {name: 0 for name in fieldnames}
    for row in rows:
        for name in fieldnames:
            value = row.get(name)
            if value is None or str(value).strip() == "":
                missing_by_column[name] += 1

    seen_rows: set[tuple[tuple[str, str], ...]] = set()
    duplicate_records = 0
    for row in rows:
        key = tuple(sorted((k, str(v)) for k, v in row.items()))
        if key in seen_rows:
            duplicate_records += 1
        else:
            seen_rows.add(key)

    url_counts: Counter[str] = Counter()
    if url_col:
        for row in rows:
            url_counts[str(row.get(url_col, "")).strip()] += 1
    duplicate_url_rows = sum(count - 1 for count in url_counts.values() if count > 1)
    duplicate_url_values = sum(1 for url, count in url_counts.items() if url and count > 1)

    class_distribution: dict[str, int] = {}
    if label_col:
        class_distribution = dict(Counter(str(row.get(label_col, "")).strip() for row in rows))

    invalid_url_records = 0
    if url_col:
        invalid_url_records = sum(1 for row in rows if is_invalid_url(row.get(url_col)))

    suitable = bool(url_col and label_col)
    return {
        "path": str(path),
        "suitable": suitable,
        "column_names": fieldnames,
        "url_column": url_col,
        "label_column": label_col,
        "num_records": len(rows),
        "missing_values": missing_by_column,
        "duplicate_records": duplicate_records,
        "duplicate_url_rows": duplicate_url_rows,
        "duplicate_url_values": duplicate_url_values,
        "class_distribution": class_distribution,
        "invalid_url_records": invalid_url_records,
    }


def format_report(report: dict) -> str:
    lines = [
        f"Dataset: {report['path']}",
        f"Column names: {report['column_names']}",
        f"Number of records: {report['num_records']}",
        f"URL column: {report['url_column']}",
        f"Label column: {report['label_column']}",
        "Missing values per column:",
    ]
    missing = report.get("missing_values") or {}
    if missing:
        for name, count in missing.items():
            lines.append(f"  - {name}: {count}")
    else:
        lines.append("  (no columns)")
    lines.extend(
        [
            f"Duplicate records (exact row repeats): {report['duplicate_records']}",
            f"Duplicate URL values: {report['duplicate_url_values']}",
            f"Extra rows from duplicate URLs: {report['duplicate_url_rows']}",
            f"Invalid URL records: {report['invalid_url_records']}",
            "Class distribution:",
        ]
    )
    distribution = report.get("class_distribution") or {}
    if distribution:
        for label, count in sorted(distribution.items(), key=lambda item: (-item[1], item[0])):
            display = label if label else "(empty)"
            lines.append(f"  - {display}: {count}")
    else:
        lines.append("  (no label column)")
    if not report.get("suitable"):
        lines.append("")
        lines.append("This file is not a suitable labelled URL dataset.")
        lines.append(required_schema_message())
    return "\n".join(lines)


def default_dataset_candidates(project_root: Path) -> list[Path]:
    return [
        project_root / "data" / "clean_urls.csv",
        project_root / "data" / "urls.csv",
        project_root / "ml" / "data" / "urls.csv",
        project_root / "dataset.csv",
        project_root / "data.csv",
    ]


def find_existing_dataset(project_root: Path) -> Path | None:
    for candidate in default_dataset_candidates(project_root):
        if candidate.is_file():
            return candidate
    return None


def main(argv: list[str] | None = None) -> int:
    project_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Inspect a labelled URL CSV dataset.")
    parser.add_argument(
        "--csv",
        dest="csv_path",
        default=None,
        help="Path to a labelled CSV. If omitted, common project locations are checked.",
    )
    args = parser.parse_args(argv)

    path = Path(args.csv_path) if args.csv_path else find_existing_dataset(project_root)
    if path is None:
        print(required_schema_message())
        print("Checked:")
        for candidate in default_dataset_candidates(project_root):
            print(f"  - {candidate}")
        return 1
    if not path.is_file():
        print(f"CSV not found: {path}")
        print(required_schema_message())
        return 1

    report = analyze_csv(path)
    print(format_report(report))
    return 0 if report.get("suitable") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

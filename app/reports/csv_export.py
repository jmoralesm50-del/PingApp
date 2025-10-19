# app/reports/csv_export.py

from __future__ import annotations
import csv
from typing import Iterable, Tuple


def export_to_csv(
    path: str,
    rows: Iterable[Tuple[str, str, str, str, str, str]]
) -> None:
    """
    rows: iterable de tuplas (ip, status, rtt_ms, hostname, timestamp, method)
    """
    headers = ["IP", "Estado", "RTT_ms", "Hostname", "Timestamp", "Metodo"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for r in rows:
            writer.writerow(r)
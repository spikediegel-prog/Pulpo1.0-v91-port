"""Pulpo command-line entry point (port: incidents only).

Port note: Preview cli.py also carries verify, setup, and tune
subcommands, which depend on fork-only packages (pulpo.setup,
pulpo.verifier, the Tkinter tuning window) that have no upstream home.
This port carries only the `incidents` subcommand from Preview PR #123:
list / show / summary over a frozen incident report, read-only. The
incidents functions and parser below are verbatim from Preview 4945147.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path


DEFAULT_INCIDENT_REPORT = "evidence/incident_report.json"


def _parse_incident_instant(value, flag):
    """Parse an ISO 8601 datetime flag into nanoseconds since the epoch."""
    if value is None:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        from datetime import datetime, timezone
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(
            f"{flag} must be an ISO 8601 datetime, e.g. 2026-11-11T00:00:00Z"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp()) * 1_000_000_000 + parsed.microsecond * 1000


def _format_incident_time(timestamp_ns):
    return time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(timestamp_ns / 1e9))


def _load_incident_report(report):
    """Load a frozen incident report; the path is resolved against the cwd."""
    from .incident_channel import load_incident_report
    destination = Path(report).expanduser().resolve()
    try:
        return load_incident_report(destination)
    except (ValueError, OSError) as exc:
        raise ValueError(f"incident report unavailable or invalid: {destination}") from exc


def _filter_incident_records(report, args):
    """Apply the CLI filters; the time window applies to first_seen_ns."""
    since_ns = _parse_incident_instant(args.since, "--since")
    until_ns = _parse_incident_instant(args.until, "--until")
    if since_ns is not None and until_ns is not None and since_ns > until_ns:
        raise ValueError("--since must not be after --until")
    return tuple(
        record for record in report.records
        if (args.kind is None or record.kind == args.kind)
        and (args.resolution is None or record.resolution == args.resolution)
        and (args.lifecycle is None or record.lifecycle == args.lifecycle)
        and (since_ns is None or record.first_seen_ns >= since_ns)
        and (until_ns is None or record.first_seen_ns <= until_ns)
    )


def _incidents_list_command(args):
    report = _load_incident_report(args.report)
    records = _filter_incident_records(report, args)
    print("PULPO INCIDENTS")
    print()
    print(f"Report .................... {Path(args.report).expanduser().resolve()}")
    print(f"Incidents ................. {report.incidents} · Near-misses: {report.near_misses} "
          f"· Unresolved: {report.unresolved}")
    print(f"Matching .................. {len(records)}")
    print()
    if not records:
        print("No incidents match.")
        return 0
    for record in records:
        print(f"{record.record_id} · {record.kind} · {record.resolution} · {record.lifecycle} · "
              f"{_format_incident_time(record.first_seen_ns)}")
    return 0


def _incidents_show_command(args):
    report = _load_incident_report(args.report)
    record = next((item for item in report.records if item.record_id == args.record_id), None)
    if record is None:
        raise ValueError(f"incident_record_not_found: {args.record_id}")
    print("PULPO INCIDENT")
    print()
    print(f"Record .................... {record.record_id}")
    print(f"Kind ...................... {record.kind}")
    print(f"Source .................... {record.source} · {record.source_detail}")
    print(f"Reason .................... {record.reason}")
    print(f"Resolution ................ {record.resolution}")
    print(f"Lifecycle ................. {record.lifecycle} · "
          f"{_format_incident_time(record.lifecycle_at_ns)} · {record.lifecycle_actor or '—'}")
    print(f"First seen ................ {_format_incident_time(record.first_seen_ns)}")
    print(f"Last seen ................. {_format_incident_time(record.last_seen_ns)}")
    print(f"Anchor hash ............... {record.anchor_hash}")
    print("Anchors ...................")
    for name, value in record.anchors:
        print(f"  {name}: {value}")
    return 0


def _incidents_summary_command(args):
    report = _load_incident_report(args.report)
    print("PULPO INCIDENT SUMMARY")
    print()
    print(f"Report .................... {Path(args.report).expanduser().resolve()}")
    print(f"Observed ................... {_format_incident_time(report.observed_at_ns)}")
    print(f"Audit valid ............... {'yes' if report.audit_valid else 'no'}")
    print(f"Audit records ............. {report.audit_records}")
    print(f"Incidents ................. {report.incidents}")
    print(f"Near-misses ............... {report.near_misses}")
    print(f"Unresolved ................ {report.unresolved}")
    print(f"Resolved cleanly .......... {report.resolved_cleanly}")
    print(f"Confirmed wrong ........... {report.confirmed_wrong}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pulpo")
    subparsers = parser.add_subparsers(dest="command", required=True)
    incidents = subparsers.add_parser(
        "incidents",
        help="read a frozen incident report (read-only; never authorizes)",
    )
    incidents_sub = incidents.add_subparsers(dest="incidents_command", required=True)
    incidents_list = incidents_sub.add_parser("list", help="list incidents in a frozen report")
    incidents_list.add_argument(
        "--report",
        default=DEFAULT_INCIDENT_REPORT,
        help="frozen incident report path (default: evidence/incident_report.json)",
    )
    incidents_list.add_argument("--kind", choices=["incident", "near_miss"])
    incidents_list.add_argument(
        "--resolution",
        choices=["unresolved", "resolved_cleanly", "confirmed_wrong", "not_applicable"],
    )
    incidents_list.add_argument(
        "--lifecycle",
        choices=["open", "acknowledged", "resolved", "closed", "not_applicable"],
    )
    incidents_list.add_argument(
        "--since", help="ISO 8601 lower bound on first seen, e.g. 2026-11-11T00:00:00Z"
    )
    incidents_list.add_argument("--until", help="ISO 8601 upper bound on first seen")
    incidents_list.set_defaults(func=_incidents_list_command)
    incidents_show = incidents_sub.add_parser("show", help="show one incident record")
    incidents_show.add_argument(
        "--report",
        default=DEFAULT_INCIDENT_REPORT,
        help="frozen incident report path (default: evidence/incident_report.json)",
    )
    incidents_show.add_argument("record_id", help="incident or near-miss record id")
    incidents_show.set_defaults(func=_incidents_show_command)
    incidents_summary = incidents_sub.add_parser(
        "summary", help="counts from a frozen incident report"
    )
    incidents_summary.add_argument(
        "--report",
        default=DEFAULT_INCIDENT_REPORT,
        help="frozen incident report path (default: evidence/incident_report.json)",
    )
    incidents_summary.set_defaults(func=_incidents_summary_command)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())

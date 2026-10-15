
import csv
import ipaddress
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet

INPUT = Path("auth_logs.csv")
OUTPUT = Path("investigation_findings.csv")
TIMELINE = Path("incident_timeline.csv")
REPORT = Path("incident_report.pdf")

SPRAY_THRESHOLD = 5
BRUTE_FORCE_THRESHOLD = 5


def normalize(row):
    """Normalize and validate one synthetic authentication event."""
    timestamp = datetime.fromisoformat(
        row["timestamp"].replace("Z", "+00:00")
    )

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    ip = str(ipaddress.ip_address(row["ip"].strip()))
    account = row["account"].strip()
    action = row["action"].strip().lower()
    result = row["result"].strip().lower()

    if not account or action != "login":
        raise ValueError("Invalid account or action")

    if result not in {"success", "failure"}:
        raise ValueError("Invalid result")

    return {
        "timestamp": timestamp,
        "ip": ip,
        "account": account,
        "action": action,
        "result": result,
    }


def investigate():
    events = []

    with INPUT.open(newline="", encoding="utf-8") as file:
        for line_number, row in enumerate(csv.DictReader(file), start=2):
            try:
                events.append(normalize(row))
            except (ValueError, KeyError) as exc:
                print(f"Skipping row {line_number}: {exc}")

    events.sort(key=lambda event: event["timestamp"])

    failed_by_ip = defaultdict(list)
    failed_by_account = defaultdict(list)
    findings = []

    for event in events:
        if event["result"] == "failure":
            failed_by_ip[event["ip"]].append(event)
            failed_by_account[event["account"]].append(event)

    # Detection 1: many failed logins against one account.
    for account, failures in failed_by_account.items():
        if len(failures) >= BRUTE_FORCE_THRESHOLD:
            findings.append({
                "rule": "Repeated login failures",
                "entity": account,
                "count": len(failures),
                "severity": "High",
                "evidence": (
                    f"{len(failures)} failed attempts against account "
                    f"{account}"
                ),
                "action": "Review authentication logs and account security."
            })

    # Detection 2: one source trying multiple accounts.
    for ip, failures in failed_by_ip.items():
        accounts = {event["account"] for event in failures}

        if len(accounts) >= SPRAY_THRESHOLD:
            findings.append({
                "rule": "Possible password spraying",
                "entity": ip,
                "count": len(accounts),
                "severity": "High",
                "evidence": (
                    f"{len(failures)} failures across "
                    f"{len(accounts)} distinct accounts"
                ),
                "action": "Review source activity and apply approved controls."
            })

    # Detection 3: successful login after earlier failures.
    for event in events:
        if event["result"] != "success":
            continue

        prior = [
            failure for failure in failed_by_account[event["account"]]
            if failure["timestamp"] < event["timestamp"]
        ]

        if len(prior) >= 3:
            findings.append({
                "rule": "Success after repeated failures",
                "entity": event["account"],
                "count": len(prior),
                "severity": "High",
                "evidence": (
                    f"{len(prior)} earlier failures before a successful "
                    f"login from {event['ip']}"
                ),
                "action": "Verify whether the successful access was authorized."
            })

    # Write findings.
    columns = [
        "rule", "entity", "count", "severity", "evidence", "action"
    ]

    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(findings)

    # Write normalized chronological timeline.
    with TIMELINE.open("w", newline="", encoding="utf-8") as file:
        columns = ["timestamp", "ip", "account", "action", "result"]
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()

        for event in events:
            writer.writerow({
                **event,
                "timestamp": event["timestamp"].isoformat()
            })

    create_report(events, findings)

    print(f"Events analyzed: {len(events)}")
    print(f"Detection findings: {len(findings)}")
    print(f"Created: {OUTPUT}, {TIMELINE}, {REPORT}")


def create_report(events, findings):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(REPORT), pagesize=A4)

    story = [
        Paragraph("Security Log Investigation Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(
            "Scope: synthetic authentication events supplied with this "
            "educational project.",
            styles["BodyText"]
        ),
        Spacer(1, 8),
        Paragraph(f"Events analyzed: {len(events)}", styles["BodyText"]),
        Paragraph(f"Findings generated: {len(findings)}", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Detection Findings", styles["Heading2"]),
    ]

    rows = [["Rule", "Entity", "Count", "Severity", "Evidence"]]

    for finding in findings:
        rows.append([
            finding["rule"],
            finding["entity"],
            str(finding["count"]),
            finding["severity"],
            finding["evidence"],
        ])

    if not findings:
        rows.append([
            "No rule triggered", "-", "0", "Informational",
            "No configured threshold was reached."
        ])

    table = Table(rows, repeatRows=1, colWidths=[95, 70, 35, 55, 180])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Limitations and Response", styles["Heading2"]))
    story.append(Paragraph(
        "These rules identify patterns for investigation; they do not prove "
        "malicious activity. Validate timestamps, account ownership, source "
        "context, and related events before drawing conclusions. Preserve "
        "relevant logs and follow the organization's authorized incident "
        "response process.",
        styles["BodyText"]
    ))

    doc.build(story)


if __name__ == "__main__":
    investigate()

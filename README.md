
# Security Log Investigation and Incident Response

## 1. Project Overview

This project analyzes authentication event logs to identify suspicious login activities and generate security investigation findings.

The project uses Python to normalize log records, detect repeated login failures, identify possible password spraying, create an incident timeline, and generate an incident report in PDF format.

## 2. Objectives

- Normalize timestamps, IP addresses, usernames, actions, and results.
- Detect repeated login failures and possible brute-force attempts.
- Identify possible password spraying activities.
- Detect successful logins following repeated failures.
- Create a chronological investigation timeline.
- Generate a PDF incident report with evidence and recommended actions.

## 3. Technologies Used

- Python 3
- CSV
- IP address validation
- ReportLab
- GitHub

## 4. Project Structure

```text
security-log-investigation/
├── investigate.py
├── auth_logs.csv
├── test_investigate.py
├── requirements.txt
├── README.md
├── investigation_findings.csv
├── incident_timeline.csv
└── incident_report.pdf
```

## 5. Features

### Log Normalization
Validates and standardizes timestamps, IP addresses, account names, and authentication results.

### Brute-Force Detection
Flags accounts with repeated failed login attempts.

### Password-Spraying Detection
Flags a source IP address that generates failed login attempts against multiple accounts.

### Unusual Access Detection
Flags successful logins that follow several earlier failed attempts against the same account.

### Incident Timeline
Sorts authentication events chronologically for easier investigation.

### Incident Report
Generates a PDF containing investigation statistics, detection findings, and recommended response actions.

## 6. Installation

Install Python 3 and open a terminal in the project folder.

Install the required dependency:

```bash
python -m pip install -r requirements.txt
```

## 7. Run Automated Tests

Execute:

```bash
python -m unittest
```

The tests check valid event normalization and invalid IP address handling.

## 8. Run the Project

Execute:

```bash
python investigate.py
```

The program reads `auth_logs.csv` and generates the following files:

- `investigation_findings.csv`
- `incident_timeline.csv`
- `incident_report.pdf`

## 9. Detection Rules

| Detection | Condition |
|---|---|
| Repeated login failures | Five or more failures against one account |
| Possible password spraying | Failures against five or more distinct accounts from one IP |
| Success after repeated failures | A successful login after at least three earlier failures |

These are configurable educational rules. A triggered rule does not independently prove an attack occurred.

## 10. Expected Results

The sample dataset contains fictional authentication events. The analysis should identify repeated failures against an account, failures across multiple accounts from one IP, and a successful login after earlier failures.

The findings CSV records the rule, affected entity, count, severity, evidence, and recommended action.

## 11. Security Recommendations

- Review suspicious authentication events.
- Verify account ownership and whether successful access was authorized.
- Preserve relevant logs for investigation.
- Apply approved rate limits and multi-factor authentication.
- Follow the organization's incident response procedures.
- Do not expose real usernames, credentials, or sensitive logs in a public repository.

## 12. Limitations

This project uses synthetic data and simple rule-based detections. It may generate false positives and does not establish malicious intent by itself.

Use only logs you are authorized to analyze. Validate findings against additional evidence before declaring an incident confirmed.

## 13. Conclusion

This project demonstrates how Python can support defensive security log analysis, detection-rule development, incident timeline creation, and report generation.

It provides a beginner-friendly foundation for learning security monitoring and incident response.

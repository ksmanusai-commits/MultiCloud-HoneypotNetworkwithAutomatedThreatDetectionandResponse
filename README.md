# MultiCloud-HoneypotNetworkwithAutomatedThreatDetectionandResponse


## Overview
This project extends deception-based detection by implementing automated threat response
across multiple cloud platforms. Honeypot alerts generated in Splunk trigger automated
blocking of malicious IP addresses across AWS, Azure, and GCP using native firewall controls.

The objective is to demonstrate cross-cloud containment of attackers once malicious
activity is detected.

---

## Objectives
- Automate threat response based on honeypot alerts
- Block malicious IPs across AWS, Azure, and GCP
- Correlate attacks using Splunk SIEM
- Validate enforcement using status verification scripts

## Architecture

Honeypots
↓
Splunk Correlation Rules
↓
Decision Engine
↓
Automation Scripts
↓
AWS | Azure | GCP Firewalls

## Technologies Used
- OpenCanary
- Splunk Enterprise
- AWS CLI
- Azure CLI
- Google Cloud CLI
- Bash scripting

---

## Automated Response Workflow
1. Honeypot detects malicious activity
2. Splunk correlation rule triggers alert
3. Alert executes automation script
4. IP is blocked across all cloud platforms
5. Status verification confirms enforcement


## Validated Scenarios
- SSH brute-force attacks
- Azure to GCP lateral movement
- Cross-cloud IP blocking
- Block verification across providers

## Limitations
- CLI credential dependency
- Time-window based detection
- Requires per-cloud authentication setup

---

## Lessons Learned
- Importance of independent provider execution
- Credential scope challenges in automation
- Verification vs enforcement gaps

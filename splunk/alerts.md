# Splunk Alerts

This file documents the security alerts configured during the Splunk + Suricata SOC project.

---

## 1. Suricata IDS Alert Detected

**Purpose:**
Detect Suricata IDS alert events forwarded from Ubuntu to Splunk.

**Search:**

```spl
index=suricata event_type=alert
| table _time host src_ip src_port dest_ip dest_port proto alert.signature alert.category alert.severity
```

**Configuration:**

* Alert Type: Scheduled
* Schedule: Hourly
* Trigger Condition: Number of Results > 0
* Severity: Medium
* Action: Add to Triggered Alerts
* Status: Enabled

---

## 2. Privileged Sudo Command Detected

**Purpose:**
Detect privileged sudo commands executed on Ubuntu.

**Search:**

```spl
index=auth "sudo:" "COMMAND="
| rex field=_raw "sudo:\s+(?<user>\S+)\s+.*USER=(?<target_user>\S+)\s+;\s+COMMAND=(?<command>.*)"
| where isnotnull(user) AND isnotnull(command)
| table _time host user target_user command
| sort -_time
```

**Configuration:**

* Alert Type: Scheduled
* Schedule: Hourly
* Trigger Condition: Number of Results > 0
* Severity: Medium
* Action: Add to Triggered Alerts
* Status: Enabled

---

## Alert Summary

| Alert                            | Purpose                    | Status  |
| -------------------------------- | -------------------------- | ------- |
| Suricata IDS Alert Detected      | Detect Suricata IDS events | Enabled |
| Privileged Sudo Command Detected | Detect sudo activity       | Enabled |

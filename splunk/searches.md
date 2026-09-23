# Splunk SPL Searches

This file contains the main SPL searches used during the Splunk + Suricata SOC project.

---

## 1. Check All Indexes

```spl
index=* | stats count by index
```

Used to verify the number of events stored in each Splunk index.

---

## 2. Windows Security Logs

```spl
index=windows | head 20 | table _time host source sourcetype EventCode _raw
```

Used to verify Windows Security events received by Splunk.

---

## 3. Ubuntu Authentication Logs

```spl
index=auth | head 20 | table _time host source sourcetype _raw
```

Used to verify Ubuntu `/var/log/auth.log` events.

---

## 4. Sudo Activity Investigation

```spl
index=auth "sudo:" "COMMAND="
| rex field=_raw "sudo:\s+(?<user>\S+)\s+.*USER=(?<target_user>\S+)\s+;\s+COMMAND=(?<command>.*)"
| where isnotnull(user) AND isnotnull(command)
| table _time host user target_user command
| sort -_time
```

Used to identify privileged sudo commands executed on Ubuntu.

---

## 5. Suricata Event Types

```spl
index=suricata
| stats count by event_type
| sort -count
```

Used to analyze the different types of Suricata events received by Splunk.

---

## 6. Suricata IDS Alerts

```spl
index=suricata event_type=alert
| table _time host src_ip src_port dest_ip dest_port proto alert.signature alert.category alert.severity
```

Used to investigate Suricata IDS alerts.

---

## 7. Suricata Event Correlation

```spl
index=suricata
src_ip="217.160.0.187" OR dest_ip="217.160.0.187"
| stats count by event_type src_ip dest_ip dest_port
| sort -count
```

Used to correlate related Suricata network events such as `flow`, `http`, `fileinfo`, and `alert`.

---

## 8. Authentication Event Summary

```spl
index=auth | stats count by sourcetype, source, host
```

Used to verify authentication log ingestion and event counts.

---

## Project Indexes

| Index      | Purpose                    |
| ---------- | -------------------------- |
| `windows`  | Windows Security Events    |
| `auth`     | Ubuntu authentication logs |
| `suricata` | Suricata IDS events        |

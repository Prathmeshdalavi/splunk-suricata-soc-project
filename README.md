# 🔐 Splunk + Suricata SOC Monitoring Project

A hands-on **Security Operations Center (SOC) lab** built using **Splunk Enterprise, Universal Forwarder, Ubuntu, Windows Security Logs, and Suricata IDS**.

The project demonstrates centralized log collection, security event investigation, network monitoring, event correlation, and alert configuration.

---

## 🎯 Objectives

* Configure Splunk Enterprise as a centralized SIEM.
* Forward Windows and Ubuntu security logs to Splunk.
* Monitor Ubuntu authentication and privileged activity.
* Deploy Suricata IDS and ingest `eve.json` events.
* Investigate security events using SPL.
* Correlate related network events.
* Configure security detection alerts.

---

## 🏗️ Architecture

```text
Windows Security Logs ──┐
                        │
                        ▼
                 Splunk Enterprise
                    TCP 9997
                        ▲
                        │
Ubuntu VM ──────────────┘
   │
   ├── /var/log/auth.log
   │
   ├── Universal Forwarder
   │
   └── Suricata IDS
          │
          └── eve.json
```

---

## 🛠️ Technologies

| Technology          | Purpose                              |
| ------------------- | ------------------------------------ |
| Splunk Enterprise   | SIEM and log analysis                |
| Universal Forwarder | Log collection and forwarding        |
| Windows             | Security event source                |
| Ubuntu              | Linux authentication source          |
| Suricata            | Network IDS                          |
| SPL                 | Security investigation and detection |

---

## 📊 Project Results

The following telemetry was successfully indexed in Splunk:

| Index      |    Events |
| ---------- | --------: |
| `windows`  |     7,568 |
| `auth`     |       129 |
| `suricata` |     1,221 |
| **Total**  | **8,918** |

Additional investigation results:

* **39** sudo events extracted and analyzed.
* **1** verified Suricata IDS alert investigated.
* **2** scheduled Splunk alerts configured.

---

## 🔎 Key Investigations

### Ubuntu Authentication

```spl
index=auth | stats count by sourcetype, source, host
```

Monitored:

```text
/var/log/auth.log
```

### Sudo Activity

```spl
index=auth "sudo:" "COMMAND="
| rex field=_raw "sudo:\s+(?<user>\S+)\s+.*USER=(?<target_user>\S+)\s+;\s+COMMAND=(?<command>.*)"
| where isnotnull(user) AND isnotnull(command)
| table _time host user target_user command
| sort -_time
```

### Suricata IDS Alerts

```spl
index=suricata event_type=alert
| table _time host src_ip src_port dest_ip dest_port proto alert.signature alert.category alert.severity
```

A Suricata alert was identified with the signature:

```text
GPL ATTACK_RESPONSE id check returned root
```

The event was categorized as **Potentially Bad Traffic** with severity **2**.

> The IDS event was documented as a detected security event requiring investigation; it was not treated as proof of a successful compromise.

### Event Correlation

Related Suricata `alert`, `fileinfo`, `flow`, and `http` events were correlated using the involved IP address.

---

## 🚨 Configured Alerts

Two scheduled Splunk alerts were configured:

1. **Suricata IDS Alert Detected**
2. **Privileged Sudo Command Detected**

Both alerts are enabled and configured to trigger when matching search results are found.

---

## 📸 Screenshots

### Splunk Receiver

![Splunk Receiver](screenshots/01-splunk-receiver-9997.png)

### Windows Security Logs

![Windows Security Logs](screenshots/02-windows-security-logs.png)

### Ubuntu Authentication Logs

![Ubuntu Auth Logs](screenshots/03-ubuntu-auth-logs.png)

### Sudo Investigation

![Sudo Investigation](screenshots/04-sudo-investigation.png)

### Suricata Event Types

![Suricata Event Types](screenshots/05-suricata-event-types.png)

### Suricata IDS Alert

![Suricata IDS Alert](screenshots/06-suricata-ids-alert.png)

### Suricata Correlation

![Suricata Correlation](screenshots/07-suricata-correlation.png)

### Splunk Alerts

![Splunk Alerts](screenshots/08-splunk-alerts.png)

---

## 🧠 Skills Demonstrated

* Splunk Enterprise / SIEM
* SPL querying
* Log ingestion and indexing
* Windows Security monitoring
* Linux authentication monitoring
* Sudo activity investigation
* Suricata IDS
* Network event analysis
* Event correlation
* Security alert configuration
* SOC investigation workflow

---

## 📁 Repository Structure

```text
splunk-suricata-soc-project/
│
├── README.md
├── screenshots/
│   ├── 01-splunk-receiver-9997.png
│   ├── 02-windows-security-logs.png
│   ├── 03-ubuntu-auth-logs.png
│   ├── 04-sudo-investigation.png
│   ├── 05-suricata-event-types.png
│   ├── 06-suricata-ids-alert.png
│   ├── 07-suricata-correlation.png
│   └── 08-splunk-alerts.png
│
├── splunk/
├── suricata/
└── docs/
```

---

## 🚀 Future Improvements

* SOC monitoring dashboards
* Additional Windows security detections
* Brute-force detection
* Suspicious PowerShell detection
* Additional Suricata rules
* MITRE ATT&CK mapping
* Automated incident response

---

## 👤 Author

**Prathmesh Dalavi**

# Security Investigation

This document summarizes the Suricata security event investigation performed in Splunk.

## Investigation Steps

### 1. Identify Suricata Alerts

Suricata alert events were searched using:

```spl
index=suricata event_type=alert
```

One IDS alert was identified.

### 2. Review the Alert

The identified alert had the following details:

* **Signature:** `GPL ATTACK_RESPONSE id check returned root`
* **Category:** `Potentially Bad Traffic`
* **Severity:** `2`
* **Protocol:** TCP

### 3. Correlate Related Events

The involved IP address was used to find related Suricata events.

The investigation identified:

* `alert`
* `fileinfo`
* `flow`
* `http`

events related to the same network activity.

### 4. Investigation Result

The related events provided a sequence of network activity that included HTTP communication, file information, and an IDS alert.

The event was treated as a **security detection requiring further investigation**, not as confirmed evidence of a successful compromise.

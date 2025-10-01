# KB — User‑Reported Phishing (Triage & Response)

**Audience:** Tier‑1/Tier‑2 SOC analysts
**SLA:** Begin triage within **10 minutes** of report/alert

---

## Problem Signature

A user reports a suspicious email (via Phish‑Alert button or helpdesk), or the email gateway/EDR raises a phishing‑related alert. You need to verify, scope impact, contain, and close with user guidance.

---

## Preconditions / Tools

* Microsoft 365 Defender (Threat Explorer/Advanced Hunting), Exchange/Defender for Office 365
* SIEM/SOAR (e.g., Microsoft Sentinel) with mail/identity logs onboarded
* Identity admin access for password reset/token revocation (or an on‑call identity SME)
* Approved sandbox for safe detonation (use only if passive intel is insufficient)

---

## Quick Triage Checklist (do in order)

1. **Collect the original message** (headers, body, URLs, attachments). Preserve the **NetworkMessageId**.
2. **Header/auth checks:** SPF/DKIM/DMARC results, return‑path vs. from, domain age/look‑alike.
3. **Reputation (passive):** Hash/URL/domain with internal TI → only sandbox if policy allows & needed.
4. **Scope quickly:** who else received it? any **clicks**? any **credential submission**?
5. **Assign severity** (matrix below) and proceed to containment.

---

## Severity Matrix (decide & act)

| Level      | Triggers                                                                                                           | Immediate Actions                                                                                                                                   |
| ---------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **High**   | Credential harvest page + **clicks/submissions**; malware attachment **executed**; VIP/BEC themes; many recipients | **Purge** tenant‑wide, **block** sender/URL/domain, **reset password** + **revoke sessions**, **isolate endpoint** if executed, notify stakeholders |
| **Medium** | Clicks but no confirmed submission/execution; strong phish indicators                                              | Purge, block sender/URL/domain, notify recipients, monitor sign‑ins                                                                                 |
| **Low**    | No clicks; benign marketing or simulation                                                                          | Close with user education, no purge needed                                                                                                          |

---

## Containment Actions

**Mail:** Search & **purge** the message across all mailboxes; add sender/domain/URL to **blocklists**; tighten/repair transport rules if needed.
**Identity (if creds at risk):** Force **password reset**, **revoke refresh tokens**, **sign‑out everywhere**, enforce/re‑register **MFA**; monitor **SigninLogs** for risky sign‑ins.
**Endpoint (if attachment executed):** **Isolate** host via EDR; run on‑demand scan; remove dropped files/persistence (tasks/services/Run keys).
**Network:** Short‑TTL blocks for malicious domains/IPs seen in campaign.

---

## Evidence to Capture (for ticket/report)

* NetworkMessageId, sender address/domain/IP, recipients count, subject
* URLs/domains, attachment names + **SHA‑256**
* Delivery/visibility timeline (first/last seen), # delivered/# purged, # clicks/# submissions
* Actions taken (purge counts, blocks, resets, isolates) and approvals

---

## User & Stakeholder Communications

* **Recipients:** “A malicious email was removed from your mailbox. Do not engage with similar messages. If you entered credentials, change your password immediately and report to IT.”
* **Reporter:** Thank them; reinforce correct reporting behavior.
* **Stakeholders:** Brief summary (scope, impact, actions, residual risk, next steps).

---

## Common False Positives

* Legit marketing newsletters failing SPF/DMARC due to misconfig
* Internal testing/simulations (KnowBe4) — verify campaign IDs
* Shared cloud storage links (Google/Microsoft) with scary wording but legit sender

---

## Post‑Incident Tasks

* Remove malicious **inbox rules** / forwarding; fix exceptions that allowed delivery
* Add IOCs to watchlists/blocklists; tune detections for the observed pattern
* Enroll clickers/submitters in **targeted awareness (e.g., KnowBe4 remedials)**
* Update metrics: MTTA, time‑to‑purge, click rate, submit rate, FP rate

---

## ATT\&CK Mapping (use as applicable)

* **TA0001 Initial Access:** T1566 (Phishing) — .001 Attachment, .002 Link, .003 Service
* **TA0006 Credential Access:** T1056.007 (Web Forms), T1556 (Modify Authentication Process) when MFA/social engineering involved
* **TA0002 Execution:** T1204 (User Execution) for attachment/script execution
* **TA0005 Defense Evasion:** T1564.008 (Email Forwarding Rule), T1027 (Obfuscated/Encoded Content)
* **TA0009 Collection / TA0010 Exfiltration:** T1114 (Email Collection), T1041 (Exfiltration Over Web Services/C2)

---

## Quick‑Copy Hunts (Microsoft 365 Defender AH)

**Delivered suspicious mail with URLs (last 24h):**

```
let w = 24h;
EmailEvents
| where Timestamp >= ago(w)
| join kind=leftouter EmailUrlInfo on NetworkMessageId
| project Timestamp, NetworkMessageId, RecipientEmailAddress, SenderFromDomain, Subject, Url, UrlDomain, DeliveryAction
| order by Timestamp desc
```

**Who clicked those URLs:**

```
UrlClickEvents
| where Timestamp >= ago(24h)
| where UrlDomain in (EmailUrlInfo | where Timestamp >= ago(24h) | project UrlDomain)
| project Timestamp, UserId, ClickAction, UrlDomain, Url
| order by Timestamp desc
```

**Inbox rule creation/changes (possible BEC):**

```
OfficeActivity
| where TimeGenerated >= ago(7d)
| where Operation in ("New-InboxRule","Set-InboxRule")
| where Parameters has_any ("forward","redirect","delete","markasread")
| project TimeGenerated, UserId, Operation, Parameters
```

**Risky sign‑ins after suspected credential post:**

```
SigninLogs
| where TimeGenerated >= ago(48h)
| where UserPrincipalName in (/* impacted users */)
| summarize by UserPrincipalName, Location=LocationDetails, IPAddress, ResultType, TimeGenerated
| order by TimeGenerated desc
```

**Attachment execution indicator (endpoint):**

```
DeviceProcessEvents
| where Timestamp >= ago(24h)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| where ProcessCommandLine has_any (".vbs",".js","powershell","wscript","cmd /")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

---

## Close Criteria

* Malicious emails purged, blocks in place, impacted identities/devices secured
* No residual signs of access/malware in the last 24–48h
* Ticket contains artifacts, timeline, actions, and notifications

**Owner:** *SOC KB Maintainer*
**Last Updated:** *<fill date>*
**Related:** *Phishing Incident Response Playbook*, *Account Compromise Playbook*

# Microsoft Sentinel + Defender XDR SIEM/SOAR Lab

## Lab Title

**Unified Security Operations with Microsoft Sentinel, Microsoft Defender XDR, SIEM Analytics and SOAR Automation**

## Duration

**2.5–3 hours**

## Audience

Security analysts, SOC engineers, cloud security engineers, MSSP analysts, Microsoft security students, and Microsoft Sentinel beginners/intermediate users.

---

## Scenario

You are working as a SOC analyst for an organization using **Microsoft Sentinel** as its SIEM and **Microsoft Defender XDR** as its XDR platform.

A suspicious sign-in activity is detected from an unusual location. Shortly after, the same user performs risky cloud activity.

Your task is to:

1. Connect security data sources.
2. Investigate logs using KQL.
3. Create a Microsoft Sentinel analytics rule.
4. Generate an incident.
5. Investigate the incident.
6. Create a SOAR playbook.
7. Automate incident response using an automation rule.
8. Document the SOC analyst actions.

---

## Learning Objectives

By the end of this lab, participants will be able to:

- Understand how Microsoft Sentinel works as a cloud-native SIEM.
- Understand how Microsoft Defender XDR contributes XDR incidents and alerts.
- Use KQL to hunt for suspicious activity.
- Create a scheduled analytics rule in Microsoft Sentinel.
- Generate and investigate a Sentinel incident.
- Create a SOAR playbook with Azure Logic Apps.
- Trigger a playbook automatically using a Sentinel automation rule.
- Perform basic incident triage and response.

---

## Lab Architecture

### Components

- Microsoft Sentinel
- Log Analytics Workspace
- Microsoft Defender XDR
- Microsoft Entra ID logs
- Microsoft Sentinel analytics rules
- Microsoft Sentinel incidents
- Azure Logic Apps
- Microsoft Sentinel automation rules
- Email or Microsoft Teams notification for SOAR response

### Attack Flow

```text
Suspicious sign-in activity
        ↓
Logs ingested into Microsoft Sentinel
        ↓
KQL query detects suspicious behavior
        ↓
Analytics rule creates an incident
        ↓
Automation rule triggers SOAR playbook
        ↓
SOC notification is sent
        ↓
Analyst investigates and responds
```

---

## Prerequisites

### Required Access

Participants should have access to:

- Azure subscription
- Microsoft Sentinel enabled on a Log Analytics Workspace
- Contributor or Microsoft Sentinel Contributor permissions
- Logic App Contributor permissions
- Microsoft Entra ID logs connected to Microsoft Sentinel

### Optional Access

For the XDR section, the environment may also include:

- Microsoft Defender XDR portal access
- Microsoft Defender for Endpoint
- Microsoft Defender for Office 365
- Microsoft Defender for Identity
- Microsoft Defender for Cloud Apps
- Microsoft Defender XDR connector enabled in Microsoft Sentinel

> **Trainer Note:**  
> If participants do not have full tenant permissions, run the Defender XDR section as a demo and allow participants to complete the SIEM/SOAR section with Microsoft Sentinel logs only.

---

## Part 1 — Open Microsoft Sentinel

1. Go to the Azure Portal.
2. Search for **Microsoft Sentinel**.
3. Select your Microsoft Sentinel workspace.
4. Open the workspace overview page.

---

## Part 2 — Verify Data Connectors

Go to:

```text
Microsoft Sentinel > Content management > Content hub
```

Install the following solutions if available:

- Microsoft Entra ID
- Microsoft Defender XDR
- Microsoft Defender for Cloud
- Microsoft Sentinel Training Lab Solution

Then go to:

```text
Microsoft Sentinel > Configuration > Data connectors
```

Verify that at least one of the following connectors is active:

- Microsoft Entra ID
- Microsoft Defender XDR
- Azure Activity
- Microsoft Defender for Cloud
- Office 365

---

## Part 3 — SIEM Log Investigation with KQL

### Objective

Use KQL to search for suspicious sign-in behavior.

---

### Step 1 — Check Sign-in Logs

Go to:

```text
Microsoft Sentinel > Logs
```

Run:

```kql
SigninLogs
| take 10
```

If there are no results, try:

```kql
AADNonInteractiveUserSignInLogs
| take 10
```

---

### Step 2 — Detect Failed Sign-in Attempts

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, AppDisplayName
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

### Expected Result

The query shows users with multiple failed sign-in attempts in the last 24 hours.

### Analyst Question

Which users had repeated failed sign-ins?

---

### Step 3 — Detect Successful Sign-in After Failures

```kql
let FailedSignins =
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts >= 5;
let SuccessfulSignins =
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| project SuccessTime = TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location;
FailedSignins
| join kind=inner SuccessfulSignins on UserPrincipalName, IPAddress
| project SuccessTime, UserPrincipalName, IPAddress, AppDisplayName, Location, FailedAttempts
| order by SuccessTime desc
```

### Expected Result

The query identifies accounts where multiple failures were followed by a successful sign-in from the same IP address.

### Analyst Question

Could this indicate password spraying, brute force activity, or successful account compromise?

---

## Part 4 — Create a Microsoft Sentinel Analytics Rule

### Objective

Create a scheduled analytics rule that generates an incident when suspicious sign-in activity is detected.

---

### Step 1 — Create Rule

Go to:

```text
Microsoft Sentinel > Configuration > Analytics
```

Select:

```text
Create > Scheduled query rule
```

---

### Rule Details

| Setting | Value |
|---|---|
| Name | Suspicious Sign-in: Multiple Failures Followed by Success |
| Description | Detects users with multiple failed sign-in attempts followed by a successful sign-in from the same IP address. |
| Severity | Medium |
| MITRE ATT&CK Tactics | Initial Access, Credential Access |
| MITRE ATT&CK Techniques | T1110 — Brute Force, T1078 — Valid Accounts |

---

### Rule Query

```kql
let FailedSignins =
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts >= 5;
let SuccessfulSignins =
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| project SuccessTime = TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location;
FailedSignins
| join kind=inner SuccessfulSignins on UserPrincipalName, IPAddress
| project SuccessTime, UserPrincipalName, IPAddress, AppDisplayName, Location, FailedAttempts
```

---

### Query Scheduling

| Setting | Value |
|---|---|
| Run query every | 5 minutes |
| Lookup data from the last | 1 hour |
| Alert threshold | Generate alert when number of query results is greater than 0 |

---

### Incident Settings

Enable:

```text
Create incidents from alerts triggered by this analytics rule
```

---

### Entity Mapping

#### Account Entity

| Identifier | Value |
|---|---|
| Account Name or UPN | UserPrincipalName |

#### IP Entity

| Identifier | Value |
|---|---|
| Address | IPAddress |

---

### Save the Rule

Select:

```text
Review + create
```

Then select:

```text
Create
```

---

## Part 5 — Generate or Simulate an Incident

### Option A — Use Real Logs

Wait for the analytics rule to run.

Then go to:

```text
Microsoft Sentinel > Threat management > Incidents
```

Look for an incident named:

```text
Suspicious Sign-in: Multiple Failures Followed by Success
```

---

### Option B — Use Demo Query for Training

If the environment has no sign-in logs, use the following demo KQL:

```kql
let DemoSigninLogs = datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    AppDisplayName:string,
    Location:string
)
[
    ago(50m), "alex@contoso.com", "185.10.10.10", 50126, "Office 365", "Unknown",
    ago(45m), "alex@contoso.com", "185.10.10.10", 50126, "Office 365", "Unknown",
    ago(40m), "alex@contoso.com", "185.10.10.10", 50126, "Office 365", "Unknown",
    ago(35m), "alex@contoso.com", "185.10.10.10", 50126, "Office 365", "Unknown",
    ago(30m), "alex@contoso.com", "185.10.10.10", 50126, "Office 365", "Unknown",
    ago(20m), "alex@contoso.com", "185.10.10.10", 0, "Office 365", "Unknown"
];
let FailedSignins =
DemoSigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts >= 5;
let SuccessfulSignins =
DemoSigninLogs
| where ResultType == 0
| project SuccessTime = TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location;
FailedSignins
| join kind=inner SuccessfulSignins on UserPrincipalName, IPAddress
| project SuccessTime, UserPrincipalName, IPAddress, AppDisplayName, Location, FailedAttempts
```

---

## Part 6 — Incident Investigation

### Objective

Investigate the generated incident like a SOC analyst.

---

### Step 1 — Open the Incident

Go to:

```text
Microsoft Sentinel > Threat management > Incidents
```

Open the suspicious sign-in incident.

Review:

- Severity
- Status
- Owner
- Entities
- Alerts
- Tactics and techniques
- Timeline
- Related events

---

### Step 2 — Assign the Incident

Set:

| Field | Value |
|---|---|
| Owner | Your analyst account |
| Status | Active |
| Tag | Identity Threat |

---

### Step 3 — Investigate the Account Entity

Open the user entity and review:

- User principal name
- Recent sign-ins
- IP addresses
- Related alerts
- Related incidents

---

### Step 4 — Investigate the IP Entity

Open the IP entity and review:

- Number of sign-in attempts
- Associated accounts
- Location
- Related incidents
- Threat intelligence enrichment, if available

---

### Analyst Notes Template

```text
Incident Summary:
Multiple failed sign-in attempts were followed by a successful sign-in.

Affected User:
<user principal name>

Source IP:
<IP address>

Potential Threat:
Credential attack, password spraying, brute force, or compromised account.

Recommended Action:
Reset user password, revoke sessions, require MFA, review risky sign-ins, and monitor follow-up activity.
```

---

## Part 7 — XDR Investigation

### Objective

Understand how Microsoft Defender XDR contributes incidents and alerts to the unified SOC workflow.

---

### Step 1 — Open Microsoft Defender Portal

Go to:

```text
https://security.microsoft.com
```

Navigate to:

```text
Incidents & alerts > Incidents
```

---

### Step 2 — Review Defender XDR Incidents

Look for incidents related to:

- Suspicious sign-in
- Impossible travel
- Malicious inbox rule
- Malware detection
- Endpoint compromise
- Suspicious OAuth app
- Risky user activity

---

### Step 3 — Compare XDR and SIEM Data

Compare the Microsoft Defender XDR incident with the Microsoft Sentinel incident.

Review:

- Incident title
- Affected users
- Devices
- Mailboxes
- IP addresses
- Alerts
- Evidence
- Investigation graph
- Recommended actions

---

### Discussion

Microsoft Sentinel provides the SIEM layer for collecting and correlating data from many sources.

Microsoft Defender XDR provides the XDR layer for correlating security signals across Microsoft security products.

Together, they help the SOC investigate identity, endpoint, email, cloud app, and infrastructure activity from a unified incident queue.

---

## Part 8 — Create a SOAR Playbook

### Objective

Create a Logic App playbook that sends a notification when a Microsoft Sentinel incident is created.

---

### Step 1 — Create a Logic App

Go to:

```text
Azure Portal > Create a resource > Logic App
```

Use:

| Setting | Value |
|---|---|
| Logic App type | Consumption |
| Resource group | Same as Microsoft Sentinel workspace |
| Region | Same or closest region |
| Name | Notify-SOC-On-Sentinel-Incident |

Create the Logic App.

---

### Step 2 — Open Logic App Designer

Open the Logic App and select:

```text
Logic app designer
```

Choose:

```text
Blank Logic App
```

---

### Step 3 — Add Microsoft Sentinel Trigger

Search for:

```text
Microsoft Sentinel
```

Select the trigger:

```text
When a response to a Microsoft Sentinel incident is triggered
```

Sign in and authorize the connection.

---

### Step 4 — Add Email Notification Action

Add a new step.

Search for:

```text
Office 365 Outlook
```

Select:

```text
Send an email (V2)
```

Configure:

| Field | Value |
|---|---|
| To | soc@contoso.com |
| Subject | New Microsoft Sentinel Incident: `<Incident title>` |

Body:

```text
A new Microsoft Sentinel incident has been created.

Incident Title: <Incident title>
Severity: <Severity>
Status: <Status>
Incident URL: <Incident URL>

Please review and begin triage.
```

Use dynamic content from the Microsoft Sentinel incident trigger where available.

---

### Optional Microsoft Teams Notification

Instead of email, use Microsoft Teams:

```text
Post message in a chat or channel
```

Example message:

```text
New Microsoft Sentinel incident detected.

Title: <Incident title>
Severity: <Severity>
Owner: <Owner>
URL: <Incident URL>
```

---

### Step 5 — Save the Playbook

Select:

```text
Save
```

---

## Part 9 — Create an Automation Rule

### Objective

Automatically trigger the SOAR playbook when the suspicious sign-in incident is created.

---

### Step 1 — Open Automation Rules

Go to:

```text
Microsoft Sentinel > Configuration > Automation
```

Select:

```text
Create > Automation rule
```

---

### Step 2 — Configure Rule

| Setting | Value |
|---|---|
| Name | Notify SOC for Suspicious Sign-in Incidents |
| Trigger | When incident is created |
| Condition | Analytics rule name equals `Suspicious Sign-in: Multiple Failures Followed by Success` |
| Action | Run playbook: `Notify-SOC-On-Sentinel-Incident` |

Optional actions:

- Change status to **Active**
- Assign owner
- Add tag: **Identity Threat**

---

### Step 3 — Save the Automation Rule

Select:

```text
Apply
```

---

## Part 10 — Test the SOAR Flow

### Objective

Confirm that the automation rule triggers the playbook.

---

### Test Steps

1. Wait for the analytics rule to create an incident.
2. Open the incident.
3. Confirm the incident has the correct tag.
4. Confirm that the playbook ran successfully.
5. Confirm that the SOC email or Teams message was received.

---

### Validation Checklist

| Test | Expected Result | Status |
|---|---|---|
| Analytics rule runs | Rule executes successfully | Pass/Fail |
| Incident created | New incident appears in Sentinel | Pass/Fail |
| Entity mapping works | Account and IP entities are visible | Pass/Fail |
| Automation rule triggers | Automation rule runs on incident creation | Pass/Fail |
| Playbook executes | Logic App run succeeds | Pass/Fail |
| Notification sent | Email or Teams message received | Pass/Fail |

---

## Part 11 — Analyst Response Actions

After investigation, the analyst should document response actions.

### Recommended Manual Response

For identity-based suspicious activity:

1. Reset the user password.
2. Revoke active sessions.
3. Require MFA registration or re-registration.
4. Review risky sign-ins.
5. Review user mailbox rules.
6. Review OAuth app consent.
7. Review recent file access.
8. Check if the source IP targeted other users.
9. Escalate if lateral movement is suspected.

---

### Incident Closure

Set:

| Field | Value |
|---|---|
| Status | Closed |
| Classification | True positive |
| Reason | Suspicious activity |

Closing comment:

```text
Suspicious sign-in activity was detected and investigated. The affected account was reviewed, recommended identity response actions were performed, and no further malicious activity was confirmed at this stage.
```

---

## Bonus Challenge — Add Enrichment

### Objective

Improve the playbook with enrichment.

Add one or more of the following actions:

- Get IP geolocation.
- Check IP against threat intelligence.
- Add comment to incident.
- Add tag based on severity.
- Send high-severity incidents to Teams.
- Create a ticket in ServiceNow or Jira.
- Notify SOC manager for high-severity incidents.

---

### Example Enriched SOAR Logic

```text
If severity equals High:
    Add tag: High Priority
    Send Teams alert to SOC channel
    Send email to SOC manager
Else:
    Send standard SOC notification
```

---

## Bonus KQL Hunting Queries

### Query 1 — Multiple Users Targeted by Same IP

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize TargetedUsers = dcount(UserPrincipalName), Attempts = count() by IPAddress
| where TargetedUsers >= 5 and Attempts >= 20
| order by TargetedUsers desc
```

---

### Query 2 — Successful Sign-in from New Country

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| summarize Countries = make_set(Location), Count = count() by UserPrincipalName
| where array_length(Countries) > 1
| order by Count desc
```

---

### Query 3 — Risky Sign-ins

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where RiskLevelAggregated != "none"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, RiskLevelAggregated, RiskState, Location
| order by TimeGenerated desc
```

---

### Query 4 — Azure Activity by Suspicious User

```kql
AzureActivity
| where TimeGenerated > ago(24h)
| summarize Operations = count() by Caller, OperationNameValue, ActivityStatusValue
| order by Operations desc
```

---

### Query 5 — Security Alerts from Defender XDR

```kql
SecurityAlert
| where TimeGenerated > ago(24h)
| summarize Alerts = count() by ProductName, AlertName, Severity
| order by Alerts desc
```

---

## Final Lab Questions

1. What suspicious behavior did the analytics rule detect?
2. Which user account was involved?
3. Which IP address was involved?
4. Was the activity likely brute force, password spraying, or normal user behavior?
5. What evidence supports your conclusion?
6. Did the SOAR playbook execute successfully?
7. What manual actions should the SOC analyst perform?
8. How could this detection be improved?
9. How could automation reduce analyst workload?
10. How does Defender XDR improve the investigation compared with SIEM logs alone?

---

## Expected Outcome

At the end of the lab, participants should have:

- Created a Microsoft Sentinel analytics rule.
- Used KQL for SIEM detection.
- Generated or reviewed a Microsoft Sentinel incident.
- Investigated account and IP entities.
- Reviewed Microsoft Defender XDR incident context.
- Created an Azure Logic Apps SOAR playbook.
- Created an automation rule to trigger the playbook.
- Completed a basic SOC investigation workflow.

---

## Instructor Notes

### Common Issue: No `SigninLogs` Data

Use the demo KQL or connect Microsoft Entra ID logs.

### Common Issue: Playbook Does Not Appear in Microsoft Sentinel

Check that:

- The Logic App was saved.
- The Microsoft Sentinel trigger was used.
- Permissions were granted.
- The playbook and Microsoft Sentinel workspace are in compatible resource scopes.
- The user has permission to run playbooks.

### Common Issue: Automation Rule Does Not Trigger

Check that:

- The rule is enabled.
- Conditions match the analytics rule name.
- Incident creation is enabled in the analytics rule.
- Playbook permissions are configured.

### Common Issue: No Defender XDR Incidents

Use this section as a demo or discussion if the tenant does not have Defender XDR licensing or active alerts.

---

## Lab Summary

This lab demonstrated a complete Microsoft security operations workflow:

```text
Data Collection
    ↓
KQL Detection
    ↓
Analytics Rule
    ↓
Incident Creation
    ↓
Investigation
    ↓
SOAR Automation
    ↓
Analyst Response
```

Microsoft Sentinel provides SIEM capabilities for log collection, detection, hunting, and incident management.

Microsoft Defender XDR provides correlated XDR detections across identity, endpoint, email, cloud apps, and Microsoft security signals.

SOAR automation with Azure Logic Apps helps the SOC respond faster, reduce manual work, and standardize incident handling.

---

## Suggested Repository Name

```text
sentinel-defender-xdr-siem-soar-lab
```

## Suggested GitHub Description

```text
A hands-on Microsoft Sentinel and Defender XDR lab covering SIEM detection, KQL hunting, incident investigation, and SOAR automation with Azure Logic Apps.
```

## Suggested Tags

```text
microsoft-sentinel
defender-xdr
siem
soar
kql
azure-security
logic-apps
soc
cybersecurity
```

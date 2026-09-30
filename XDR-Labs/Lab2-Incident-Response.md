# 🧪 Lab 2: Incident Response & Automation in Microsoft Sentinel  

---

## 🎯 Objective  
This lab teaches you how to **investigate and respond to security incidents** in **Microsoft Sentinel** using **Microsoft Defender XDR** integrations, Logic App playbooks, and automated remediation.  

You will learn to perform incident triage, run playbooks, correlate alerts across Defender products, and automate response workflows.

---

## 🧰 Prerequisites  
Before starting, ensure you have:  
- A **Microsoft Sentinel workspace** connected to:  
  - Microsoft 365 Defender  
  - Microsoft Defender for Endpoint  
  - Microsoft Defender for Office 365  
  - Microsoft Entra ID logs  
- At least one incident generated (from *Lab 1 – Detecting Phishing* or another analytics rule).  
- Permissions: *Sentinel Responder*, *Security Reader*, or *Contributor*.  
- Logic Apps enabled in your subscription.  

---

## 🧩 Step 1: Understand Sentinel Incidents  

1. Go to **Microsoft Sentinel → Incidents**.  
2. Select an active incident (e.g., phishing, risky sign-in, or malware detection).  
3. Review the following tabs:
   - **Overview:** Displays severity, status, and entities (users, hosts, IPs).  
   - **Entities:** Lists accounts, devices, and IPs associated with the incident.  
   - **Investigate:** Opens a visual investigation graph for root-cause analysis.  
4. Observe how Sentinel correlates alerts from multiple data sources (Defender for Endpoint, Office 365, etc.) into a unified incident.

> 💡 *Each incident is an aggregation of correlated alerts and entities — allowing SOC teams to see the full attack kill chain.*

---

## 🔍 Step 2: Perform Manual Investigation  

Use Sentinel’s **Investigation Graph** and **Logs** to explore the incident.

### 1️⃣ Open Investigation Graph  
1. From the incident view, click **Investigate**.  
2. Expand the graph nodes:
   - Click on the **User** entity to view related sign-ins or devices.  
   - Click on the **Device** entity to view Defender alerts.  
3. Identify potential lateral movement or privilege escalation.

### 2️⃣ Query Related Logs  
Run the following queries in **Logs** to get context:  

**User Sign-in History**
```kql
SigninLogs
| where UserPrincipalName == "<affected-user>"
| order by TimeGenerated desc
```

**Device Alert Summary**
```kql
SecurityAlert
| where Entities has "<device-name>"
| summarize count() by AlertName, Severity
| order by count_ desc
```

**Email Correlation (if phishing-related)**
```kql
EmailEvents
| where RecipientEmailAddress == "<affected-user>"
| project TimeGenerated, SenderFromAddress, Subject, ThreatTypes
```

✅ **Goal:** Identify initial compromise vector, affected assets, and potential spread.

---

## 🚨 Step 3: Assign and Manage Incidents  

Effective incident management ensures accountability and tracking.  

1. Go to **Microsoft Sentinel → Incidents → [Select Incident]**.  
2. Click **Assign → [Your Name or SOC Analyst]**.  
3. Change **Status** to:
   - *Active* – under investigation  
   - *In Progress* – mitigation ongoing  
   - *Resolved* – response completed  
4. Add **Tags** (e.g., `Phishing`, `Credential Access`, `Automation`).  
5. Document your findings in **Comments**.  

> 🧠 *Tags and comments are key for collaboration and audit tracking.*

---

## ⚙️ Step 4: Automate Response with Playbooks  

You can automatically respond to incidents using Logic Apps playbooks connected to Sentinel.  

### 🧩 Recommended Playbooks  
- **Auto-Isolate-Device.json** → Isolates compromised endpoint via Defender for Endpoint.  
- **Alert-to-Teams.json** → Notifies your SOC or IT channel in Microsoft Teams.  
- **Close-LowSeverity.json** → Automatically closes false positives or low-impact alerts.  

### ⚙️ How to Attach Playbooks  
1. In the **Incident details** pane, select **Automation → + Add new automation rule**.  
2. Define:  
   - **Trigger:** *When incident is created*  
   - **Condition:** *Severity = High or Medium*  
   - **Action:** *Run playbook (choose from list)*  
3. Save and test with an existing or new incident.  

> ⚡ Automation rules run instantly when incidents meet the specified criteria.

---

## 🤖 Step 5: Run On-Demand Response from the Incident Page  

You can manually trigger playbooks during investigation for targeted response:  

1. From the incident view, click **View full details**.  
2. Select the **Playbooks** tab.  
3. Choose the desired playbook (e.g., *Auto-Isolate Device*) → click **Run**.  
4. Verify in **Logic Apps → Runs history** that the automation executed successfully.  

Example outcome:
- The affected endpoint is isolated in Defender for Endpoint.  
- The SOC receives a Teams notification with alert summary and incident link.  

---

## 🔄 Step 6: Correlate Alerts Across Microsoft Defender XDR  

1. Go to the **Microsoft 365 Defender portal** ([security.microsoft.com](https://security.microsoft.com)).  
2. Under **Incidents & Alerts**, find the same incident ID that appeared in Sentinel.  
3. Compare data between Sentinel and Defender:
   - Alerts correlated across **Email**, **Identity**, and **Device** signals.  
   - Unified timeline showing attacker steps (compromise → persistence → exfiltration).  
4. Confirm that Sentinel correctly synchronized data via the **Microsoft 365 Defender connector**.

> 🧩 Sentinel uses Defender XDR’s incident fusion engine — combining multiple signals into a single view.

---

## 📊 Step 7: Build an Incident Response Workbook  

You can visualize active incidents and automation activity with a Sentinel workbook.

### Create Workbook Queries

**Active Incidents by Severity**
```kql
SecurityIncident
| summarize Count = count() by Severity
| render piechart
```

**Incidents Over Time**
```kql
SecurityIncident
| summarize Count = count() by bin(TimeGenerated, 1d)
| render timechart
```

**Automation Runs**
```kql
AzureDiagnostics
| where Category == "WorkflowRuntime"
| summarize Count = count() by bin(TimeGenerated, 1h)
| render columnchart
```

Save as **“Incident Response Overview”** and share with your SOC team.

---

## 🧩 Step 8: Validate the End-to-End Response Flow  

To confirm everything works:
1. Trigger a simulated alert or re-run **Lab 1** phishing scenario.  
2. Verify Sentinel creates a new incident.  
3. Ensure your playbooks trigger automatically (Teams message or isolation).  
4. Check that incident status updates and comments are logged.  

🎯 *Goal:* Confirm full automation, from detection → investigation → response.

---

## 🧹 Step 9: Cleanup  

When finished:  
- Disable test automation rules.  
- Delete test playbooks or test incidents.  
- Review Logic App run logs and metrics to verify automation performance.  

---

## 🧠 Learning Outcomes  

By completing this lab, you will:  
✅ Understand **Sentinel incident lifecycle management**.  
✅ Investigate incidents using **KQL, Entities, and the Investigation Graph**.  
✅ Automate responses using **Logic Apps playbooks**.  
✅ Correlate alerts with **Microsoft Defender XDR** for unified visibility.  
✅ Create **Incident Response dashboards** and improve SOC efficiency.

---

## 📚 References  
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/azure/sentinel/)  
- [Microsoft Defender XDR Overview](https://learn.microsoft.com/microsoft-365/security/defender/)  
- [Automate responses with Playbooks](https://learn.microsoft.com/azure/sentinel/tutorial-respond-threats-playbook)  
- [KQL Reference](https://learn.microsoft.com/azure/data-explorer/kusto/query/)  
- [Microsoft 365 Defender Portal](https://security.microsoft.com)  

---

## ✅ Next Lab  
Proceed to **[Lab 3 – Threat Hunting with KQL](Lab3-Threat-Hunting.md)**  
Learn how to proactively hunt for adversary behavior using advanced KQL queries and Microsoft Defender telemetry.

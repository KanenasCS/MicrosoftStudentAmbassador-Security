# 🧪 Lab 1: Detecting Phishing in Microsoft Sentinel  

---

## 🎯 Objective  
This lab guides you through detecting, investigating, and responding to **phishing attacks** using **Microsoft Sentinel** and **Microsoft Defender XDR**.  
You will simulate a phishing attempt, analyze email and sign-in logs, create detections, and build automated responses using Logic Apps.

---

## 🧰 Prerequisites  
Before starting this lab, make sure you have:  

- A **Microsoft Sentinel workspace** connected to:
  - Microsoft 365 Defender  
  - Microsoft Defender for Office 365  
  - Microsoft Entra ID (formerly Azure AD)  
- Permissions: *Contributor* or *Security Administrator* role in Sentinel.  
- A test user in Microsoft 365 to receive simulated phishing emails.  
- Logic Apps enabled in your subscription (for automation).  

Optional but recommended:  
- A **Microsoft 365 E5 Developer subscription** with access to Defender and Sentinel.  
- Attack Simulation Training enabled in Microsoft Defender for Office 365.  

---

## 🧩 Step 1: Simulate a Phishing Event  

1. Go to the [Microsoft 365 Defender portal](https://security.microsoft.com).  
2. Navigate to **Email & Collaboration → Attack Simulation Training**.  
3. Select **Launch a simulation → Credential Harvest**.  
4. Choose a phishing template (e.g., “Security Alert – Action Required”).  
5. Send it to one or more test users.  
6. Wait 5–10 minutes for telemetry to appear in Sentinel.  

> 💡 *If you don’t have Attack Simulator access, you can import test email logs via CSV or use Sentinel’s demo data.*

---

## 🔍 Step 2: Analyze Email Logs in Microsoft Sentinel  

Now that your phishing simulation is complete, it’s time to explore the logs in Microsoft Sentinel.  

1. Go to your **Sentinel workspace → Logs**.  
2. Run the following **KQL query** to identify phishing detections:  

```kql
EmailEvents
| where ThreatTypes has "Phish"
| extend Sender = SenderFromAddress, Recipient = RecipientEmailAddress
| project TimeGenerated, Sender, Recipient, Subject, ThreatTypes, DeliveryLocation, DetectionMethods
| order by TimeGenerated desc
```

### ✅ Expected Result
A table listing phishing detections, showing sender, recipient, subject, and threat classification.  

**Interpretation:**  
If you see multiple phishing detections for the same sender, it indicates a potential targeted campaign.  

---

## 🚨 Step 3: Correlate Phishing Emails with User Sign-ins  

To investigate possible compromises, you can correlate phishing events with risky user sign-ins.  

Run this **KQL correlation query**:  

```kql
let PhishedUsers = EmailEvents
    | where ThreatTypes has "Phish"
    | distinct RecipientEmailAddress;
SigninLogs
| where UserPrincipalName in (PhishedUsers)
| where RiskLevelDuringSignIn in ("medium", "high") or ConditionalAccessStatus == "failure"
| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn, ConditionalAccessStatus
| order by TimeGenerated desc
```

### ✅ Expected Result  
A list of users who received phishing emails and subsequently triggered risky or failed sign-ins.  

**Interpretation:**  
These users may have entered credentials into phishing forms or had credentials reused by attackers.

---

## ⚙️ Step 4: Create a Detection Rule  

Let’s convert the above query into an automated analytics rule.  

1. In Sentinel, navigate to **Analytics → + Create → Scheduled query rule**.  
2. Rule name: `Detect Phished Users with Risky Sign-ins`.  
3. Description: `Detects users who received phishing emails and later performed risky sign-ins.`  
4. Paste the KQL query from Step 3.  
5. Set the **query frequency** to 1 hour and the **lookback period** to 24 hours.  
6. Set **alert threshold:** greater than 0 results.  
7. Assign **Severity:** High.  
8. Set **MITRE tactics:**  
   - *Initial Access*  
   - *Credential Access*  
9. Enable the rule and save it.  

> 🔔 The rule now automatically generates an incident whenever a phishing-related risky sign-in is detected.

---

## 🔁 Step 5: Automate Response with Playbooks  

Automation helps SOC teams react faster. You can attach **Logic Apps playbooks** to this rule.  

### 🔧 Playbook 1: Auto-Isolate Device  
Uses Defender for Endpoint to isolate the compromised machine automatically.  
- File: `/Playbooks/Auto-Isolate-Device.json`  
- Trigger: *When incident is created*  
- Action: `POST /machines/{id}/isolate` in Defender for Endpoint API.  

### 🔧 Playbook 2: Alert-to-Teams  
Sends a Teams message to your SOC channel when a new incident is generated.  
- File: `/Playbooks/Alert-to-Teams.json`  
- Trigger: *When incident is created*  
- Action: Sends adaptive card to Teams with alert details.  

#### 🪄 How to Import
1. Go to **Logic Apps → Add → Import from JSON**.  
2. Paste the content of either playbook JSON file.  
3. Configure connections:
   - Sentinel API connection  
   - Microsoft Teams connector  
   - Defender for Endpoint connector  
4. Save and test with a sample incident.  

> ⚠️ Always test playbooks in a **non-production workspace** before linking to live detections.

---

## 📊 Step 6: Build a Phishing Detection Workbook  

Workbooks help visualize phishing trends and user risk over time.

### Create the Workbook
1. Go to **Microsoft Sentinel → Workbooks → + Add workbook**.  
2. Click **Edit → Add query**.  
3. Add the following **visual queries**:  

**1️⃣ Phishing Detection Trend**
```kql
EmailEvents
| where ThreatTypes has "Phish"
| summarize Count = count() by bin(TimeGenerated, 1d)
| render timechart
```

**2️⃣ Top Targeted Users**
```kql
EmailEvents
| where ThreatTypes has "Phish"
| summarize Count = count() by RecipientEmailAddress
| top 10 by Count
```

**3️⃣ Risky Sign-ins After Phishing**
```kql
SigninLogs
| where RiskLevelDuringSignIn in ("medium", "high")
| summarize Count = count() by UserPrincipalName
| top 10 by Count
```

4. Save the workbook as **“Phishing Detection Overview.”**  

You can now monitor phishing activity, top targeted users, and post-phish sign-in risk in real time.  

---

## 🧠 Step 7: Validate and Simulate End-to-End Flow  

Perform an end-to-end validation of your setup:  
1. Send another phishing simulation to a test user.  
2. Verify it appears in **EmailEvents**.  
3. Confirm that the analytics rule triggers a new incident.  
4. Check that your playbooks execute automatically:
   - The Teams channel receives an alert card.  
   - Defender for Endpoint isolates the compromised device.  

🎉 **Result:** You’ve successfully built an end-to-end phishing detection and response pipeline using Microsoft Sentinel and XDR.

---

## 🧩 Step 8: Clean Up Resources  
After completing the lab:  
- Delete the test simulation campaigns in Defender.  
- Disable the analytics rule if you used a shared workspace.  
- Remove any test playbooks or connections you created.  

---

## 🧠 Learning Outcomes  

By completing this lab, you will be able to:  
✅ Detect phishing activity using **EmailEvents** data.  
✅ Correlate phishing detections with **SigninLogs**.  
✅ Build custom analytics rules in Microsoft Sentinel.  
✅ Automate responses using **Logic Apps playbooks**.  
✅ Visualize phishing trends and risky users through **workbooks**.  

---

## 📚 References  
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/azure/sentinel/)  
- [Microsoft Defender for Office 365](https://learn.microsoft.com/microsoft-365/security/office-365-security/)  
- [Microsoft 365 Defender Portal](https://security.microsoft.com/)  
- [KQL Reference Guide](https://learn.microsoft.com/azure/data-explorer/kusto/query/)  
- [Microsoft Security GitHub Repositories](https://github.com/Azure/Azure-Sentinel)

---

## ✅ Next Lab
Continue with **[Lab 2 – Incident Response & Automation](Lab2-Incident-Response.md)**  
Learn how to triage, investigate, and automate remediation workflows using **Microsoft Sentinel + Defender XDR**.

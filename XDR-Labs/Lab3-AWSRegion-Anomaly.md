# 🧪 Lab 3: AWS Region Anomaly Detection  

## 🎯 Objective  
This lab focuses on detecting **abnormal AWS API activity originating from unexpected or unauthorized regions** using **Microsoft Sentinel** integrated with **AWS CloudTrail**.  
Such anomalies can indicate potential credential misuse, insider threats, or compromised access keys operating outside approved regions.  

---

## 🧰 Prerequisites  
Before starting, ensure you have:  
- A **Microsoft Sentinel workspace** connected to **AWS CloudTrail** (via S3 connector or Data Collection Endpoint).  
- At least one **AWS account** with CloudTrail logging enabled for all regions.  
- Access to **AWS CLI** or the **AWS Console** for simulation.  
- An existing **Data Connector** ingesting CloudTrail logs into the **AWSCloudTrail** table.  
- Optional: Logic App access for automated response.  

---

## 🧩 Step 1: Simulate Multi-Region Activity  

In your AWS account, intentionally perform actions from regions not typically used by your organization (for example, simulate access from **ap-south-1**, **sa-east-1**, or **eu-north-1**).  

**Using AWS CLI Example:**  

##bash
Run commands from multiple regions
aws ec2 describe-instances --region ap-south-1
aws s3 ls --region sa-east-1
aws iam list-users --region eu-north-1

These actions generate CloudTrail logs showing API activity across multiple regions.

#🔍 Step 2: Detect Abnormal Region Access in Sentinel

In Microsoft Sentinel → Logs, run the following KQL query:

AWSCloudTrail
| extend Region = tostring(AWSRegion)
| summarize DistinctRegions = dcount(Region) by UserIdentityArn, bin(TimeGenerated, 1d)
| where DistinctRegions > 3
| project TimeGenerated, UserIdentityArn, DistinctRegions
| order by DistinctRegions desc


✅ Purpose:

Identifies AWS accounts performing operations in more than three distinct regions within a single day.
Highlights potential credential sharing or unauthorized geographic access.

#⚠️ Step 3: Investigate the Findings
Once suspicious region activity is detected:
Validate whether the regions are part of your organization’s approved list.
Review CloudTrail event names and source IPs for those sessions.
Check IAM roles, access keys, or temporary credentials used.
Cross-reference activity with Defender for Cloud or Defender for Cloud Apps for additional anomalies.

Example Investigation KQL:

AWSCloudTrail
| where UserIdentityArn == "arn:aws:iam::123456789012:user/DevOpsEngineer"
| project TimeGenerated, EventName, SourceIpAddress, AWSRegion, UserAgent
| order by TimeGenerated desc


This query gives detailed visibility into specific API actions from the suspicious user.

#🤖 Step 4: Automate Response (Optional)

Create a Sentinel Logic App playbook named Notify-AWSRegion-Anomaly.json that:
Sends a Microsoft Teams message or email to the SOC team.
Triggers an AWS Lambda function to temporarily disable access keys for the affected user.

Example Teams Notification Template:

#🚨 AWS Region Anomaly Detected
User: arn:aws:iam::123456789012:user/DevOpsEngineer
Regions Accessed: 6
Action: SOC Review Required

Example Logic App Flow:

Trigger: Sentinel Incident → AWS Region Anomaly
Condition: DistinctRegions > 3
Action: Post message to Teams channel
Optional: Call AWS Lambda to disable IAM keys

#📊 Step 5: Create a Workbook Visualization

Use Sentinel Workbooks to visualize multi-region AWS activity trends.
KQL for Workbook Visualization:

AWSCloudTrail
| summarize RegionCount = count() by AWSRegion
| sort by RegionCount desc
| render columnchart


This creates a bar chart showing the number of CloudTrail events per region, helping analysts easily identify abnormal regions with unexpected spikes.

🧠 Learning Outcomes
After completing this lab, you will be able to:
Ingest and normalize AWS CloudTrail logs into Microsoft Sentinel.
Detect AWS accounts performing operations from unauthorized or unusual regions.
Investigate region-based anomalies using KQL.
Automate SOC notifications and responses using Logic Apps.

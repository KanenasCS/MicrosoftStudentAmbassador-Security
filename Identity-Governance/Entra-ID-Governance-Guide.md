# 🧩 Entra ID Governance & Conditional Access Guide  

---

## 🎯 Objective  
This guide provides an overview of **Microsoft Entra ID Governance** features and explains how to implement **Conditional Access policies** for a secure identity posture.  

It supports your security baseline by ensuring least privilege, continuous access evaluation, and automated access reviews.

---

## 🔐 1. What Is Entra ID Governance?  

**Microsoft Entra ID Governance** provides tools to balance security and user productivity through:  
- **Access Reviews:** Regularly review user/group/app access.  
- **Entitlement Management:** Automate access package assignments and expirations.  
- **Lifecycle Workflows:** Automate joiner-mover-leaver processes.  
- **Privileged Identity Management (PIM):** Manage just-in-time (JIT) admin access.  

---

## 🧱 2. Core Governance Pillars  

| Pillar | Description | Microsoft Service |
|--------|--------------|-------------------|
| **Access Lifecycle** | Automate provisioning/deprovisioning | Entra ID + Lifecycle Workflows |
| **Access Policies** | Control session and sign-in context | Conditional Access |
| **Access Reviews** | Validate user access periodically | Entra Governance |
| **Privileged Access** | Manage high-privilege roles securely | PIM |
| **Auditing & Compliance** | Monitor and report access events | Audit Logs & Workbooks |

---

## ⚙️ 3. Implementing the Security Baseline  

Use the provided **ConditionalAccess-Security-Baseline.json** to deploy a security baseline policy in Entra ID.

### Policy Highlights  
- Enforces **MFA for all users**.  
- Blocks **legacy authentication**.  
- Excludes one **break-glass admin account**.  
- Limits sessions to **4 hours sign-in frequency**.  
- Requires **compliant or hybrid joined devices**.  

### Deployment Steps  
1. Go to the **Azure Portal → Entra ID → Security → Conditional Access**.  
2. Click **New policy → Import JSON**.  
3. Paste the content from `ConditionalAccess-Security-Baseline.json`.  
4. Review conditions and modify:
   - Replace `BreakGlassAdmin@domain.com` with your actual emergency account.  
   - Adjust **trusted IP ranges** if applicable.  
5. Save and enable the policy.  

> ⚠️ Always test new Conditional Access policies in **report-only mode** before enforcing them.

---

## 🧩 4. Integrating with Identity Governance  

Combine Conditional Access with Entra ID Governance capabilities for full lifecycle management:  

- Use **Access Packages** to bundle apps and groups with built-in approval workflows.  
- Schedule **Access Reviews** for privileged roles and guest users.  
- Use **Lifecycle Workflows** to revoke access automatically for leavers.  
- Integrate **PIM** to require MFA and justification for admin role activation.  

---

## 📊 5. Monitoring and Reporting  

Track Conditional Access and Governance performance using:  
- **Sign-in Logs:** View MFA prompts, blocked sessions, and risk levels.  
- **Audit Logs:** Record policy changes and assignments.  
- **Workbooks:** Build dashboards visualizing access reviews and PIM activations.  
- **Microsoft Graph API:** Automate reporting and access governance actions.  

---

## 🧠 Learning Outcomes  
By implementing this guide, you will:  
✅ Understand **Microsoft Entra ID Governance architecture**.  
✅ Deploy a **security baseline Conditional Access policy**.  
✅ Automate lifecycle management with **Access Reviews and PIM**.  
✅ Monitor and report on access governance effectively.

---

## 📚 References  
- [Microsoft Entra ID Governance](https://learn.microsoft.com/entra/id-governance/)  
- [Conditional Access Overview](https://learn.microsoft.com/azure/active-directory/conditional-access/overview)  
- [Access Reviews](https://learn.microsoft.com/entra/id-governance/access-reviews-overview)  
- [Privileged Identity Management](https://learn.microsoft.com/azure/active-directory/privileged-identity-management/pim-configure)  
- [Lifecycle Workflows](https://learn.microsoft.com/entra/id-governance/lifecycle-workflows-overview)

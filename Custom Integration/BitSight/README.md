# BitSight Risk Findings Codeless Connector

This package contains a **codeless Microsoft Sentinel connector** for reduced-scope BitSight Risk Findings using **RestApiPoller**.

## What it does

- Calls the BitSight findings endpoint directly:
  - `GET /ratings/v1/companies/{companyGuid}/findings`
- Pulls the ten agreed risk vectors:
  - botnet_infections
  - spam_propagation
  - malware_servers
  - unsolicited_comm
  - potentially_exploited
  - ssl_certificates
  - patching_cadence
  - mobile_software
  - open_ports
  - file_sharing
- Uses `limit=100`, `expand=remediation_history,tag_details,attributed_companies`
- Uses `last_seen_gte` / `last_seen_lte` with `yyyy-MM-dd`
- Uses `offset` paging
- Writes to `BitsightRiskFindings_CL`
- Filters to `WARN` and `BAD` findings in the DCR transform

## Important limitation

This codeless design is intentionally limited to **one explicit company GUID per Connect action**.
It does **not** perform dynamic portfolio discovery like the working Function App does.

## Authentication

BitSight expects Basic authentication with the token as username and an empty password.
The working Function App code builds this header by converting `BitSightToken:` to Base64.

For this codeless connector, the user must paste:

`Base64(BitSightToken:)`

into the **BitSight Basic auth value** field.

Example:
```bash
printf '%s' 'YOUR_BITSIGHT_TOKEN:' | base64
```

## Deployment order

1. Publish `bitsight-risk-findings-codeless-connection-template.json` as a Template Spec.
2. Deploy `bitsight-risk-findings-codeless-connector-definition.json`.
3. Open the connector in Microsoft Sentinel and enter:
   - BitSight company GUID
   - BitSight company display name
   - Base64 of `BitSightToken:`

## Notes

This package uses the same endpoint and risk vector set as the working reduced Function App implementation, but removes the Function App entirely.


## v2 fix

This version fixes the DCR transform KQL by removing the extra closing parenthesis that caused `InvalidTransformQuery` during DCR compilation.

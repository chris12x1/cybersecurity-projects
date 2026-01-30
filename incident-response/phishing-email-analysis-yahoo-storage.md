# Phishing Email Analysis – Yahoo Storage Scam

## Overview
This lab documents the analysis of a suspected phishing email impersonating Yahoo, using email header analysis and URL investigation tools.

## Email Summary
- Email Type: Phishing (Credential Harvesting)
- Attack Vector: Email
- Impersonated Brand: Yahoo
- User Impact: Account compromise risk

## Tools Used
- MXToolbox (Email Header Analysis)
- urlscan.io (URL behavior analysis)
- Manual inspection

## Analysis Performed
- Reviewed sender address and email content
- Analyzed SPF authentication results
- Investigated embedded URL behavior
- Identified social engineering techniques

## Key Findings
- Sender domain not associated with Yahoo
- SPF authentication failure for sending IP
- Obfuscated third-party URL unrelated to Yahoo
- Social engineering using urgency and fear
- Landing page behavior designed to evade detection

## Verdict
This email was classified as **malicious phishing** based on multiple authentication failures, domain impersonation, and deceptive URL behavior.

## Recommended Response
- Block sender domain and IP
- Remove email from inbox
- Educate users on phishing indicators
- Monitor for similar campaigns

## Evidence
Artifacts supporting this analysis are stored in the `artifacts/` directory.  
Sensitive information has been redacted to protect privacy.

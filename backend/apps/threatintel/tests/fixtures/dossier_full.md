# Threat Actor : APT29
> MITRE ATT&CK Group ID: **G0016**

## Intelligence Overview

APT29 is a state-sponsored espionage group attributed to Russia's Foreign Intelligence Service. Operational since at least 2008, it targets governments, diplomatic institutions and technology companies. The group is distinguished by exceptional operational security, patient long-term access operations, and creative abuse of legitimate cloud services for command and control. It consistently demonstrates advanced tradecraft including token theft and SAML forgery.

> Generated: 2026-08-14 21:54 UTC  |  Sources: cisa, mitre_attack, cisa_kev

## Overview

| Field | Value |
|---|---|
| **Origin** | Russian Federation |
| **First Seen** | 2008 |
| **Motivations** | espionage, financial |
| **Also Known As** | Cozy Bear, NOBELIUM, The Dukes |

## TTP Table

| Technique ID | Tactic | Name | Confidence |
|---|---|---|---|
| T1003.002 | Credential Access | Security Account Manager | MEDIUM |
| T1005 | Collection | Data from Local System | MEDIUM |
| T1078.004 | Stealth | Cloud Accounts | MEDIUM |
| T1110.003 | Credential Access | Password Spraying | MEDIUM |

## Targeted Sectors

- Government
- Think Tanks

## Known Exploited CVEs (CISA KEV)

| CVE ID | Product | Vendor | Date Added |
|---|---|---|---|
| CVE-2021-35247 | Serv-U | SolarWinds | 2022-01-21 |
| CVE-2024-21413 | Office Outlook | Microsoft | 2025-02-06 |

## Associated Malware / Tools

| Name | Type | Description |
|---|---|---|
| SUNBURST | malware | A trojanized DLL used in the SolarWinds compromise. |
| WellMess | malware | A lightweight malware family with .NET and Golang variants. |
| Cobalt Strike | malware | A commercial remote access tool. |

## Campaigns

### SolarWinds Compromise

A supply chain operation discovered in mid-December 2020.

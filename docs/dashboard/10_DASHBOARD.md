# 10 - Analyst Dashboard & UI Specification

```yaml
Module Title:        React 18 Analyst Dashboard & Workflow Components
Version:             2.1.0
Primary Files:       frontend/src/App.tsx
                     frontend/src/pages/Upload.tsx
                     frontend/src/pages/FraudCard.tsx
                     frontend/src/pages/TechnicalView.tsx
                     frontend/src/pages/ThreatIntelView.tsx
                     frontend/src/pages/InvestigationChat.tsx
                     frontend/src/components/investigation/InvestigationShell.tsx
                     frontend/src/components/investigation/VisualImpersonationPanel.tsx
                     frontend/src/hooks/useInvestigationModel.ts
```

---

## Table of Contents
- [1. Executive Overview](#1-executive-overview)
- [2. UI Navigation & Page Routing](#2-ui-navigation--page-routing)
- [2b. Investigation Shell (`InvestigationShell.tsx`)](#2b-investigation-shell-investigationshelltsx)
- [3. Executive Fraud Card Page (`FraudCard.tsx`)](#3-executive-fraud-card-page-fraudcardtsx)
- [4. Technical SOC View & Causal Workflow (`TechnicalView.tsx`)](#4-technical-soc-view--causal-workflow-technicalviewtsx)
- [5. Threat Intelligence View (`ThreatIntelView.tsx`)](#5-threat-intelligence-view-threatintelviewtsx)
- [6. AI Investigation Assistant Chat (`InvestigationChat.tsx`)](#6-ai-investigation-assistant-chat-investigationchattsx)
- [7. Interactive Causal Workflow Diagram (`WorkflowDiagram.tsx`)](#7-interactive-causal-workflow-diagram-workflowdiagramtsx)

---

## 1. Executive Overview

The **Analyst Dashboard** is a Single Page Application (SPA) built with React 18, TypeScript, Vite, and Tailwind CSS. It translates static decompilation, dynamic Frida traces, and mathematical risk scores into actionable views for fraud analysts, SOC teams, and bank executives.

---

## 2. UI Navigation & Page Routing (`App.tsx`)

The dashboard features a persistent header navigation bar with JWT auth status and role-based guards (`RequireAuth`) in [`App.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/App.tsx):

- `/`: Upload & Analysis Launcher ([`Upload.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/Upload.tsx))
- `/batch`: Enterprise Batch Scan ([`BatchScan.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/BatchScan.tsx))
- `/batch/:batch_id`: Enterprise Batch Details & Live Queue ([`BatchDetail.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/BatchDetail.tsx))
- `/fraud-card`: Executive View & Fraud Card ([`FraudCard.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/FraudCard.tsx))
- `/technical`: Technical SOC View & Workflow Diagram ([`TechnicalView.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/TechnicalView.tsx))
- `/threat-intel`: Threat Intelligence Correlation View ([`ThreatIntelView.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/ThreatIntelView.tsx))
- `/history`: Historical Analysis Case Store ([`History.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/History.tsx))
- `/chat`: AI Investigation Assistant ([`InvestigationChat.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/InvestigationChat.tsx))
- `/history/:sha256`: Deep-link to a stored case (loads via `InvestigationShell` + `FraudCard`)
- `/login`: Analyst JWT Login ([`Login.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/Login.tsx))

---

## 2b. Investigation Shell (`InvestigationShell.tsx`)

[`InvestigationShell.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/investigation/InvestigationShell.tsx) is the shared chrome for all post-upload investigation routes. It:

- Resolves the active SHA-256 from the route (`/history/:sha256`) or `AnalysisContext.activeSha256`, then calls `loadCaseByHash` against `GET /api/v1/cases/{sha256}`.
- Renders [`CaseHeader`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/investigation/CaseHeader.tsx) above the page content.
- When [`useInvestigationModel`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/hooks/useInvestigationModel.ts) has a bundle, mounts [`ScoreLedgerSlideOver`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/investigation/ScoreLedgerSlideOver.tsx) and [`EvidenceDrawer`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/investigation/EvidenceDrawer.tsx) (static findings + `GET /api/v1/cases/{sha256}/evidence` runtime records).
- Persists analyst notes via [`AnalystNotesPanel`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/investigation/AnalystNotesPanel.tsx) (`GET` / `POST /api/v1/cases/{sha256}/notes`).

---

## 3. Executive Fraud Card Page (`FraudCard.tsx`)

Designed for executive decision-makers in [`FraudCard.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/FraudCard.tsx):
- **Risk Badge & FRS Meter**: Visual score dial ($0.0 - 100.0$) and severity band from the API (`Safe`, `Suspicious`, `High Risk`, `Critical`).
- **Plain-English Executive Narrative**: Generated by Gemini 2.5 Flash (`GEMINI_MODEL`) summarizing malware behavior.
- **Recommended Actions**: Clear SOC mitigation steps (e.g., Block APK SHA-256, Enforce Step-up Auth).
- **Customer Advisory Draft**: Pre-drafted regulatory advisory for affected bank customers.
- **Visual Impersonation (VIDE)**: [`VisualImpersonationExecutiveCard`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/investigation/VisualImpersonationExecutiveCard.tsx) summarizes `vide` when the analysis payload includes a match (deterministic; not LLM-generated).

---

## 4. Technical SOC View & Causal Workflow (`TechnicalView.tsx`)

Designed for reverse engineers and SOC tier-2/3 analysts in [`TechnicalView.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/TechnicalView.tsx):
- **Explainability Engine**: Displays deterministic rule matches and scoring breakdowns.
- **APK Metadata**: Package name, SHA-256, version, target SDK, and certificate details.
- **Threat Indicators & Permission Analysis**: Granular dangerous permission table.
- **Network Intelligence**: Extracted C2 URLs, IP addresses, and mitmproxy HAR flows.
- **Raw Evidence Tabs**: Tabbed view of permissions, string literals, static APIs, manifest excerpts, and Frida runtime calls.
- **Fraud Workflow Reconstruction**: Houses the interactive `WorkflowDiagram.tsx` component.
- **Visual Impersonation (VIDE)**: [`VisualImpersonationPanel`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/investigation/VisualImpersonationPanel.tsx) shows baseline match detail from the `vide` object.
- **Evidence registry**: [`EvidenceRegistrySection`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/investigation/EvidenceRegistrySection.tsx) lists merged static + runtime evidence from the investigation bundle.
- **Runtime Screenshots**: When `dynamic_analysis.screenshots` contains paths, the UI loads images via authenticated `GET /api/v1/screenshots/{sha256}/{filename}` (JWT `fetch` + blob URLs; `<img>` cannot send `Authorization`).

---

## 5. Threat Intelligence View (`ThreatIntelView.tsx`)

In [`ThreatIntelView.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/ThreatIntelView.tsx):
- **VirusTotal Detection Ratio**: Vendor detection summary (e.g., 42/72 malicious).
- **AlienVault OTX & AbuseIPDB Panels**: Reputation scores and threat pulse counts.
- **Malware Family Classification**: Deterministic classification badge (*Drinik*, *Xenomorph*, *Cerberus*).

---

## 6. AI Investigation Assistant Chat (`InvestigationChat.tsx`)

An interactive chat interface backed by RAG context in [`InvestigationChat.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/InvestigationChat.tsx):
- Uses the **Gemini RAG Vector Index** (`gemini_rag.py`) to query specific details about the active sample.
- Grounded strictly in observable case findings with zero hallucination.

---

## 7. Interactive Causal Workflow Diagram (`WorkflowDiagram.tsx`)

Renders reconstructed `FraudWorkflow` stages in [`WorkflowDiagram.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/WorkflowDiagram.tsx):
- **Stage Node Cards**: Displays stage title, MITRE ATT&CK technique badge, duration, and confidence score.
- **Expandable Details**: Clicking a stage reveals full description, fired Frida hooks, and evidence counts.
- **Sequence Badge**: Identifies campaign type (`FULL_ACCOUNT_TAKEOVER`, `OTP_THEFT_CHAIN`, `OVERLAY_PHISHING`, `DROPPER_CHAIN`).

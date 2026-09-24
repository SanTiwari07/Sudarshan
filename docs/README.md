# SUDARSHAN Documentation Portal

> **Authoritative Technical Documentation System**  
> **Platform Version:** Backend 2.1.0 · Analysis Engine 2.3.0  
> **Verified Tests:** 2,841 collected tests (100% passing)  

Welcome to the SUDARSHAN documentation portal. Every document in this directory has been audited and verified against the live executable codebase.

---

## Documentation Directory Index

```
docs/
├── 00_PROJECT/                  # Vision, context, glossary, and verified ground truth
│   ├── GROUND_TRUTH.md          # ★ Primary codebase-verified reality document
│   ├── VISION.md                # 90-second fraud asymmetry & platform mission
│   ├── PROJECT_CONTEXT.md       # Origin, hackathon background, and evolution
│   └── GLOSSARY.md              # Domain terminology and acronyms
│
├── 01_ARCHITECTURE/             # High-level architecture, maps, and network topology
│   ├── SYSTEM_ARCHITECTURE.md   # Distributed microservices and component interactions
│   ├── CODEBASE_MAP.md          # Granular file and module organization
│   ├── DATA_FLOW.md             # End-to-end investigation sequence diagram
│   ├── API_ARCHITECTURE.md      # REST design, JWT authentication, and RBAC
│   └── SECURITY_BOUNDARIES.md   # Sandbox isolation and network leak prevention
│
├── 02_ANALYSIS/                 # Static, dynamic, UI, and threat intelligence engines
│   ├── STATIC_ANALYSIS.md       # Androguard, APKTool, JADX, and APK repair
│   ├── DYNAMIC_ANALYSIS.md      # Isolated Android guest and Frida runtime
│   ├── AGENTIC_EXPLORATION.md   # Deep UI Explorer & 5-level perception hierarchy
│   ├── FRIDA_INSTRUMENTATION.md # Hook architecture and API interception
│   ├── NETWORK_ANALYSIS.md      # Transparent mitmproxy capture & HAR processing
│   ├── VISUAL_IMPERSONATION.md  # VIDE: Layout AST, CIEDE2000 ΔE, RapidFuzz, Signer Registry
│   └── THREAT_INTELLIGENCE.md   # VirusTotal, AlienVault OTX, and AbuseIPDB correlation
│
├── 03_RISK/                     # Deterministic scoring, indices, and safety floors
│   ├── RISK_ENGINE.md           # Master FRS composite formula & safety floors
│   ├── STEI.md                  # Static Threat Evaluation Index (5 axes)
│   ├── BFCI.md                  # Behavioral Fraud Confidence Index v2 (7 axes)
│   ├── FRAUD_RISK_SCORE.md      # Normalized 0–100 score bands and operational semantics
│   └── DETERMINISM.md           # Mathematical determinism guarantees and proof
│
├── 04_AI/                       # Grounded RAG, Gemini client, and prompt safety
│   ├── AI_INVESTIGATION.md      # Grounded explanation assistant architecture
│   ├── RAG.md                   # 5-stage RAG pipeline and 7-section response format
│   ├── AI_SAFETY.md             # 3-state circuit breaker and failover design
│   └── PROMPT_SANITIZATION.md   # Adversarial APK string sanitization
│
├── 05_SECURITY/                 # Isolation, access control, and threat models
│   ├── SANDBOX_CONTAINMENT.md   # Host LAN leak prevention & containment checks
│   ├── SECURITY_MODEL.md        # JWT auth, 3-tier RBAC, rate limits, session revocation
│   ├── THREAT_MODEL.md          # Attacker personas and mitigation matrix
│   └── KNOWN_SECURITY_LIMITATIONS.md # Operational boundaries & managed limits
│
├── 06_OPERATIONS/               # Running, deploying, and maintaining SUDARSHAN
│   ├── HOW_TO_RUN.md            # One-command startup, Docker Compose, and dev modes
│   ├── DEPLOYMENT.md            # Production deployment and PostgreSQL activation
│   ├── ENVIRONMENT.md           # Environment variables and configuration matrix
│   ├── PRE_FLIGHT.md            # Pre-flight diagnostic checklist
│   └── TROUBLESHOOTING.md       # Common operational failure modes and resolutions
│
├── 07_API/                      # REST API endpoints, schemas, and usage
│   ├── API_REFERENCE.md         # Complete route catalog across backend and engine
│   ├── ANALYSIS_API.md          # Sync/async upload, job status, cancellation
│   ├── CASE_API.md              # Case search, filtering, tags, and notes
│   ├── BATCH_API.md             # Enterprise batch scanning and job control
│   ├── REPORT_API.md            # PDF, interactive HTML, and STIX 2.1 exports
│   └── RUNTIME_API.md           # Real-time Frida telemetry and resilience triggers
│
├── 08_DEVELOPMENT/              # Contribution standards, testing, and guidelines
│   ├── CONTRIBUTING.md          # Architecture rules from AGENTS.md
│   ├── TESTING.md               # Pytest suite, fixtures, and execution guide
│   ├── DEVELOPMENT_GUIDE.md     # Setting up local developer environment
│   └── CODE_STANDARDS.md        # Python/TypeScript coding standards
│
├── 09_EVIDENCE/                 # Forensic models, reporting, and exports
│   ├── EVIDENCE_MODEL.md        # Unified normalized evidence event schema
│   ├── REPORTING.md             # ReportLab PDF generation and executive cards
│   ├── STIX_EXPORT.md           # STIX 2.1 threat intelligence bundles
│   └── IOC_PIPELINE.md          # IOC extraction and threat reputation
│
├── 10_VALIDATION/               # Test matrices, benchmarks, and feature verification
│   ├── VALIDATION.md            # Multi-stage empirical verification protocol
│   ├── BENCHMARKS.md            # Performance benchmarks and memory profiling
│   ├── TEST_MATRIX.md           # Breakdown of 2,841 collected tests
│   └── FEATURE_STATUS.md        # Implemented vs experimental feature matrix
│
└── 99_HISTORY/                  # Historical milestones, changelogs, and past audits
    ├── CHANGELOG.md             # Version release history
    ├── AUDIT_HISTORY.md         # Archive of past audit phases
    ├── HISTORICAL_NOTES.md      # Design decisions and architectural evolution
    ├── audits/                  # Detailed engineering audit reports
    └── reports/                 # Historical hackathon milestone reports
```

# 07 — BOI Mobile (Bank of India) — Design Specification

*Follows the corpus schema (exemplar: `01_sbi_yono.md`).*

# APP IDENTITY
- **Bank:** Bank of India (public sector)
- **Exact Application Name:** BOI Mobile *(newer generation: "BOI Mobile Omni Neo
  Bank App")*
- **Baseline ID:** `BASE-07-BOI` · **Shortcode:** `BOI`
- **Research Date:** 2026-08-12
- **Platform:** Android (Capacitor target); iOS exists
- **Official Sources:** Google Play `com.boi.ua.android` **VERIFIED**; BOI "Omni
  Neo" official page
- **Research Confidence:** Identity HIGH; current-generation transition MED; visual PARTIAL
- **Naming note (IMPORTANT):** an active migration **BOI Mobile → BOI Mobile Omni
  Neo Bank App** is documented (older app described as discontinued). Baseline name
  = **BOI Mobile**; Omni-Neo-specific UI is flagged `[UNKNOWN]` unless verified.

# PURPOSE OF THIS SPECIFICATION
Research-grounded, local, mock-data prototype spec of publicly observable BOI Mobile
UI patterns, as a VIDE trusted baseline. No real auth/backend/credentials/
transactions. Colors approximated from public brand identity.

# SOURCE EVIDENCE
| Source | Type | What It Supports | Confidence |
|---|---|---|---|
| Google Play listing (VERIFIED) | [OFFICIAL SOURCE] | Name, package, identity | HIGH |
| BOI Omni Neo official page | [OFFICIAL SOURCE] | Current-generation transition | MED |
| BOI public brand (blue + orange "star") | [PUBLIC OBSERVATION] | Color approximation | MED |
| Banking UX conventions | [INFERENCE] | Screen structure | LOW–MED |

# BRAND AND VISUAL IDENTITY
## Logo Treatment
BOI "star" mark uses blue + orange. **Do not bundle real logo.** →
**ORIGINAL TEST ASSET REQUIRED.**
## Color System
| Token | Value | Confidence | Evidence |
|---|---|---|---|
| primary | `#0B3D91` (BOI blue) | APPROXIMATED | public brand identity |
| secondary | `#F58220` (BOI orange) | APPROXIMATED | public brand identity |
| accent | `#F4A81D` (amber) | APPROXIMATED | highlight |
| background | `#F2F5FA` | APPROXIMATED | light bg |
| surface | `#FFFFFF` | APPROXIMATED | cards |
| text-primary | `#14213A` | APPROXIMATED | text |
| text-secondary | `#59637A` | APPROXIMATED | secondary |
| divider | `#E1E6EF` | APPROXIMATED | hairlines |
| success `#1E8E4E` / warning `#E8A100` / error `#C0392B` | APPROXIMATED | states |
## Typography
Sans; exact font UNKNOWN. System/`Inter`, 700/500/400. APPROXIMATED.

# DESIGN PRINCIPLES
Medium density; blue header, orange accents; public-sector utilitarian; card
dashboard; bottom nav. (Omni Neo may be more modern — flagged UNKNOWN.)

# SCREEN INVENTORY
**MUST IMPLEMENT (11):** `SPLASH`, `LOGIN`, `MPIN`, `HOME`, `ACCOUNTS`,
`ACCOUNT_DETAILS`, `TXN_HISTORY`, `TRANSFER`, `AMOUNT`, `REVIEW`, `RECEIPT`.
**OPTIONAL:** `BIOMETRIC`, `SERVICES`, `CARDS`, `PROFILE`, `NOTIFICATIONS`, `SETTINGS`.
**NOT VERIFIED:** Omni Neo redesign screens (flagged `[UNKNOWN]`).

# INFORMATION ARCHITECTURE
```mermaid
graph TD
  SPLASH-->LOGIN-->MPIN-->HOME
  LOGIN-->FORGOT
  HOME-->ACCOUNTS-->ACCOUNT_DETAILS-->TXN_HISTORY-->TXN_DETAIL
  HOME-->TRANSFER-->AMOUNT-->REVIEW-->RECEIPT-->HOME
```
| From | To | Trigger |
|---|---|---|
| MPIN | HOME | 6 digits (mock) |
| HOME | TRANSFER | quick action |
| REVIEW | RECEIPT | Confirm (mock) |

# SCREEN SPECIFICATIONS
## SPLASH — `BOI-SPLASH` `/` — blue bg, test mark, auto→LOGIN. SIMULATED.
## LOGIN — `BOI-LOGIN` `/login` — `AUTH_FORM_VERTICAL_PRIMARY_CTA`; any input→MPIN. MOCK.
## MPIN — `BOI-MPIN` `/mpin` — `PINPAD_NUMERIC_ENTRY`; 6 digits→HOME. **No capture.** SIMULATED.
## HOME — `BOI-HOME` `/home` — `DASHBOARD_CARD_GRID_QUICKACTIONS`+`TAB_HOST_BOTTOMNAV`
`HEADER(greeting,notif) → ACCOUNT_SUMMARY_CARD → QUICK_ACTIONS(Transfer,Pay,Bills,Services) → RECENT_ACTIVITY → BOTTOM_NAV`. Blue/orange. MOCK DATA.
## ACCOUNTS / ACCOUNT_DETAILS / TXN_HISTORY — corpus patterns.
## TRANSFER→AMOUNT→REVIEW→RECEIPT — mock flow. SIMULATED.

# REUSABLE COMPONENT SYSTEM
Shared corpus set.

# DESIGN TOKEN MAP
```css
--color-primary:#0B3D91; --color-secondary:#F58220; --color-accent:#F4A81D; /* APPROXIMATED */
--color-bg:#F2F5FA; --color-surface:#FFFFFF; /* APPROXIMATED */
--color-text-primary:#14213A; --color-text-secondary:#59637A; --color-divider:#E1E6EF; /* APPROXIMATED */
--color-success:#1E8E4E; --color-warning:#E8A100; --color-error:#C0392B; /* APPROXIMATED */
--radius-card:16px; --space-16:16px; --font-heading:'Inter',system-ui; /* APPROXIMATED */
```

# NAVIGATION MANIFEST (JSON)
```json
{"baselineId":"BASE-07-BOI","entry":"BOI-SPLASH",
 "nodes":[{"id":"BOI-SPLASH","route":"/"},{"id":"BOI-LOGIN","route":"/login"},
 {"id":"BOI-MPIN","route":"/mpin"},{"id":"BOI-HOME","route":"/home"},
 {"id":"BOI-TRANSFER","route":"/transfer"},{"id":"BOI-AMOUNT","route":"/transfer/amount"},
 {"id":"BOI-REVIEW","route":"/transfer/review"},{"id":"BOI-RECEIPT","route":"/transfer/receipt"}],
 "edges":[{"from":"BOI-SPLASH","to":"BOI-LOGIN","trigger":"timeout"},
 {"from":"BOI-LOGIN","to":"BOI-MPIN","trigger":"submit-mock"},
 {"from":"BOI-MPIN","to":"BOI-HOME","trigger":"mpin-complete-mock"},
 {"from":"BOI-AMOUNT","to":"BOI-REVIEW","trigger":"continue"},
 {"from":"BOI-REVIEW","to":"BOI-RECEIPT","trigger":"confirm-mock"}]}
```

# SCREEN FINGERPRINT MAP (authored)
```
SCREEN_ID: BOI-HOME  SIGNATURE: DASHBOARD_CARD_GRID_QUICKACTIONS
FEATURES: [blue header, balance card, quick actions, recent activity, bottom nav]
SCREEN_ID: BOI-LOGIN SIGNATURE: AUTH_FORM_VERTICAL_PRIMARY_CTA
```

# MOCK DATA REQUIREMENTS
Fictional accounts/transactions/payees/cards/notifications (corpus shapes). No real PII.

# PROTOTYPE EXCLUSIONS
no real login · no credential transmission · no backend · no transactions · no live
OTP · no production security · no personal-data collection · no logo reuse.

# RESEARCH GAPS AND LIMITATIONS
Exact colors/typeface UNKNOWN (approximated); **Omni Neo redesign UI UNKNOWN / NOT
VERIFIED**; BOI Mobile → Omni Neo transition documented; post-login layouts representative.

# IMPLEMENTATION HANDOFF SUMMARY
11-screen mock prototype, blue+orange palette, card dashboard + transfer flow,
deterministic mock data, no backend. If targeting Omni Neo generation, treat its
specific screens as UNKNOWN placeholders. See
`03-implementation-plans/07_boi_implementation.md`.

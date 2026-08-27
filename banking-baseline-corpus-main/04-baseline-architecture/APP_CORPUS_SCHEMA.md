# APP_CORPUS_SCHEMA.md

The **shared schema** every app in this corpus conforms to. Cross-app
consistency is mandatory: the corpus is later used for baseline registration and
screen/navigation similarity experiments, which require identical conventions.

---

## 1. Identifier conventions

### 1.1 Baseline ID
Format: `BASE-<NN>-<SHORTCODE>`

| # | Baseline ID | Shortcode | App |
|---|---|---|---|
| 01 | `BASE-01-SBI` | SBI | YONO SBI |
| 02 | `BASE-02-HDFC` | HDFC | HDFC Bank MobileBanking |
| 03 | `BASE-03-ICICI` | ICICI | iMobile Pay |
| 04 | `BASE-04-AXIS` | AXIS | Axis Mobile / "open" |
| 05 | `BASE-05-BOB` | BOB | bob World |
| 06 | `BASE-06-PNB` | PNB | PNB ONE |
| 07 | `BASE-07-BOI` | BOI | BOI Mobile |
| 08 | `BASE-08-KOTAK` | KOTAK | Kotak811 & Mobile Banking |
| 09 | `BASE-09-INDUS` | INDUS | IndusMobile / INDIE |
| 10 | `BASE-10-UNION` | UNION | Vyom (Union ease) |

### 1.2 Screen ID
Format: `<SHORTCODE>-<SCREEN_KEY>` — e.g. `SBI-HOME`, `HDFC-LOGIN`.

**Canonical screen keys** (an app implements a subset; never invent new keys
without adding them here):

```
SPLASH, ONBOARDING, LOGIN, MPIN, BIOMETRIC, REGISTER, FORGOT,
HOME, ACCOUNTS, ACCOUNT_DETAILS, TXN_HISTORY, TXN_DETAIL,
PAYMENTS, PAYEE_LIST, PAYEE_ADD, TRANSFER, AMOUNT, REVIEW, CONFIRM, RECEIPT,
CARDS, CARD_DETAIL, DEPOSITS, DEPOSIT_OPEN,
SERVICES, REWARDS, OFFERS, PROFILE, SETTINGS, NOTIFICATIONS, HELP, LOGOUT
```

### 1.3 Route convention
Kebab-case paths mirroring screen keys: `/home`, `/accounts/:id`,
`/transfer/amount`, `/payments/payee`, etc. Documented per app in its
NAVIGATION MANIFEST.

### 1.4 Component IDs
PascalCase, from the shared component system (§4). App-specific variants suffix
the shortcode: `AccountCard`, `AccountCard.SBI` only if a real structural
difference exists.

## 2. Confidence vocabulary (used everywhere)

| Dimension | Allowed values |
|---|---|
| Evidence tag | `[OFFICIAL SOURCE]` `[PUBLIC OBSERVATION]` `[INFERENCE]` `[UNKNOWN]` |
| Color/measure | `EXACT` `APPROXIMATED` `UNKNOWN` |
| Screen class | `MUST IMPLEMENT` `OPTIONAL` `NOT VERIFIED` |
| Feature class | `MUST IMPLEMENT` `VISUAL ONLY` `SIMULATED` `NOT REQUIRED` |
| Fidelity audit | `MATCHED` `PARTIALLY MATCHED` `NOT MATCHED` `NOT VERIFIABLE` |

## 3. Design-token schema

Every app exposes the **same token names**; only values differ. This lets VIDE
compare token *usage* across baselines.

```
/* Color */
--color-primary            --color-primary-contrast
--color-secondary          --color-accent
--color-bg                 --color-surface        --color-surface-alt
--color-text-primary       --color-text-secondary --color-text-inverse
--color-divider            --color-success --color-warning --color-error --color-info

/* Typography */
--font-family-base         --font-family-heading
--font-size-caption(12)  --font-size-body(14) --font-size-subtitle(16)
--font-size-title(20)    --font-size-headline(24) --font-size-display(32)
--font-weight-regular(400) --font-weight-medium(500) --font-weight-bold(700)

/* Spacing (4px base) */
--space-4 --space-8 --space-12 --space-16 --space-20 --space-24 --space-32

/* Radius */
--radius-sm(8) --radius-md(12) --radius-card(16) --radius-pill(999)

/* Elevation */
--elev-0 --elev-1 --elev-2 --elev-3

/* Motion */
--motion-fast(120ms) --motion-base(200ms) --motion-slow(320ms)
--easing-standard(cubic-bezier(.2,0,0,1))
```

Every value carries a confidence label in the app spec's DESIGN TOKEN MAP.

## 4. Shared reusable component system

All apps draw from one component vocabulary (visual skinning differs, structure
is shared — this is what makes cross-app structural comparison meaningful):

| Component | Role |
|---|---|
| `AppShell` | Mobile frame, safe-area, status region |
| `Header` | Top bar: brand/title + actions |
| `BottomNavigation` | Primary tab bar (if app uses one) |
| `AccountCard` | Account summary surface |
| `QuickAction` | Icon+label shortcut tile |
| `TransactionRow` | One transaction line item |
| `PrimaryButton` / `SecondaryButton` | CTAs |
| `InputField` | Text/number input |
| `PINPad` | Numeric MPIN entry (mock only) |
| `Modal` | Overlay dialog |
| `Toast` | Transient message |
| `EmptyState` | No-data placeholder |
| `ListSection` | Titled grouped list |
| `Chip` / `Badge` | Status/label markers |

## 5. Machine-readable per-app record (`app.meta.json`)

Each prototype ships this file; the registration pipeline consumes it.

```json
{
  "baselineId": "BASE-01-SBI",
  "shortcode": "SBI",
  "appName": "YONO SBI",
  "bank": "State Bank of India",
  "sector": "public",
  "corpusVersion": "1.0",
  "researchDate": "2026-08-12",
  "isPrototype": true,
  "mockDataOnly": true,
  "network": "none",
  "screens": ["SPLASH","LOGIN","MPIN","HOME","ACCOUNTS","TXN_HISTORY","TRANSFER","AMOUNT","CONFIRM","RECEIPT","CARDS","SERVICES","PROFILE"],
  "navigation": "see navigation.manifest.json",
  "assets": "original-test-assets",
  "exclusions": ["no-real-auth","no-backend","no-credentials","no-transactions","no-live-otp"]
}
```

## 6. Navigation manifest schema (`navigation.manifest.json`)

```json
{
  "baselineId": "BASE-01-SBI",
  "entry": "SPLASH",
  "nodes": [
    { "id": "SPLASH", "route": "/", "type": "system" },
    { "id": "LOGIN",  "route": "/login", "type": "auth" },
    { "id": "HOME",   "route": "/home", "type": "primary" }
  ],
  "edges": [
    { "from": "SPLASH", "to": "LOGIN", "trigger": "timeout" },
    { "from": "LOGIN",  "to": "MPIN",  "trigger": "submit-mock" },
    { "from": "MPIN",   "to": "HOME",  "trigger": "mpin-complete-mock" }
  ]
}
```

## 7. Screen fingerprint schema (semantic, for VIDE)

Authored semantic descriptor — **not** an extracted fingerprint from a real app.

```
SCREEN_ID: SBI-LOGIN
STRUCTURAL_SIGNATURE: AUTH_FORM_VERTICAL_PRIMARY_CTA
FEATURES:
  - authentication-focused layout
  - vertically stacked credential fields
  - single primary CTA
  - recovery/secondary action
  - brand mark in header region
REGION_ORDER: [STATUS, HEADER, PRIMARY_CONTENT, FOOTER_CTA]
```

**Structural signature vocabulary** (shared across corpus):
`AUTH_FORM_VERTICAL_PRIMARY_CTA`, `DASHBOARD_CARD_GRID_QUICKACTIONS`,
`LIST_TRANSACTIONS_CHRONO`, `FORM_AMOUNT_ENTRY_NUMERIC`,
`SUMMARY_REVIEW_CONFIRM`, `RECEIPT_SUCCESS_STATE`, `TAB_HOST_BOTTOMNAV`,
`DETAIL_HEADER_METADATA_LIST`, `SETTINGS_LIST_GROUPED`, `PINPAD_NUMERIC_ENTRY`.

## 8. Mock-data schema (shared shapes)

```json
{
  "accounts": [{ "id","type","maskedNumber","balance","currency","nickname" }],
  "transactions": [{ "id","accountId","date","description","amount","direction","channel","balanceAfter" }],
  "payees": [{ "id","name","maskedAccount","ifsc","bankName","type" }],
  "cards": [{ "id","type","maskedNumber","network","expiry","status" }],
  "notifications": [{ "id","title","body","date","read","category" }]
}
```

All values are **fictional**. Masked numbers use non-real patterns
(e.g. `XXXXXX1234`), amounts and names are invented, IFSC codes are placeholders.

## 9. Consistency rules (enforced by the corpus auditor)

1. Same section order in every design spec (PART 5 template).
2. Same section order in every implementation plan (PART 6 template).
3. Screen keys only from §1.2; structural signatures only from §7.
4. Token names identical across apps (§3); only values/confidence differ.
5. Every value has a confidence label.
6. Every prototype declares the standard exclusion set (§5).

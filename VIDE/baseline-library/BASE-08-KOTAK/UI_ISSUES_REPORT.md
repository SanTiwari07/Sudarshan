# UI Issues Report - Kotak 811 Mobile App (Baseline 08)

This document outlines the UI alignment, padding, margin, and layout issues identified in the frontend implementation. While the overall structure follows the design specifications, several specific areas require attention to improve visual balance and professional execution.

## 1. Home Screen (`Home.tsx`)
*   **Quick Actions Grid Alignment**: The `grid-cols-4` container holds buttons with text labels (`text-xs`). When a label spans two lines (e.g., "Transfer Money" vs "Recharge"), the height differences cause the circular icons above them to misalign vertically.
    *   *Fix*: Apply a consistent min-height to the text container or vertically align the grid items at the top (`items-start`).
*   **Account Summary Card Padding & Spacing**: 
    *   The separation between the Available Balance section and the top/bottom areas is somewhat inconsistent (`mb-4` used arbitrarily). 
    *   The "Transfer" and "Statements" action buttons at the bottom use `flex justify-between`, but they may look disconnected from the card content due to the hairline border spacing (`pt-4`). 
*   **Recent Transactions Margin**: The spacing inside the recent transactions list can feel cramped. The container uses `gap-3`, but the text block (description + date) could use better line-height management to differentiate hierarchy.

## 2. Transfer Screen (`Transfer.tsx`)
*   **Search Input Icon Alignment**: The search icon in the text input is vertically positioned using a hardcoded `top-4`. Since the input has padding `p-4`, this does not guarantee perfect vertical centering across different devices or text scaling settings.
    *   *Fix*: Change `top-4` to `top-1/2 -translate-y-1/2` for robust vertical centering.
*   **Recent Payees Header**: The "RECENT PAYEES" section header has `mb-4` and is placed outside the list container. It feels slightly disconnected from the list it describes.

## 3. Amount Screen (`Amount.tsx`)
*   **Amount Input Field Width**: The input field for the amount has a fixed width of `w-32`. If a user enters a larger amount (e.g., ₹ 100,000+), the text will overflow or get cut off. 
    *   *Fix*: Remove the strict width limitation, using flex-grow or a larger max-width to allow the field to expand gracefully.
*   **Footer Button Overlap**: The "Proceed to Pay" button is placed in a `fixed bottom-0` container. While the main wrapper has `pb-20`, on smaller viewports, the padding might not be sufficient, causing the bottom fixed area to overlap the "Paying from" card.

## 4. Review Screen (`Review.tsx`)
*   **Vertical Alignment of Key-Value Pairs**: The "To" and "From" summary rows use `flex justify-between items-center`. Because the right-side values contain two lines of text (e.g., Name + VPA, or Account Type + Number), vertical centering causes the left-side labels ("To", "From") to float in the middle, which looks awkward.
    *   *Fix*: Use `items-start` so the label aligns with the primary text on the first line.

## 5. Profile Screen (`Profile.tsx`)
*   **Section Header Margins**: The headers for "Account Settings" and "Support" use `px-2`. However, the rounded cards below them fill the width of the parent (which has `px-4`). This creates a slight visual misalignment between the left edge of the header text and the left edge of the card.
    *   *Fix*: Remove `px-2` from the section headers to align them perfectly with the card boundaries.
*   **Logout Button Spacing Stack**: The Logout button is a direct sibling in a container using `space-y-6`, but it also has an explicitly added `mt-4`. This causes the spacing to stack inappropriately, creating too much gap before the button.

## 6. Accounts Screen (`Accounts.tsx`)
*   **Status Badge Placement**: The "Active" status badge (`bg-green-100`) floats to the right within a `flex justify-between items-start` container. On smaller screens, if the account type name is long, it might crash into the badge. A better layout would wrap the text or ensure a minimum gap.
*   **Balance Spacing**: The label "Available Balance" and the amount value are tightly stacked (`mb-1`). Increasing the visual hierarchy and spacing here would improve readability.

## 7. Login Screen (`Login.tsx`)
*   **Form Padding and Margins**: The main form has a container with `flex-1 flex flex-col`. The "Forgot CRN?" button uses `mb-8`, pushing the "Continue" button far down. The `mt-auto` on the button container correctly pins it to the bottom, but the intermediate spacing makes the form feel disjointed.

## Summary Recommendation
Overall, standardizing margins (e.g., strictly sticking to `p-4` or `p-6` as the standard screen padding), fixing vertical alignments (`items-start` for multi-line flex items), and ensuring text doesn't overflow fixed-width containers will greatly improve the visual quality of the Kotak 811 baseline screens.

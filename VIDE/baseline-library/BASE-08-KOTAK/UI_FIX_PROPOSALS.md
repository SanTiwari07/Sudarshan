# UI Fix Proposals - Kotak 811 Mobile App (Baseline 08)

This document outlines the concrete code changes required to address the UI issues identified in `UI_ISSUES_REPORT.md` across the app's screens.

## 1. Transfer Screen (`Transfer.tsx`)
**Issue:** Search Input Icon Alignment is hardcoded.
*   **Target File:** `app/src/screens/Transfer.tsx`
*   **Change:** Update the SVG icon's class to use robust vertical centering.
    *   *From:* `className="absolute left-4 top-4 text-gray-400"`
    *   *To:* `className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400"`

**Issue:** Recent Payees Header disconnected.
*   **Target File:** `app/src/screens/Transfer.tsx`
*   **Change:** Reduce the bottom margin to tighten the visual grouping with the list below.
    *   *From:* `className="text-sm font-bold text-gray-500 mb-4"`
    *   *To:* `className="text-sm font-bold text-gray-500 mb-2"`

## 2. Amount Screen (`Amount.tsx`)
**Issue:** Amount Input Field Width limitation.
*   **Target File:** `app/src/screens/Amount.tsx`
*   **Change:** Remove the fixed `w-32` width and allow the input to flex, preventing larger numbers from getting cut off.
    *   *From:* `className="w-32 bg-transparent border-none outline-none text-center"`
    *   *To:* `className="w-full max-w-[200px] bg-transparent border-none outline-none text-center"`

**Issue:** Footer Button Overlap.
*   **Target File:** `app/src/screens/Amount.tsx`
*   **Change:** Increase the bottom padding of the main wrapper to prevent the fixed footer from overlapping content on small viewports.
    *   *From:* `className="flex flex-col min-h-screen bg-gray-50 pb-20"`
    *   *To:* `className="flex flex-col min-h-screen bg-gray-50 pb-24"`

## 3. Review Screen (`Review.tsx`)
**Issue:** Vertical Alignment of Key-Value Pairs.
*   **Target File:** `app/src/screens/Review.tsx`
*   **Change:** Change `items-center` to `items-start` so that the left-side labels align with the first line of the multi-line right-side text.
    *   *From:* `className="flex justify-between items-center border-b border-gray-100 pb-4"`
    *   *To:* `className="flex justify-between items-start border-b border-gray-100 pb-4"`

## 4. Profile Screen (`Profile.tsx`)
**Issue:** Section Header Margins.
*   **Target File:** `app/src/screens/Profile.tsx`
*   **Change:** Remove `px-2` to align the headers directly with the edges of the cards.
    *   *From:* `className="text-xs font-bold text-gray-500 mb-3 px-2 uppercase"`
    *   *To:* `className="text-xs font-bold text-gray-500 mb-3 uppercase"`

**Issue:** Logout Button Spacing Stack.
*   **Target File:** `app/src/screens/Profile.tsx`
*   **Change:** Remove the explicit `mt-4` on the Logout button, allowing the parent's `space-y-6` to handle the spacing evenly.
    *   *From:* `className="w-full py-4 rounded-xl font-bold bg-white text-red-600 shadow-sm border border-red-100 mt-4"`
    *   *To:* `className="w-full py-4 rounded-xl font-bold bg-white text-red-600 shadow-sm border border-red-100"`

## 5. Accounts Screen (`Accounts.tsx`)
**Issue:** Status Badge Placement.
*   **Target File:** `app/src/screens/Accounts.tsx`
*   **Change:** Add a `gap-4` to ensure long account names do not crash into the status badge.
    *   *From:* `className="flex justify-between items-start mb-4"`
    *   *To:* `className="flex justify-between items-start gap-4 mb-4"`

**Issue:** Balance Spacing.
*   **Target File:** `app/src/screens/Accounts.tsx`
*   **Change:** Increase the margin below the "Available Balance" label to improve readability and visual hierarchy.
    *   *From:* `className="text-xs text-gray-500 mb-1"`
    *   *To:* `className="text-xs text-gray-500 mb-2"`

## 6. Login Screen (`Login.tsx`)
**Issue:** Form Padding and Margins.
*   **Target File:** `app/src/screens/Login.tsx`
*   **Change:** Reduce the bottom margin of the "Forgot CRN?" container to prevent disjointed spacing.
    *   *From:* `className="flex justify-end mb-8"`
    *   *To:* `className="flex justify-end mb-4"`

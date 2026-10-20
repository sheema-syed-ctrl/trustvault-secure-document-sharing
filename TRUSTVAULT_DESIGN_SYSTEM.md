# TrustVault — Precision SaaS Design System

**System Name:** TrustVault Precision (v2.0)  
**Philosophy:** Enterprise Security, High Information Density, Zero Decorative Waste, Tactile Micro-Interactions  
**Influences:** Linear (layout precision), Stripe (typography & hierarchy), Apple (restraint & contrast)  

---

## 1. Design Tokens & CSS Custom Properties

### A. Color Palette
The color system provides explicit contrast, semantic clarity, and dual-theme compatibility (Light & Dark).

```css
:root {
  /* Brand Primitives */
  --tv-primary-50:  #eff6ff;
  --tv-primary-100: #dbeafe;
  --tv-primary-200: #bfdbfe;
  --tv-primary-300: #93c5fd;
  --tv-primary-400: #60a5fa;
  --tv-primary-500: #3b82f6; /* Core Primary */
  --tv-primary-600: #2563eb;
  --tv-primary-700: #1d4ed8;
  --tv-primary-800: #1e40af;
  --tv-primary-900: #1e3a8a;

  /* Neutral Primitives (Slate/Zinc) */
  --tv-gray-50:  #f8fafc;
  --tv-gray-100: #f1f5f9;
  --tv-gray-200: #e2e8f0;
  --tv-gray-300: #cbd5e1;
  --tv-gray-400: #94a3b8;
  --tv-gray-500: #64748b;
  --tv-gray-600: #475569;
  --tv-gray-700: #334155;
  --tv-gray-800: #1e293b;
  --tv-gray-900: #0f172a;
  --tv-gray-950: #020617;

  /* Semantic Feedback */
  --tv-success: #10b981;
  --tv-success-bg: #ecfdf5;
  --tv-warning: #f59e0b;
  --tv-warning-bg: #fffbeb;
  --tv-danger:  #ef4444;
  --tv-danger-bg:  #fef2f2;
  --tv-info:    #06b6d4;
  --tv-info-bg:    #ecfeff;

  /* Semantic Theme Tokens (Default: Light Mode) */
  --tv-bg-body:       var(--tv-gray-50);
  --tv-bg-surface:    #ffffff;
  --tv-bg-surface-elevated: #ffffff;
  --tv-bg-subtle:     var(--tv-gray-100);
  --tv-border-default: var(--tv-gray-200);
  --tv-border-subtle:  #edf2f7;
  --tv-border-strong:  var(--tv-gray-300);

  --tv-text-main:     var(--tv-gray-900);
  --tv-text-muted:    var(--tv-gray-500);
  --tv-text-subtle:   var(--tv-gray-400);

  --tv-primary:       var(--tv-primary-600);
  --tv-primary-hover: var(--tv-primary-700);
  --tv-primary-light: var(--tv-primary-50);
  --tv-primary-text:  var(--tv-primary-700);

  /* Shadows */
  --tv-shadow-xs: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
  --tv-shadow-sm: 0 1px 3px 0 rgba(0, 0, 0, 0.08), 0 1px 2px -1px rgba(0, 0, 0, 0.05);
  --tv-shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.08), 0 2px 4px -2px rgba(0, 0, 0, 0.04);
  --tv-shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.03);
  --tv-shadow-glow: 0 0 20px rgba(59, 130, 246, 0.25);
}

[data-theme="dark"] {
  --tv-bg-body:       #070a12;
  --tv-bg-surface:    #0f172a;
  --tv-bg-surface-elevated: #162036;
  --tv-bg-subtle:     #131c2e;
  --tv-border-default: #1e293b;
  --tv-border-subtle:  #172338;
  --tv-border-strong:  #334155;

  --tv-text-main:     #f8fafc;
  --tv-text-muted:    #94a3b8;
  --tv-text-subtle:   #64748b;

  --tv-primary:       var(--tv-primary-500);
  --tv-primary-hover: var(--tv-primary-400);
  --tv-primary-light: rgba(59, 130, 246, 0.15);
  --tv-primary-text:  var(--tv-primary-300);

  --tv-success-bg: rgba(16, 185, 129, 0.15);
  --tv-warning-bg: rgba(245, 158, 11, 0.15);
  --tv-danger-bg:  rgba(239, 68, 68, 0.15);
  --tv-info-bg:    rgba(6, 182, 212, 0.15);

  --tv-shadow-xs: 0 1px 2px 0 rgba(0, 0, 0, 0.4);
  --tv-shadow-sm: 0 1px 3px 0 rgba(0, 0, 0, 0.4), 0 1px 2px -1px rgba(0, 0, 0, 0.3);
  --tv-shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -2px rgba(0, 0, 0, 0.3);
  --tv-shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -4px rgba(0, 0, 0, 0.4);
}
```

### B. Typography Scale & Font Hierarchy
- **Font Stack:** `'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`
- **Monospace Stack:** `'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, monospace`
- **Display 1 (Hero Title):** `2.75rem` (44px), `font-weight: 800`, `letter-spacing: -0.04em`, `line-height: 1.15`
- **Heading 1 (Page Title):** `1.875rem` (30px), `font-weight: 700`, `letter-spacing: -0.03em`, `line-height: 1.2`
- **Heading 2 (Section Title):** `1.375rem` (22px), `font-weight: 600`, `letter-spacing: -0.02em`
- **Heading 3 (Card Title):** `1.125rem` (18px), `font-weight: 600`, `letter-spacing: -0.01em`
- **Body Regular:** `0.9375rem` (15px), `font-weight: 400`, `line-height: 1.5`
- **Body Semibold:** `0.9375rem` (15px), `font-weight: 600`, `line-height: 1.5`
- **Small / Metadata:** `0.8125rem` (13px), `font-weight: 500`, `letter-spacing: 0.01em`
- **Micro Badge / Timestamp:** `0.6875rem` (11px), `font-weight: 600`, `text-transform: uppercase`, `letter-spacing: 0.05em`

### C. Radii, Transitions, and Spacing
- **Border Radii:**
  - `radius-sm`: `6px` (badges, small tags, tooltips)
  - `radius-md`: `10px` (inputs, buttons, pill cards)
  - `radius-lg`: `14px` (cards, dialogs, dropzones)
  - `radius-xl`: `20px` (modals, hero containers)
  - `radius-full`: `9999px` (status pills, avatar chips)
- **Transitions:**
  - Micro-interaction: `150ms cubic-bezier(0.16, 1, 0.3, 1)`
  - Layout transition: `250ms cubic-bezier(0.16, 1, 0.3, 1)`
  - Modal entrance: `300ms cubic-bezier(0.16, 1, 0.3, 1)`

---

## 2. Reusable Component Catalog

### 1. Application Sidebar (`.tv-sidebar`)
- Fixed-left navigation rail on desktop (`width: 260px`), collapsible to compact rail (`width: 72px`).
- Smooth drawer on viewports `< 992px` with full overlay backdrop.
- Grouped sections: Core Navigation, Workspaces, Administrative Governance, Account Profile.
- Active indicators with subtle left accent line and soft background tint.

### 2. Topbar Navigation (`.tv-topbar`)
- Breadcrumbs for contextual orientation.
- Global document search entry point with keyboard shortcut indicator (`Ctrl + K`).
- Quick actions (e.g. Upload button for owners).
- Theme toggle switch (Dark / Light).
- User profile dropdown with current RBAC role badge.

### 3. Metric & Statistic Cards (`.tv-stat-card`)
- Clean white/dark surface with a subtle 1px border.
- Top row: Metric label in uppercase small type + icon in rounded-pill container.
- Value in 32px bold type with subtle counter transition.
- Bottom row: Contextual sub-metric or status badge.

### 4. Enterprise Data Tables (`.tv-table`)
- Sticky headers with refined typography (`uppercase`, `font-size: 11px`, `letter-spacing: 0.06em`).
- Hover row background with 1px border transitions.
- Monospace styling for UUIDs, hashes, and IP addresses.
- Right-aligned quick action button groups with accessible icon tooltips.

### 5. File Upload Dropzone (`.tv-dropzone`)
- Drag-and-drop target with dashed border and animated pulse on drag-over.
- Embedded file details preview on selection (Name, Size, MIME type indicator).
- Integrated pre-flight size validation check (25 MB cap).

### 6. Status & Permission Pills (`.tv-badge`)
- **READ:** Cyan / Soft Blue (`bg: var(--tv-info-bg)`, `text: var(--tv-info)`)
- **EDIT:** Amber / Gold (`bg: var(--tv-warning-bg)`, `text: var(--tv-warning)`)
- **ADMIN:** Rose / Crimson (`bg: var(--tv-danger-bg)`, `text: var(--tv-danger)`)
- **OWNER:** Royal Indigo (`bg: var(--tv-primary-light)`, `text: var(--tv-primary)`)
- **SUCCESS / ACTIVE:** Emerald (`bg: var(--tv-success-bg)`, `text: var(--tv-success)`)

### 7. Form Controls (`.tv-input`, `.tv-select`)
- Integrated icons, clean focus rings with dual shadow (`0 0 0 3px rgba(59, 130, 246, 0.2)`).
- Inline error messages with error icon and smooth height transition.
- Password input with toggle visibility eye icon.

### 8. Modal & Confirmation Dialogs (`.tv-modal`)
- Centered layout, blurred backdrop (`backdrop-filter: blur(8px)`).
- Explicit danger confirmations for revocation and document deletion.
- Auto-focus on primary action or cancel button.

---

## 3. Accessibility & Usability Standards (WCAG 2.2 AA)
1. **Contrast Ratio:** Text-to-background contrast exceeds `4.5:1` for regular text and `3:1` for large text across both light and dark themes.
2. **Focus Visibility:** Clear 2px dual-color focus indicators (`:focus-visible`) for all interactive elements.
3. **Reduced Motion:** All transitions and animations respect `@media (prefers-reduced-motion: reduce)`.
4. **Touch Target Size:** Interactive buttons and touch targets meet minimum 44x44px requirements on mobile devices.

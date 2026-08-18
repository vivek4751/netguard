# NetGuard Demo Accessibility Verification

The NetGuard demo was reviewed against the interactive controls and motion shown in the single-page showcase.

| Check | Implementation and verification |
|---|---|
| Keyboard focus | Hero, demo, report-copy, and navigation controls use native interactive elements. A visible `:focus-visible` outline is applied to buttons and links. |
| Demo status | The analysis status is a polite live region, so the transition from ready to running to complete is announced without interrupting the user. |
| Progress semantics | The lifecycle meter uses `role="progressbar"` with an accessible label and current/min/max values. |
| Motion preference | A `prefers-reduced-motion: reduce` rule disables nonessential motion and smooth scrolling. |
| Touch layout | The showcase was visually verified at 390px and 1280px widths; tabular content remains horizontally scrollable instead of collapsing data. |
| Interaction regression | The UI test verifies start, intermediate 27% progress / Dispatcher phase, completion, and Run Again reset behavior. |

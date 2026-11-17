---
trigger: model_decision
description: Use when creating or editing Django templates, CSS, JavaScript, or anything the user sees on screen.
---

# UI rules (full spec: `docs/06_UI_GUIDELINES.md`)

- Django templates extending `templates/base.html`. One stylesheet `static/css/style.css`, one script `static/js/app.js`.
- No inline styles, no Bootstrap/Tailwind/React/jQuery, no CDN, no external fonts or icons, no chart library. Light theme only.
- Use only the CSS variables and components in `docs/06` (`.card`, `.badge--*`, `.chip`, `.finding`, `.table`, `.notice`, `.btn`). Do not invent new visual styles.
- Result page section order is fixed: assessment, threat intel, local findings, ML, enrichment, unavailable checks, parsed components, limitation notice.
- Show the submitted URL only as defanged plain text in `<code>` via the `defang` filter. Never a link or button, no `urlize`, no `|safe` on user data.
- Show the risk score as "N / 100, higher means more suspicious" with the points table and coverage line. Inconclusive shows no score.
- Wording: "High risk", "Medium risk", "Low observed risk", "Inconclusive". Never "Safe". Unavailable checks are never shown as "no match".
- Every badge carries a text label (colour is never the only signal).

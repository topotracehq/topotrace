# TopoTrace brand guide

**Turn Infrastructure Into Insight** is the official tagline. Use **Infrastructure Into Insight** in compact navigation. Product spelling is TopoTrace; the company is TopoTrace LLC.

## Identity

The vector mark refines the supplied concept into a navy hexagon with two T shapes, topographic contours, and an orange route connecting cyan endpoints. It is a fresh vector interpretation, not an exact tracing of the concept board.

Assets live in `internal/webui/static/img/`: `topotrace-mark.svg`, simplified `topotrace-icon.svg`, `topotrace-mono.svg`, and `topotrace-lockup-light.svg` / `topotrace-lockup-dark.svg`. SVG backgrounds are transparent except the dark lockup. Wordmarks use Segoe UI with an Arial fallback; keep text editable, and outline it in a design editor before sending to a print vendor.

Leave at least one route-node diameter of clear space around the mark. Use the simplified icon below 48px; use the full mark at 48px or larger. Avoid tagline lockups below 300px wide. Never stretch, rotate, add shadows, or recolor individual parts.

| Color | Value | Use |
|---|---|---|
| Midnight Navy | #0B1F33 | Navigation, text, mark |
| Signal Orange | #F97316 | Route and brand accents |
| Deep Blue | #163B63 | Supporting surfaces |
| Trace Cyan | #39B8C8 | Route endpoints |
| Cloud White | #F4F7FA | Page background, reversed mark |

Use dark orange #9A3E08 for small text on white; bright brand orange is for accents. Product typography follows the system sans-serif stack, with bold, tightly spaced wordmarks and readable regular-weight body text.

## Rename history

TopoTrace was originally developed under the working name Muster. As of
2026-09-21 (commit `3a57417`), the rename is complete at every layer,
not just the presentation name: the Go module path, binary and service
names, config file paths and locations, the `TOPOTRACE_*` environment
variable prefix, the agent-to-server wire protocol (`TOPOTRACE1`), API
fields, audit event identifiers, browser storage keys, session cookies,
and every agent script across all supported platforms all use the
TopoTrace name. A fresh clone or install has no remaining
Muster-named component.

Matching PNG exports include 512px icons and 1800px lockups. PNG favicons are supplied at 16, 32, and 180px.

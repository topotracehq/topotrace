# Dashboard navigation and document reader

TopoTrace's dashboard uses a shared visual system for navigation, forms, evidence
tables, reports, and documentation. This interface refresh is included in release
2026.09.18.5. It changes presentation and navigation, not permissions or the scope
of collected data.

## Find your workspace

The sidebar keeps page names visible and groups them by task:

| Section | Pages | Use it to |
|---|---|---|
| Overview | Fleet, Hosts, Visibility, Entity map | Understand inventory, reporting, and relationships |
| Operations | Work queue, Board, Compliance, Agents | Prioritize findings, organize devices, and manage enrollment |
| Workspace | Ask TopoTrace, Tools, Docs, Settings | Ask evidence questions and manage your workspace |

The header shows your current section. Inventory search appears on Hosts. Account
opens the existing token controls; this is the same authentication mechanism as
before. On smaller screens, select Menu to open navigation. Escape or Close menu
closes it. Keyboard users can use Skip to content to reach the current page.

Work queue separates Findings, Ownership, Dynamic groups, and Change plans into
sections so administrative controls do not sit below every finding. Filtering and
saved views still apply to the Findings section.

## Read and share a guide

Open Docs to browse guides grouped under Start here, Operate, and Reference. Find
a guide searches guide titles, not the full documentation text. Each article has
a reading-time estimate and an On this page section for jumping to headings.

Copy link provides a direct link such as `/#/docs/recovery`. If clipboard access
is unavailable, the reader displays the link for manual copying. Browser Back
and Forward navigate between guides. Print guide prints the article without the
application navigation; your browser can save that output as a PDF.

Code samples remain selectable text. Wide reference tables scroll within the
article on small screens. Links in documentation are restricted to supported web
and local destinations; document text is not interpreted as executable HTML.

## Present evidence

Visibility keeps its demo label, counts, and evidence tabs prominent. The demo's
three-minute walkthrough is available in a collapsible section. Presentation mode
hides the sidebar and setup controls to give the evidence more space. Escape or
Exit presentation returns to the normal layout. This does not change permissions.

The executive report uses the same typography and colors, with an embedded company
logo, clear summary sections, and print-friendly tables. Demo reports remain
marked as fictional. The report's content, score definitions, and data scope are
unchanged.

## Update an existing installation

Install the new server binary and restart TopoTrace, then refresh the browser with
Ctrl+F5. The dashboard and its documentation are embedded in that binary; copying
the source files alone does not update the running application. Existing URLs,
saved views, credentials, and workflow records continue to work.
## Fleet workspace additions

Open **Today** for the current attention summary. Search, collections,
comparison, the inbox, integration health, onboarding, and report selection
are connected through its feature tabs. Site operations provides reviewed
discovery and deployment jobs. See [Fleet workspace](fleet-workspace.md) and
[Discovery & remote deployment](site-operations.md) for permissions and setup.
## Fleet workspace additions

Open **Today** for the current attention summary. Search, collections,
comparison, the inbox, integration health, onboarding, and report selection
are connected through its feature tabs. Site operations provides reviewed
discovery and deployment jobs. See [Fleet workspace](fleet-workspace.md) and
[Discovery & remote deployment](site-operations.md) for permissions and setup.

# Entity map

TopoTrace already knew every one of these relationships. What it could not
do was show them together.

A host's page listed its vulnerabilities. The Compliance tab listed
software violations. Another card listed risky browser extensions.
Nothing answered "which hosts share this CVE," or "what does this one
rule actually touch," or "is that extension on one machine or half the
fleet." Those are relationship questions, and a list is the wrong shape
for them.

The Entity map tab (`GET /api/entities`, `internal/entitygraph`) is
that one picture: entities as typed nodes, the relationships between
them as typed edges, laid out and traversable.

This is a different picture from the Fleet tab's network and asset map
(`internal/graph`), which is about topology: what sits on which subnet,
and which swept addresses turned out to be hosts nobody manages. Both
still exist because they answer different questions.

## What counts as an entity

| Kind | Family | Drawn as | Where it comes from |
| --- | --- | --- | --- |
| host | asset | circle | every enrolled host |
| group | asset | rounded square | the distinct values of `Host.Group`, plus a synthetic `(ungrouped)` |
| package | asset | hexagon | notable entries in `installed_software` (see below) |
| cve | finding | diamond | `vuln.Finding`, both TopoTrace's own package matches and imported scanner findings |
| certificate | finding | triangle | `tls_certificates` entries that are expiring or expired |
| extension | finding | pentagon | browser extensions that are risky or on more than one host |
| rule | policy | square | every `model.Rule` and `model.SoftwareRule` |

Relationship types are `member` (host is in a group), `installs`
(host has a package or extension), `affected-by` (package carries a
CVE), `exposed-to` (host has an imported finding with no package),
`presents` (host serves a certificate), `governs` (rule covers a
group), and `indirect`, which is explained under filters below.

## Keeping it readable

A fleet of fifteen hosts carries thousands of installed packages. A
node per package per host is a hairball that answers nothing, so a
package earns a node only by being notable: it carries a known
vulnerability, it violates a software rule, it matches a shadow-AI
signature, or it is a licensed product in `internal/sprawl`'s catalog.
On the demo fleet that turns thousands of packages into about twenty.

Certificates appear only when they are expiring or expired, and
extensions only when they are risky or installed on more than one host.
The rule behind all three: a node has to be either something an
operator would act on, or something that links two hosts together. A
healthy certificate on one host is neither, and a degree-one leaf node
is just ink.

There is also a hard cap (`entitygraph.DefaultMaxNodes`, 300). When it
bites, the lowest-degree nodes of the most expendable kinds go first,
and hosts, groups and rules are always kept, so the skeleton of the
picture survives. The response says how many were dropped and the
dashboard says so too.

## Reading it

Color is the **family**, shape is the **kind**, a ring is **status**,
and size is **degree** (how many things the entity touches, so hubs
look like hubs).

Three family colors, not seven kind colors, and that was a measured
decision rather than a taste one. In a node-link diagram any two nodes
can end up side by side, so a categorical palette has to separate every
possible pair, not just neighbors in a legend. Run the seven hues a
kind-colored version would need through a colorblind-separation check
and it fails hard: the worst pair lands at a perceptual distance of 3.2
for protanopia against a floor of 8, and 12.9 for normal vision against
a floor of 15. Three hues pass the same all-pairs check comfortably
(worst 9.2 and 24.0). So family carries color, kind carries shape, and
nothing is identified by color alone. Status keeps its own reserved red
and amber, drawn as a ring rather than a fill, and is always restated
in words in the tooltip, the detail pane and the table.

Every node also carries a direct label where one fits. Which labels fit
is worked out server-side against the real geometry: most-connected
first, four candidate positions each (below, above, right, left), and
skipped entirely rather than drawn over a neighbor. The names that lose
that competition are still in the hover tooltip and the table view.

## Using it

Click any entity to pivot the map around it. The view narrows to that
entity's neighborhood, the hop count becomes adjustable (one to four),
and a detail pane lists every relationship in words with a link through
to the host page where there is one. Click it again, or "Whole fleet,"
to zoom back out.

The filter row toggles entity kinds. "Show table" is the same graph as
a sortable list of entities with their kind, detail, status and link
count, which is the non-visual route to the same facts.

### Indirect edges

Filtering has a subtlety worth knowing about. Ask for hosts and CVEs
only, and the package nodes that join them are gone, which would
silently drop the very links the question was about. So when a filter
removes an intermediate entity, its surviving neighbors are joined
directly by an `indirect` edge, drawn dotted and named in the legend.

A contracted path is a derived fact, not something the fleet reported,
which is why it looks different. Two limits keep it honest: only
entities of different families are joined, so a package shared by
fifteen hosts does not explode into a hundred host-to-host edges, and a
removed entity with more than 24 surviving neighbors is skipped.

## The API

```
GET /api/entities?types=host,cve&focus=<node id>&depth=2&max=300
GET /api/entities/kinds
```

Both `readonly`. Every parameter is optional: `types` filters by kind
(naming no valid kind is a 400 rather than a silent full graph),
`focus` narrows to one entity's neighborhood, `depth` sets the hop
count (capped at 4), and `max` overrides the node cap. The response
carries nodes with their computed positions, radii, status and label
placement, the edges, per-kind counts for the whole fleet (not just
what was drawn), and, when focused, that node plus its relationships.

`GET /api/entities/kinds` serves the legend's own vocabulary from the
binary, so the dashboard's filter row and legend cannot drift from what
the builder actually produces.

Group-scoped API keys see only their own hosts here, and therefore only
the entities those hosts reach, the same as every other fleet view.

## Layout

Positions are computed server-side and the client only draws, the same
division of labor as `internal/graph`. It is a fixed-iteration
force-directed relaxation with no randomness anywhere: initial
positions come from a stable sort rather than a seed, so the same fleet
always lays out identically.

Three passes follow the relaxation, and the order matters. `fit` scales
the result into the canvas. `separate` then pushes overlapping nodes
apart, which has to happen after the scaling rather than before, or
scaling down would put them back on top of each other. This pass is
also the only reason several fleet-wide rules are visible at all: four
rules that all govern the same six groups are topologically identical,
so the relaxation settles them on exactly the same coordinates.
`clamp` keeps everything inside the canvas afterwards, and then labels
are assigned.

## Data model

For the static version of this picture, the shapes TopoTrace persists and
how they reference each other, see `docs/data-model.md`. That page and
its diagram are generated from `internal/model/types.go` by
`tools/erd`, so they cannot drift from the code:

```
go run ./tools/erd           # regenerate docs/data-model.{md,svg}
go run ./tools/erd -check    # fail if either is out of date
```

Entities and fields are parsed straight out of the Go source.
Relationships cannot be, since Go has no foreign keys and TopoTrace
carries no ORM tags, so they are declared in the generator and then
checked against the parsed types: a declaration naming a struct or
field that no longer exists is a hard error rather than a quietly wrong
diagram.

## What is verified

`internal/entitygraph` is unit tested for entity sharing across hosts,
the noise filters, rule scoping, the type filter and its counts, focus
narrowing by depth, the node cap keeping the skeleton, edge
contraction, layout determinism, non-overlap and label assignment. The
whole tab was then driven end to end in a headless browser against the
seeded fleet: 62 entities and 82 relationships rendered with no console
errors, pivoting onto a shared package and onto a host, the hop-count
selector, the kind filters with contraction, the table view and the
hover tooltips.

The palette was checked with a runnable colorblind-separation
validator, at the three-hue set actually shipped and at the seven-hue
set that was rejected. The numbers quoted above are that tool's output,
against this dashboard's real background color.

Not verified: any fleet large enough to hit the 300-node cap in a way
that matters, since the demo fleet produces 62. The cap's behavior is
unit tested at a small cap, not observed on a thousand-host fleet.

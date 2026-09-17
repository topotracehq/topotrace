# Air-gapped reporting

For a host with **no network route to Muster at all** -- an isolated
OT/SCADA segment, a classified enclave, a box you just don't want
talking to anything -- there's no agent that can "call home." The
air-gapped path instead reuses the exact same local fact-collection
logic the normal Linux/macOS/Windows agent scripts already have, and
swaps the network send for a text blob a human carries across the gap.

There is no separate `agent/airgap` binary: it's a flag on the
existing scripts.

## Producing a report

```bash
# Linux/macOS host, no network path to Muster:
./muster-agent.sh --host-name db-enclave-03 --platform linux \
    --airgap-out /media/usb/db-enclave-03-report.json

# or print it to the terminal to retype/photograph/QR-encode by hand:
./muster-agent.sh --host-name db-enclave-03 --platform linux --airgap-out -
```

```powershell
# Windows host:
.\muster-agent.ps1 -HostName db-enclave-03 -Platform windows `
    -AirgapOut D:\db-enclave-03-report.json
```

This runs the *identical* capture step every other agent run does
(same commands, same `internal/cook/*.go` parsers on the receiving
end) and packages it into the same `tar.gz` -- the only difference is
what happens to the bytes afterward: instead of opening a TCP socket,
they're base64-encoded into a small JSON envelope:

```json
{"platform": "linux", "host": "db-enclave-03", "payload_b64": "H4sIAAAA..."}
```

and either written to the path you gave `--airgap-out`/`-AirgapOut`,
or printed to stdout if you passed `-` (handy for terminal-to-terminal
retyping over a KVM, or piping into a QR generator -- see below).

## Getting it to Muster

Carry that JSON by whatever means your air gap allows -- a USB drive,
retyping it by hand, a QR code -- to any machine that *can* reach
Muster, then either:

- Paste it into the **Agents** tab's **Air-gapped import** panel in the
  web UI, or
- `POST` it directly:

  ```bash
  curl -sS -X POST "http://<muster-host>:8080/api/airgap-report" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <enrollment-or-master-token>" \
      --data @db-enclave-03-report.json
  ```

The server decodes `payload_b64`, extracts it exactly the way the TCP
ingest daemon extracts a normal upload, and cooks it through the same
`cook.Pipeline` -- change tracking, staleness, posture, and
vulnerability correlation all just work, with zero air-gap-specific
code past the decode step (see `internal/api`'s `handleAirgapReport`).

Authorization is the same enrollment-token model as `mobile-report`:
create an enrollment for the host from the Agents tab first (or use the
server's master token, if it has one configured), same as any other
reporting path.

## About QR codes

Michael's original ask mentioned "a QR code or some encoded text like
base64" -- this ships the base64 side fully (it's the actual payload
format, works for a capture of any size, and is what
`POST /api/airgap-report` expects either way). It does **not** include
QR *generation*: Muster doesn't vendor a QR library (this project's
policy is a near-zero dependency footprint, and pulling one in here
would also need network access this dev environment didn't have when
writing this), and there's no QR *decoding* on the server side either
-- the "Air-gapped import" panel is a plain text box.

For a genuinely tiny capture where a QR code is worth the trouble
(most captures are tens of KB and won't fit in one QR code's ~3KB
practical text limit), the base64 text from `--airgap-out -` can be
fed into any general-purpose QR generator (a phone app, `qrencode` on
the receiving machine, a website) and scanned back with any QR reader
-- the round trip is just moving the same base64 string, nothing
Muster-specific to build or trust on either end. For anything bigger
than a trivial capture, a file on a USB drive is the realistic path.

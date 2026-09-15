// Package ingest is Muster's TCP front door: a lightweight, deliberately
// simple framed protocol agents use to push a captured data packet.
//
// Wire format, one request per connection:
//
//	MUSTER1 <platform> <host> <payload-bytes>\n
//	<payload-bytes> raw bytes of a gzip-compressed tar archive>
//
// The server replies with a single line and closes the connection:
//
//	OK <changes>\n     -- packet accepted, cooked, N fields changed since last time
//	ERR <message>\n    -- rejected; message is safe to log/display, never
//	                      raw internal error text
//
// This is a from-scratch design, not a port of anything -- picked because
// it's the simplest thing that (a) is a real length-prefixed protocol
// worth writing a decoder for by hand, matching the "concurrent TCP
// ingest daemon" pitch, and (b) is trivial for a test client or a real
// future agent in any language to implement: one line of ASCII, then N
// bytes.
package ingest

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

const protocolVersion = "MUSTER1"

// header is a parsed request line.
type header struct {
	Platform string
	Host     string
	Bytes    int64
}

var (
	// Keep these conservative -- this is a network-facing parser reading
	// attacker-shaped input before any auth layer exists (see server.go's
	// TODO on auth). Platform/host feed directly into filesystem paths
	// downstream, so they're restricted to a safe charset here, at the
	// earliest possible point, rather than trusted and sanitized later.
	maxHeaderLine = 512
	maxPayload    = int64(256 << 20) // 256MB per packet
)

func isSafeToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

func readHeader(r *bufio.Reader) (header, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return header{}, fmt.Errorf("reading header: %w", err)
	}
	if len(line) > maxHeaderLine {
		return header{}, fmt.Errorf("header line too long")
	}
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return header{}, fmt.Errorf("malformed header: want 4 fields, got %d", len(fields))
	}
	if fields[0] != protocolVersion {
		return header{}, fmt.Errorf("unsupported protocol %q", fields[0])
	}
	platform, host := strings.ToLower(fields[1]), fields[2]
	if !isSafeToken(platform) || !isSafeToken(host) {
		return header{}, fmt.Errorf("invalid platform/host")
	}
	n, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || n < 0 || n > maxPayload {
		return header{}, fmt.Errorf("invalid payload size")
	}
	return header{Platform: platform, Host: host, Bytes: n}, nil
}

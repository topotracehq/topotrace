package ingest

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"muster/internal/cook"
)

// Server is the TCP ingest daemon. One goroutine per connection --
// handleConn does the read/extract/cook work for a single agent packet
// and never touches another connection's state, so there's no locking
// needed at this layer (the store underneath does its own).
type Server struct {
	Addr       string
	RawBaseDir string
	Pipeline   *cook.Pipeline
	Logger     *slog.Logger

	// TODO before this ever listens on anything but localhost: agents
	// currently authenticate with nothing at all. A real deployment
	// needs at least a per-agent shared token in the header, or mTLS.
	// Called out here rather than silently shipped, since "here's
	// exactly the auth gap and why" is a more honest portfolio artifact
	// than pretending v1 already solved it.

	listener net.Listener
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// ListenAndServe blocks, accepting connections until ctx is cancelled or
// an unrecoverable listener error occurs.
func (s *Server) ListenAndServe(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("ingest: listen on %s: %w", s.Addr, err)
	}
	s.listener = ln
	s.log().Info("ingest listening", "addr", s.Addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutting down, not a real error
			}
			return fmt.Errorf("ingest: accept: %w", err)
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log := s.log().With("remote", remote)

	conn.SetDeadline(time.Now().Add(2 * time.Minute))

	reader := bufio.NewReader(conn)
	hdr, err := readHeader(reader)
	if err != nil {
		log.Warn("bad header", "err", err)
		fmt.Fprintf(conn, "ERR bad request\n")
		return
	}
	log = log.With("platform", hdr.Platform, "host", hdr.Host, "bytes", hdr.Bytes)

	snapshotDir := filepath.Join(s.RawBaseDir, hdr.Platform, hdr.Host, time.Now().UTC().Format("20060102T150405Z"))
	if err := extractPayload(reader, hdr.Bytes, snapshotDir); err != nil {
		log.Error("extract failed", "err", err)
		fmt.Fprintf(conn, "ERR could not process packet\n")
		return
	}

	changes, err := s.Pipeline.Cook(ctx, hdr.Platform, hdr.Host)
	if err != nil {
		log.Error("cook failed", "err", err)
		fmt.Fprintf(conn, "ERR packet stored but cooking failed\n")
		return
	}

	log.Info("packet cooked", "changes", len(changes))
	fmt.Fprintf(conn, "OK %d\n", len(changes))
}

// extractPayload reads exactly n bytes from r as a gzip-compressed tar
// archive and extracts it into destDir. Guards against zip-slip (entries
// whose name would resolve outside destDir) since this is untrusted
// network input landing directly on disk.
func extractPayload(r io.Reader, n int64, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("creating snapshot dir: %w", err)
	}

	limited := io.LimitReader(r, n)
	gzr, err := gzip.NewReader(limited)
	if err != nil {
		return fmt.Errorf("opening gzip stream: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue // skip dirs/symlinks/etc -- only plain capture files expected
		}

		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			return fmt.Errorf("tar entry %q escapes destination", hdr.Name)
		}
		destPath := filepath.Join(destDir, cleanName)

		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
	return nil
}

/*******************************************************************************
 * @file         server.go
 * @brief        Part of the Muster ingest module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package ingest

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"muster/internal/agenthealth"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"muster/internal/cook"
	"muster/internal/model"
	"muster/internal/operations"
	"muster/internal/store"
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

	// Token, when non-empty, is the shared secret every MUSTER1 and
	// MUSTER1-RESULT request must present, compared in constant time.
	// Left empty, the daemon accepts any request unauthenticated --
	// matching every earlier round's demo-friendly default -- but then
	// remediation stays off entirely: internal/api's handleQueueAction
	// refuses to queue an action at all unless the server was started
	// with -auth-token, so "no token configured" means "no path to a
	// host ever running anything," not "auth silently optional."
	Token string

	listener net.Listener
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// authorized reports whether token matches the server's configured
// master secret -- used for MUSTER1-RESULT (remediation-result)
// reports, which always require the master token or nothing (no
// enrollment-token path here; see authorizedUpload for the MUSTER1
// upload path, which additionally accepts a host-scoped enrollment
// token). An empty s.Token means auth is off entirely (every token,
// including the "-" sentinel, is accepted); a non-empty s.Token requires
// an exact, constant-time match, so "-" (no credential presented) is
// always rejected once auth is on.
func (s *Server) authorized(token string) bool {
	if s.Token == "" {
		return true
	}
	return token != noToken && subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) == 1
}

// sha256Hex mirrors internal/api's helper of the same name -- kept as
// its own three lines here rather than factored into a shared package,
// since that's the whole function and this package otherwise has no
// reason to depend on internal/api or vice versa.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// authorizedUpload reports whether token authorizes a MUSTER1 upload for
// host specifically -- broader than authorized: it also accepts a live
// enrollment token (internal/model.Enrollment, minted via POST
// /api/enrollments), but ONLY when that enrollment's Host matches this
// exact upload's host. A matching still-pending enrollment is flipped to
// "enrolled" here, on its very first successful use -- the one-way
// transition the dashboard's Agents page polls for. Enrollment tokens
// are deliberately narrower than the master token in one more way too:
// they never authorize a MUSTER1-RESULT (remediation-result) report --
// see authorized's doc comment -- so a newly self-enrolled host can push
// fact reports immediately but can't act as a credential for anything
// else.
func (s *Server) authorizedUpload(ctx context.Context, token, host string) bool {
	if s.Token == "" {
		return true
	}
	if token != noToken && subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) == 1 {
		return true
	}
	if s.Pipeline == nil || s.Pipeline.Store == nil || token == noToken {
		return false
	}
	enr, ok, err := s.Pipeline.Store.FindEnrollmentByHash(ctx, sha256Hex(token))
	if err != nil || !ok || enr.Host != host {
		return false
	}
	if enr.Status != "enrolled" {
		if err := s.Pipeline.Store.MarkEnrolled(ctx, enr.ID); err != nil {
			s.log().Error("marking enrollment enrolled", "err", err)
		}
	}
	return true
}

// ListenAndServe blocks, accepting connections until ctx is cancelled or
// an unrecoverable listener error occurs.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Token == "" {
		s.log().Warn("ingest daemon running without -auth-token -- any client that can reach this port can submit data as any host, and remediation actions stay unavailable until a token is set")
	}
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
	fields, err := readLine(reader)
	if err != nil || len(fields) == 0 {
		log.Warn("bad header", "err", err)
		fmt.Fprintf(conn, "ERR bad request\n")
		return
	}

	switch fields[0] {
	case protocolUpload:
		s.handleUpload(ctx, conn, reader, fields, log)
	case protocolResult:
		s.handleResult(ctx, conn, reader, fields, log)
	default:
		log.Warn("unsupported protocol", "verb", fields[0])
		fmt.Fprintf(conn, "ERR bad request\n")
	}
}

func (s *Server) handleUpload(ctx context.Context, conn net.Conn, reader *bufio.Reader, fields []string, log *slog.Logger) {
	hdr, err := readUploadHeader(fields)
	if err != nil {
		log.Warn("bad header", "err", err)
		fmt.Fprintf(conn, "ERR bad request\n")
		return
	}
	log = log.With("platform", hdr.Platform, "host", hdr.Host, "bytes", hdr.Bytes)

	if !s.authorizedUpload(ctx, hdr.Token, hdr.Host) {
		log.Warn("unauthorized upload")
		_ = agenthealth.Failure(ctx, s.Pipeline.Store, hdr.Host, "unauthorized upload (bad or missing token)", time.Now().UTC())
		fmt.Fprintf(conn, "ERR unauthorized\n")
		return
	}

	snapshotDir := filepath.Join(s.RawBaseDir, hdr.Platform, hdr.Host, time.Now().UTC().Format("20060102T150405Z"))
	if err := ExtractPayload(reader, hdr.Bytes, snapshotDir); err != nil {
		log.Error("extract failed", "err", err)
		_ = agenthealth.Failure(ctx, s.Pipeline.Store, hdr.Host, "payload could not be extracted: "+err.Error(), time.Now().UTC())
		fmt.Fprintf(conn, "ERR could not process packet\n")
		return
	}

	changes, err := s.Pipeline.Cook(ctx, hdr.Platform, hdr.Host)
	if err != nil {
		log.Error("cook failed", "err", err)
		_ = agenthealth.Failure(ctx, s.Pipeline.Store, hdr.Host, "cook failed: "+err.Error(), time.Now().UTC())
		fmt.Fprintf(conn, "ERR packet stored but cooking failed\n")
		return
	}

	log.Info("packet cooked", "changes", len(changes))
	fmt.Fprintf(conn, "OK %d\n", len(changes))

	s.deliverPendingAction(ctx, conn, hdr.Host, log)
}

// deliverPendingAction hands the oldest undelivered queued action for
// host to whatever just successfully reported in, as a second reply
// line. See internal/remediate for the allow-list a <verb> can ever be,
// and internal/api's handleQueueAction for the only path that creates
// one -- always behind the same operator token, never reachable from an
// unauthenticated caller. Best-effort: a failure here never undoes the
// OK the upload already earned.
func (s *Server) deliverPendingAction(ctx context.Context, conn net.Conn, host string, log *slog.Logger) {
	if s.Pipeline == nil || s.Pipeline.Store == nil {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	actions, err := s.Pipeline.Store.ListActions(ctx, host)
	if err != nil {
		log.Error("checking pending action", "err", err)
		return
	}
	var action model.Action
	for _, candidate := range actions {
		if candidate.Delivered || candidate.Status != "" {
			continue
		}
		allowed, err := operations.DeliveryAllowed(ctx, s.Pipeline.Store, candidate, time.Now().UTC())
		if err != nil {
			log.Error("checking maintenance window", "err", err)
			return
		}
		if allowed && (action.ID == "" || candidate.QueuedAt.Before(action.QueuedAt)) {
			action = candidate
		}
	}
	if action.ID == "" {
		return
	}
	arg := action.Arg
	if arg == "" {
		arg = "-"
	}
	if _, err := fmt.Fprintf(conn, "ACTION %s %s %s\n", action.ID, action.Verb, arg); err != nil {
		log.Error("sending action", "err", err)
		return
	}
	if err := s.Pipeline.Store.MarkActionDelivered(ctx, action.ID); err != nil {
		log.Error("marking action delivered", "err", err)
		return
	}
	log.Info("delivered action", "action_id", action.ID, "verb", action.Verb)
}

// handleResult processes a MUSTER1-RESULT connection: an agent reporting
// what happened when it executed an action delivered on an earlier
// upload. Never executes anything itself -- this is purely a record of
// what the agent says it already did.
func (s *Server) handleResult(ctx context.Context, conn net.Conn, reader *bufio.Reader, fields []string, log *slog.Logger) {
	hdr, err := readResultHeader(fields)
	if err != nil {
		log.Warn("bad result header", "err", err)
		fmt.Fprintf(conn, "ERR bad request\n")
		return
	}
	log = log.With("action_id", hdr.ActionID, "status", hdr.Status)

	if !s.authorized(hdr.Token) {
		log.Warn("unauthorized result")
		fmt.Fprintf(conn, "ERR unauthorized\n")
		return
	}

	detail, err := io.ReadAll(io.LimitReader(reader, hdr.Bytes))
	if err != nil {
		log.Error("reading result detail", "err", err)
		fmt.Fprintf(conn, "ERR could not read result\n")
		return
	}

	if s.Pipeline == nil || s.Pipeline.Store == nil {
		fmt.Fprintf(conn, "ERR server has no store configured\n")
		return
	}
	if err := s.Pipeline.Store.RecordActionResult(ctx, hdr.ActionID, hdr.Status, string(detail)); err != nil {
		if errors.Is(err, store.ErrActionNotFound) {
			fmt.Fprintf(conn, "ERR unknown action\n")
			return
		}
		log.Error("recording action result", "err", err)
		fmt.Fprintf(conn, "ERR could not record result\n")
		return
	}
	log.Info("recorded action result")
	fmt.Fprintf(conn, "OK\n")
}

// ExtractPayload reads exactly n bytes from r as a gzip-compressed tar
// archive and extracts it into destDir. Guards against zip-slip (entries
// whose name would resolve outside destDir) since this is untrusted
// input landing directly on disk -- exported so internal/api's air-gap
// report handler (a base64-over-HTTP alternative delivery path for the
// exact same payload shape) can reuse it rather than duplicating the
// zip-slip-safe extraction logic.
func ExtractPayload(r io.Reader, n int64, destDir string) error {
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

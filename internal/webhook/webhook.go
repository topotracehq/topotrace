// Package webhook is Muster's outbound notification path: on a notable
// event (a policy or software violation, a remediation proposed,
// approved or executed, a violation resolved), deliver a small payload
// to every configured Sink -- generic webhook URLs, a Slack or Teams
// channel, a Jira project, a ServiceNow instance.
//
// Deliveries go through a durable queue: an event is written to the
// Store (one model.Document per pending delivery) before any network
// call, a background worker attempts each with exponential backoff, and
// a delivery that exhausts its attempts is kept as "dead" so an
// operator can see what never arrived instead of it vanishing into a
// log line. A restart resumes whatever was pending. This replaced the
// original "one attempt, one retry, then a warning" behavior once the
// number of things that could be on the other end grew past a single
// URL. Without a Store (tests, or a Dispatcher built with New), the
// queue is in-memory and the semantics are otherwise identical.
package webhook

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"muster/internal/model"
	"muster/internal/store"
)

// Event is the payload delivered to every configured sink.
type Event struct {
	Type      string    `json:"type"` // "host_new", "host_stale", "policy_violation", "software_violation", "violation_resolved", "remediation_proposed", "remediation_executed", "test"
	Host      string    `json:"host,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// QueueKind is the model.Document kind pending deliveries are stored as.
const QueueKind = "notify_queue"

// MaxAttempts is how many times one delivery is tried before it's dead.
const MaxAttempts = 6

// backoff returns how long to wait before attempt n (1-based) is retried.
func backoff(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 2 * time.Second
	case 2:
		return 15 * time.Second
	case 3:
		return time.Minute
	case 4:
		return 5 * time.Minute
	default:
		return 30 * time.Minute
	}
}

// Delivery is one queued (event, sink) pair and its attempt history.
type Delivery struct {
	ID          string    `json:"id"`
	Sink        string    `json:"sink"`
	Event       Event     `json:"event"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt"`
	LastError   string    `json:"last_error,omitempty"`
	Dead        bool      `json:"dead"`
	CreatedAt   time.Time `json:"created_at"`
	DeliveredAt time.Time `json:"delivered_at,omitempty"`
}

// Dispatcher fans Events out to its Sinks through the queue. A nil
// Dispatcher is safe to call Send/Count on (no-ops), so callers never
// branch on "are notifications configured."
type Dispatcher struct {
	sinks  []Sink
	byName map[string]Sink
	store  store.Store // nil means in-memory queue only
	log    *slog.Logger

	mu      sync.Mutex
	pending map[string]*Delivery
	dead    []Delivery // most recent MaxDead kept for inspection
	seq     int64
	wake    chan struct{}
	now     func() time.Time // injectable clock for tests
}

// MaxDead caps how many dead deliveries are kept in memory for the API.
const MaxDead = 100

// New returns a Dispatcher with one URLSink per url (may be empty) and
// no durable store -- the original constructor, kept for callers and
// tests that only want generic webhooks.
func New(urls []string, log *slog.Logger) *Dispatcher {
	sinks := make([]Sink, 0, len(urls))
	for _, u := range urls {
		sinks = append(sinks, &URLSink{URL: u, Client: &http.Client{Timeout: 10 * time.Second}})
	}
	return NewWithSinks(sinks, nil, log)
}

// NewWithSinks returns a Dispatcher over sinks, persisting its queue to
// st when non-nil (and resuming any deliveries found there).
func NewWithSinks(sinks []Sink, st store.Store, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	d := &Dispatcher{
		sinks: sinks, byName: map[string]Sink{}, store: st, log: log,
		pending: map[string]*Delivery{}, wake: make(chan struct{}, 1), now: func() time.Time { return time.Now().UTC() },
	}
	for _, s := range sinks {
		d.byName[s.Name()] = s
	}
	if st != nil {
		d.resume()
	}
	return d
}

// resume reloads pending deliveries from the store after a restart.
func (d *Dispatcher) resume() {
	docs, err := d.store.ListDocuments(context.Background(), QueueKind)
	if err != nil {
		d.log.Error("notify: reloading queue", "err", err)
		return
	}
	for _, doc := range docs {
		var del Delivery
		if json.Unmarshal(doc.Data, &del) != nil {
			continue
		}
		if n, err := strconv.ParseInt(del.ID, 10, 64); err == nil && n > d.seq {
			d.seq = n
		}
		if del.Dead {
			d.dead = append(d.dead, del)
			continue
		}
		if _, ok := d.byName[del.Sink]; !ok {
			// the sink was removed from config since -- nothing can
			// deliver it; drop it rather than retry forever
			_ = d.store.DeleteDocument(context.Background(), QueueKind, del.ID)
			continue
		}
		d.pending[del.ID] = &del
	}
	// keep the dead-letter list bounded on disk as well as in memory
	if len(d.dead) > MaxDead {
		for _, old := range d.dead[:len(d.dead)-MaxDead] {
			_ = d.store.DeleteDocument(context.Background(), QueueKind, old.ID)
		}
		d.dead = d.dead[len(d.dead)-MaxDead:]
	}
	if len(d.pending) > 0 {
		d.log.Info("notify: resumed queued deliveries", "count", len(d.pending))
	}
}

// Count reports how many sinks d delivers to. Safe on nil.
func (d *Dispatcher) Count() int {
	if d == nil {
		return 0
	}
	return len(d.sinks)
}

// SinkNames lists the configured sinks, for the settings API.
func (d *Dispatcher) SinkNames() []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, len(d.sinks))
	for _, s := range d.sinks {
		out = append(out, s.Name())
	}
	return out
}

// Send enqueues evt for every sink that accepts its type and returns
// immediately; the worker (see Run) delivers. Never blocks on the
// network and never returns an error: a sink being down must not
// break whatever triggered the event.
func (d *Dispatcher) Send(evt Event) {
	if d == nil || len(d.sinks) == 0 {
		return
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = d.now()
	}
	d.mu.Lock()
	for _, s := range d.sinks {
		if !s.Accepts(evt.Type) {
			continue
		}
		d.seq++
		del := &Delivery{ID: strconv.FormatInt(d.seq, 10), Sink: s.Name(), Event: evt, NextAttempt: d.now(), CreatedAt: d.now()}
		d.pending[del.ID] = del
		d.persist(del)
	}
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// persist writes one delivery's current state. Must hold d.mu.
func (d *Dispatcher) persist(del *Delivery) {
	if d.store == nil {
		return
	}
	data, err := json.Marshal(del)
	if err != nil {
		return
	}
	if err := d.store.PutDocument(context.Background(), model.Document{Kind: QueueKind, ID: del.ID, Data: data}); err != nil {
		d.log.Error("notify: persisting delivery", "id", del.ID, "err", err)
	}
}

func (d *Dispatcher) unpersist(id string) {
	if d.store == nil {
		return
	}
	if err := d.store.DeleteDocument(context.Background(), QueueKind, id); err != nil {
		d.log.Error("notify: removing delivery", "id", id, "err", err)
	}
}

// Run is the delivery worker: blocks until ctx is done, waking on Send
// or every few seconds to retry whatever is due. cmd/muster starts it
// with `go hooks.Run(ctx)`.
func (d *Dispatcher) Run(ctx context.Context) {
	if d == nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		d.DeliverDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-d.wake:
		case <-ticker.C:
		}
	}
}

// DeliverDue attempts every pending delivery whose NextAttempt has
// passed, once each. Exported so tests and the test-event endpoint can
// drive the queue without the worker.
func (d *Dispatcher) DeliverDue(ctx context.Context) {
	d.mu.Lock()
	var due []*Delivery
	now := d.now()
	for _, del := range d.pending {
		if !del.NextAttempt.After(now) {
			due = append(due, del)
		}
	}
	d.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].ID < due[j].ID })
	for _, del := range due {
		d.attempt(ctx, del)
	}
}

func (d *Dispatcher) attempt(ctx context.Context, del *Delivery) {
	sink, ok := d.byName[del.Sink]
	if !ok {
		d.finish(del, false, "sink no longer configured")
		return
	}
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := sink.Deliver(actx, del.Event)
	cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	del.Attempts++
	if err == nil {
		del.DeliveredAt = d.now()
		delete(d.pending, del.ID)
		d.unpersist(del.ID)
		d.log.Info("notify: delivered", "sink", del.Sink, "event", del.Event.Type, "attempts", del.Attempts)
		return
	}
	del.LastError = err.Error()
	if del.Attempts >= MaxAttempts {
		del.Dead = true
		delete(d.pending, del.ID)
		d.dead = append(d.dead, *del)
		if len(d.dead) > MaxDead {
			d.dead = d.dead[len(d.dead)-MaxDead:]
		}
		d.persist(del)
		d.log.Warn("notify: delivery dead after max attempts", "sink", del.Sink, "event", del.Event.Type, "err", err)
		return
	}
	del.NextAttempt = d.now().Add(backoff(del.Attempts))
	d.persist(del)
	d.log.Warn("notify: delivery failed, will retry", "sink", del.Sink, "event", del.Event.Type, "attempt", del.Attempts, "retry_in", backoff(del.Attempts).String(), "err", err)
}

func (d *Dispatcher) finish(del *Delivery, ok bool, msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.pending, del.ID)
	d.unpersist(del.ID)
	if !ok {
		del.Dead, del.LastError = true, msg
		d.dead = append(d.dead, *del)
	}
}

// Status is a snapshot of the queue for the API.
type Status struct {
	Sinks   []string   `json:"sinks"`
	Pending []Delivery `json:"pending"`
	Dead    []Delivery `json:"dead"`
}

// Snapshot returns the queue's current state, pending oldest first and
// dead newest first.
func (d *Dispatcher) Snapshot() Status {
	if d == nil {
		return Status{Sinks: []string{}, Pending: []Delivery{}, Dead: []Delivery{}}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st := Status{Sinks: d.SinkNames(), Pending: make([]Delivery, 0, len(d.pending)), Dead: make([]Delivery, 0, len(d.dead))}
	for _, del := range d.pending {
		st.Pending = append(st.Pending, *del)
	}
	sort.Slice(st.Pending, func(i, j int) bool { return st.Pending[i].CreatedAt.Before(st.Pending[j].CreatedAt) })
	for i := len(d.dead) - 1; i >= 0; i-- {
		st.Dead = append(st.Dead, d.dead[i])
	}
	return st
}

// DeliverNow sends evt to every accepting sink synchronously, with no
// retries, and reports each sink's outcome -- for the "send a test
// event" endpoint, where the operator is waiting for the answer.
func (d *Dispatcher) DeliverNow(ctx context.Context, evt Event) map[string]string {
	out := map[string]string{}
	if d == nil {
		return out
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = d.now()
	}
	for _, s := range d.sinks {
		if !s.Accepts(evt.Type) {
			out[s.Name()] = "skipped (sink doesn't accept " + evt.Type + " events)"
			continue
		}
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := s.Deliver(actx, evt)
		cancel()
		if err != nil {
			out[s.Name()] = "failed: " + err.Error()
		} else {
			out[s.Name()] = "ok"
		}
	}
	return out
}

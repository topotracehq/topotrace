package api

import (
	"context"
	"muster/internal/model"
	"muster/internal/operations"
	"muster/internal/store/memstore"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceScopeAndReportCollections(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	for _, v := range []struct{ name, group string }{{"allowed-device", "a"}, {"secret-device", "b"}} {
		st.UpsertHost(ctx, model.Host{Name: v.name, Platform: "linux", LastCooked: time.Now()})
		st.SetHostGroup(ctx, v.name, v.group)
	}
	st.CreateAPIKey(ctx, "scoped", "remediate", "a", sha256Hex("scoped"))
	s := &Server{Store: st, AuthToken: "master"}
	h := s.Handler()
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer scoped")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/overview", "/api/search-all?q=device", "/api/collections"} {
		w := call("GET", path, "")
		if w.Code != 200 || strings.Contains(w.Body.String(), "secret-device") {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	if w := call("GET", "/api/compare?a=allowed-device&b=secret-device", ""); w.Code != 404 {
		t.Fatal("cross-scope comparison", w.Code)
	}
	if w := call("POST", "/api/collections", `{"name":"bad","hosts":["secret-device"]}`); w.Code != 400 {
		t.Fatal("cross-scope collection", w.Code)
	}
	operations.Save(ctx, st, collectionKind, "c", deviceCollection{ID: "c", Name: "picked", Group: "a", Hosts: []string{"allowed-device", "secret-device"}})
	w := call("GET", "/api/reports/executive?collection=c&mode=technical&sections=hosts", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret-device") || !strings.Contains(w.Body.String(), "allowed-device") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", "/api/sites", ""); w.Code != 401 && w.Code != 403 {
		t.Fatal("scoped site access", w.Code)
	}
	if w := call("GET", "/api/integration-health", ""); w.Code != 401 && w.Code != 403 {
		t.Fatal("scoped integration access", w.Code)
	}
}

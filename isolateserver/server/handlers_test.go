// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

import (
	"bytes"
	"github.com/maruel/aedmztest"
	"github.com/maruel/ut"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newServer() *httptest.Server {
	m := http.NewServeMux()
	SetupHandlers(m, aedmztest.NewAppMock(nil))
	return httptest.NewServer(m)
}

func get(t testing.TB, ts *httptest.Server, resource string, status int) string {
	r, err := http.Get(ts.URL + resource)
	return commonRequest(t, r, err, status)
}

func post(t testing.TB, ts *httptest.Server, resource, contentType string, body io.Reader, status int) string {
	r, err := http.Post(ts.URL+resource, contentType, body)
	return commonRequest(t, r, err, status)
}

func commonRequest(t testing.TB, r *http.Response, err error, status int) string {
	if err != nil {
		t.Fatal(err)
	}
	ut.AssertEqual(t, status, r.StatusCode)
	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestWarmup(t *testing.T) {
	ts := newServer()
	defer ts.Close()

	body := get(t, ts, "/_ah/warmup", http.StatusOK)
	ut.AssertEqual(t, "Warmed up", body)
}

// It must fail.
func TestWarmupPOST(t *testing.T) {
	ts := newServer()
	defer ts.Close()

	// TODO(maruel): Should be http.StatusMethodNotAllowed.
	body := post(t, ts, "/_ah/warmup", "application/stream", &bytes.Buffer{}, http.StatusNotFound)
	ut.AssertEqual(t, "404 page not found\n", body)
}

func TestRoot(t *testing.T) {
	ts := newServer()
	defer ts.Close()

	body := get(t, ts, "/", http.StatusOK)
	if len(body) < 1000 {
		t.Fatalf("Root page is not large enough:\n%s", body)
	}
	if len(body) > 100000 {
		t.Fatalf("Root page is too large:\n%s", body)
	}
	if !strings.Contains(body, "<title>Isolate Server</title>") {
		t.Fatalf("Failed to find title in root page:\n%s", body)
	}
}

// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

import (
	"bytes"
	"strings"
	"testing"
)

func TestTemplatesNotEmpty(t *testing.T) {
	if len(templates) == 0 {
		t.Fatalf("Failed to load templates")
	}
}

func TestSendRoot(t *testing.T) {
	b := &bytes.Buffer{}
	SendTemplate(b, "root.html", 0)
	body := b.String()
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

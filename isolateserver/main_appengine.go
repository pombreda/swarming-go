// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

// +build appengine

package main

import (
	"github.com/maruel/swarming-go/isolateserver/server"
	"github.com/maruel/swarming-go/pkg/aedmz"
	"net/http"
)

func init() {
	server.SetupHandlers(http.DefaultServeMux, aedmz.NewApp("", ""))
}

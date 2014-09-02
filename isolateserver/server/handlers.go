// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

// This module defines all the HTTP handlers the isolate server supports.

import (
	gorillaContext "github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/maruel/swarming-go/pkg/aedmz"
	"net/http"
)

type contextKeyType int

const (
	routerKey contextKeyType = 0
)

// warmUpHandler makes sure settings are loaded and the templates will be
// compiled on startup.
func warmUpHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Warmed up"))
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Root"))
}

// handle adds a route 'path' to the router 'r' named 'name' using 'handler',
// restricted to specified 'methods'.
func handle(r *mux.Router, path string, name string, handler http.HandlerFunc, methods ...string) {
	r.HandleFunc(path, handler).Name(name).Methods(methods...)
}

// SetupHandlers adds all the isolate server routes to the web server router.
func SetupHandlers(router *http.ServeMux, app aedmz.AppContext) {
	// Route through Gorilla mux for native regexp and named route support.
	r := mux.NewRouter()
	handle(r, "/_ah/warmup", "", warmUpHandler, "GET")
	handle(r, "/", "root", rootHandler, "GET")

	h := app.InjectContext(r.ServeHTTP)

	// Set our router as the sole handler to 'router'.
	router.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		gorillaContext.Set(req, routerKey, r)
		h.ServeHTTP(w, req)
	})
}

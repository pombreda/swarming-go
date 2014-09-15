// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

// +build !appengine

package main

import (
	"code.google.com/p/leveldb-go/leveldb"
	"code.google.com/p/leveldb-go/leveldb/db"
	"code.google.com/p/leveldb-go/leveldb/memdb"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/maruel/aedmz"
	"github.com/maruel/ofh"
	"github.com/maruel/swarming-go/isolateserver/server"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"
)

var settingsFile = "settings.json"
var dbDir = "db"

type Settings struct {
	// Port to listen to.
	HTTP  string // :8080
	HTTPS string // :10443

	// SSL Certificate pair.
	PublicKey  string // cert.pem
	PrivateKey string // key.pem

	OAuth2 *ofh.OAuth2Settings
}

func readJsonFile(filePath string, object interface{}) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("Failed to open %s: %s", filePath, err)
	}
	defer func() {
		_ = f.Close()
	}()
	if err = json.NewDecoder(f).Decode(object); err != nil {
		return fmt.Errorf("Failed to decode %s: %s", filePath, err)
	}
	return nil
}

// writeJsonFile writes object as json encoded into filePath with 2 spaces indentation.
func writeJsonFile(filePath string, object interface{}) error {
	d, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		return fmt.Errorf("Failed to encode %s: %s", filePath, err)
	}

	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("Failed to open %s: %s", filePath, err)
	}
	defer func() {
		_ = f.Close()
	}()
	if _, err := f.Write(d); err != nil {
		return fmt.Errorf("Failed to write %s: %s", filePath, err)
	}
	return nil
}

func startHTTP(addr string, mux http.Handler, wg *sync.WaitGroup) (net.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("Failed to listed on %s: %s", addr, err)
	}
	srv := &http.Server{Addr: addr, Handler: mux}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(l)
	}()
	return l, nil
}

func startHTTPS(addr string, mux http.Handler, wg *sync.WaitGroup, cert, priv string) (net.Listener, error) {
	if cert == "" || priv == "" {
		return nil, fmt.Errorf("Both public and private keys must be specified. If you don't want https support, change the port.")
	}
	c, err := tls.LoadX509KeyPair(cert, priv)
	if err != nil {
		return nil, fmt.Errorf("Failed to load certificates %s/%s: %s", cert, priv, err)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("Failed to listed on %s: %s", addr, err)
	}
	srv := &http.Server{Addr: addr, Handler: mux}
	config := &tls.Config{NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{c}}
	l2 := tls.NewListener(l, config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(l2)
	}()
	return l, nil
}

type KV struct {
	K []byte
	V []byte
}

// runServer opens the configuration files, read them, starts the server. Then
// it waits for a Ctrl-C and quit. All the opened files are from the current
// working directory.
func runServer() int {
	log.SetFlags(log.Ldate | log.Lmicroseconds)

	settings := &Settings{
		HTTP:   ":8080",
		OAuth2: ofh.MakeOAuth2Settings(),
	}
	if err := readJsonFile(settingsFile, settings); err != nil {
		err = writeJsonFile(settingsFile, settings)
		if err != nil {
			log.Printf("Failed to initialize settings. %s", err)
			return 1
		}
		fmt.Printf("A configuration file was generated for you with the default settings: %s\n", settingsFile)
		fmt.Printf("Please update it as desired and rerun this command.\n")
		return 2
	}

	if settings.HTTP == "" && settings.HTTPS == "" {
		log.Printf("At least one of http or https must be set.")
		return 1
	}

	saveSettings := func() {
		settings.OAuth2.InstalledApp.Lock()
		defer settings.OAuth2.InstalledApp.Unlock()
		if settings.OAuth2.InstalledApp.ShouldSave() {
			log.Printf("Saving settings.")
			settings.OAuth2.InstalledApp.ClearDirtyBit()
			if err := writeJsonFile(settingsFile, settings); err != nil {
				log.Printf("Failed to save settings: %s", err)
			}
		}
	}
	defer saveSettings()

	// Handle Ctrl-C.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	useDb := false
	var db db.DB
	var err error
	if useDb {
		// Sadly, the implementation returned by this function is incomplete so
		// until Find() is implemented in leveldb.go, roll out our adhoc el cheapos
		// serialization to have something working. This is very inefficient.
		db, err = leveldb.Open(dbDir, nil)
	} else {
		kv := make([]KV, 0)
		count := 0
		_ = readJsonFile(dbDir, &kv)
		db = memdb.New(nil)
		for _, line := range kv {
			_ = db.Set(line.K, line.V, nil)
			count += 1
		}
		log.Printf("Loaded DB with %d items.", count)
	}

	defer func() {
		count := 0
		itr := db.Find([]byte{}, nil)
		if useDb {
			for itr.Next() {
				count += 1
			}
			log.Printf("Flushing DB with %d items.", count)
			// Technically, all iterators must be invalidated first. In practice, we
			// barely try to guarantee this.
			_ = db.Close()
		} else {
			kv := make([]KV, 0)
			for itr.Next() {
				kv = append(kv, KV{itr.Key(), itr.Value()})
				count += 1
			}
			log.Printf("Flushing DB with %d items.", count)
			if err := writeJsonFile(dbDir, kv); err != nil {
				log.Printf("Failed to save %s: %s", dbDir, err)
			}
		}
	}()

	// Notes:
	// - On AppEngine, the instance's name and version is used instead.
	// - To log to both a file and os.Stderr, use io.TeeWriter.
	// - Use &s.OAuth2.InstalledApp to force the use of installed app credentials
	//   when both are available.
	// TODO(maruel): the application name should be retrieved from app.yaml and
	// used as the default.
	app := aedmz.NewApp("isolateserver-dev", "v0.1", os.Stderr, settings.OAuth2, db)

	// TODO(maruel): Load index.yaml to configure the secondary indexes on the db.
	// TODO(maruel): Load app.yaml to add routes to support static/
	var wg sync.WaitGroup
	sockets := make([]net.Listener, 0, 2)
	if settings.HTTP != "" {
		mux := http.NewServeMux()
		server.SetupHandlers(mux, app)
		var listener net.Listener
		listener, err = startHTTP(settings.HTTP, mux, &wg)
		if err != nil {
			log.Printf("%s", err)
			quit <- os.Interrupt
		} else {
			sockets = append(sockets, listener)
		}
		log.Printf("Listening HTTP on %s", settings.HTTP)
	}

	if err == nil && settings.HTTPS != "" {
		mux := http.NewServeMux()
		server.SetupHandlers(mux, app)
		listener, err := startHTTPS(settings.HTTPS, mux, &wg, settings.PublicKey, settings.PrivateKey)
		if err != nil {
			log.Printf("%s", err)
			quit <- os.Interrupt
		} else {
			sockets = append(sockets, listener)
		}
		log.Printf("Listening HTTPS on %s", settings.HTTPS)
	}

	stillRun := true
	for stillRun {
		select {
		case <-quit:
			stillRun = false
		case <-time.After(time.Minute):
			saveSettings()
		}
	}

	for _, listener := range sockets {
		_ = listener.Close()
	}

	// TODO(maruel): Only wait 1 minute.
	log.Printf("Waiting for on-going requests...")
	app.WaitForOngoingRequests()
	return 0
}

func main() {
	os.Exit(runServer())
}

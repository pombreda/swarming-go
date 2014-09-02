// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package aedmz

// AppEngine aedmz layer.
//
// This file contains code and interfaces that is common between a local server
// and an AppEngine server.

import (
	"errors"
	"fmt"
	gorillaContext "github.com/gorilla/context"
	"github.com/youtube/vitess/go/cache"
	"net/http"
	"strings"
	"time"
)

const (
	// Same values as google_appengine/google/appengine/api/logservice/logservice.py
	LogLevelDebug = iota
	LogLevelInfo
	LogLevelWarning
	LogLevelError
	LogLevelCritical
)

// ErrNotFound is returned when a object requested in DB or Cache is not found.
var ErrNotFound = errors.New("Requested object not found")

// An AppContext is the interface to generate new RequestContext upon each new
// in-bound HTTP connections.
//
// Not much can be done by the app itself, all actions are done on behalf of an
// inbound request. In-bound requests can be generated automatically by a cron
// job or a task queue. See Tasker for a technique to trigger in-bound task
// queue requests.
type AppContext interface {
	// NewContext returns a new RequestContext for the current http.Request
	// running on this AppContext.
	//
	// This RequestContext holds context to be able to access the DB, logging and
	// user and do out-going HTTP requests on behalf of the application.
	NewContext(r *http.Request) RequestContext

	// InjectContext adds a gorilla context to the http.Request.
	//
	// This must be called at the initial router level.
	InjectContext(handler http.HandlerFunc) http.HandlerFunc
}

// Key holds the complete key to request a single exact entity in the DB or in
// the Cache.
//
// The struct is similar to appengine/datastore.Key. A Key is semantically
// immutable even if this is not enforced.
type Key struct {
	// Key's kind (also known as entity type).
	Kind string
	// Key's string ID (also known as an entity name or key name), which may be
	// "".
	StringID string
	IntID    int64
	// Key's parent key, which may be nil.
	Parent *Key
}

// Encode returns a byte representation usable in Cache or DB lookups.
func (k *Key) Encode() string {
	if k.Parent != nil {
		return fmt.Sprintf("%s%s%s%s%s", k.Parent.Encode(), keySeparator, k.Kind, keySeparator, k.StringID)
	}
	return fmt.Sprintf("%s%s%s", k.Kind, keySeparator, k.StringID)
}

// String returns the key as a human readable string.
func (k *Key) String() string {
	if k.Parent != nil {
		return fmt.Sprintf("%s/%s,%s", k.Parent.String(), k.Kind, k.StringID)
	}
	return fmt.Sprintf("/%s,%s", k.Kind, k.StringID)
}

// NewKey returns a new *Key enforcing that the kind and string ID are valids.
//
// It is prefered to use NewKey instead of of creating a Key instance directly
// for futureproofness.
func NewKey(kind, stringID string, parent *Key) *Key {
	if strings.Contains(kind, keySeparator) || strings.Contains(stringID, keySeparator) {
		panic("Oops")
		return nil
	}
	return &Key{kind, stringID, 0, parent}
}

// Returned as a result in the future for a DB or Cache operation.
type OpResult struct {
	Key    *Key
	Index  int         // Applicable for *Multi functions.
	Result interface{} // Applicable for *Get functions.
	Err    error
}

// DB abstracts an access context to a database.
//
// It is up to the implementation to cache entities.
type DB interface {
	// BUG(maruel): DB: Support queries.

	// GetMulti retrieves multiples entities from the datastore.
	//
	// dst must be a slice of type []S, []*S, []I, for some struct type S, some
	// interface type I. If an []I, each element must be a valid dst for Get: it
	// must be a struct pointer.
	GetMulti(keys []*Key, objects interface{}, results chan<- *OpResult)
	// PutMulti stores multiples entities in the datastore.
	//
	// PutMulti has the same requirements for objects than GetMulti.
	PutMulti(keys []*Key, objects interface{}, results chan<- *OpResult)
	// DeleteMulti deletes multiples entities from the datastore.
	DeleteMulti(keys []*Key, results chan<- *OpResult)
}

// TransactionDB abstracts a direct access context to a database.
//
// It is guaranteed to not be cached.
type TransactionDB interface {
	DB
	RunInTransaction(tx func(db DB) error) error
}

// Get is a shorthand function to synchronously fetch a single entity from
// the DB.
func Get(db DB, key *Key, obj interface{}) error {
	results := make(chan *OpResult)
	go db.GetMulti([]*Key{key}, []interface{}{obj}, results)
	return (<-results).Err
}

// Put is a shorthand function to synchronously put a single entity in the
// DB.
func Put(db DB, key *Key, obj interface{}) (*Key, error) {
	results := make(chan *OpResult)
	go db.PutMulti([]*Key{key}, []interface{}{obj}, results)
	result := <-results
	return result.Key, result.Err
}

// Delete is a shorthand function to synchronously delete a single entity in
// the DB.
func Delete(db DB, key *Key) error {
	results := make(chan *OpResult)
	go db.DeleteMulti([]*Key{key}, results)
	return (<-results).Err
}

// Cache is a simplified interface to an memcache-like service. It is
// compatible with DB.
//
// - The maximum size of a cached data value is 1 MB minus the size of the key
//   minus an implementation-dependent overhead which is approximately
//   100 bytes.
// - Keys larger than 250 bytes will be hashed with SHA-256, which introduces a
//   (very small) possibility of collision.
type Cache interface {
	// BUG(maruel): DB should implement Cache, which would make chaining caches
	// trivial. This would likely mean Cache to implement GetMulti() and
	// PutMulti(). (Revision: not so sure about this)

	CacheGet(key *Key, results chan<- *OpResult)
	// Semantically, setting a key to value nil is the same as deleting the entry.
	CacheSet(key *Key, object interface{}, expiration time.Duration)
}

// CacheGet is a shorthand function to synchronously fetch a single entry in
// the cache that supports timeout.
//
// It ignores any error.
func CacheGet(cache Cache, key *Key, timeout time.Duration) interface{} {
	results := make(chan *OpResult)
	go cache.CacheGet(key, results)
	if timeout == 0 {
		return (<-results).Result
	}
	select {
	case r := <-results:
		return r.Result
	case <-time.After(timeout):
		return nil
	}
}

// Abstract contextual logging.
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warningf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// LogService is an interface to read back the logs.
type LogService interface {
	// ScanLogs scans the logs by time and returns the items found in the channel.
	// The Record returned in the channel will be inclusively between [start,
	// end]. If minLevel is -1, it is ignored. Otherwise, it specifies an AppLog
	// entry with the minimum log level must be present in the Record to be
	// returned. versions, if specified, is a whitelist of the versions to
	// enumerate.
	ScanLogs(start, end time.Time, minLevel int, versions []string, logs chan<- *Record)
	// GetLogEntry returns one or many specific requests logs.
	GetLogEntry(requestIDs []string, logs chan<- *Record)
}

type Tasker interface {
	TaskEnqueue(url, taskName string, payload []byte) error
}

// AppIdentity exposes the application's identity.
type AppIdentity interface {
	AppID() string
	AppVersion() string
}

// Connectivity exposes both unauthenticated and authenticated out-bound HTTP
// connections.
type Connectivity interface {
	// HttpClient returns an *http.Client for outgoing connections that are
	// bound to this incoming request. Note that the RoundTripper may enforce a
	// limit on the data size.
	HttpClient() (*http.Client, error)
	// OAuth2HttpClient returns an *http.Client that can be used to send RPCs to a
	// remote service like Google CloudStorage with the Application's identity.
	OAuth2HttpClient(scope string) (*http.Client, error)
}

// Context for a single HTTP request.
type RequestContext interface {
	AppIdentity
	Connectivity
	Logger
	LogService
	Tasker
	Cache

	// Using the RequestContext as a DB will access the cached DB. It is using
	// the same cache as provided by Cache.
	DB

	// DB retrieves an handle to the uncached DB. All requests will go through
	// directly skipping the cache.
	UncachedDB() TransactionDB

	// User is defined in the proper aedmz for this specific request.
	UserCurrent() *User
}

// GetContext returns the framework Context associated with the request.
func GetContext(r *http.Request) RequestContext {
	return gorillaContext.Get(r, contextKey).(RequestContext)
}

// Internal stuff.

const (
	contextKey   contextKeyType = 0
	keySeparator                = "\x00"
)

type contextKeyType int

type roundTripper struct {
	r http.RoundTripper
	l Logger
}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.l.Infof("Outoing: %s@%s (%db)", req.Method, req.URL, req.ContentLength)
	// Add one of them if involved logging is desired.
	//r.l.Debugf("Outoing: %s", req)
	//r.l.Debugf("Outoing: %#v", req)
	return r.r.RoundTrip(req)
}

// inMemoryCache implements the Cache interface for in-memory cache.
//
// TODO(maruel): Sadly, vitess' cache doesn't support expiration but at least
// it supports cache size which is important.
// An option is leveldb's memDB since it compresses the memory but the default
// buffers are way too large.
type inMemoryCache struct {
	*cache.LRUCache
}

func makeInMemoryCache(capacity int) *inMemoryCache {
	return &inMemoryCache{cache.NewLRUCache(int64(capacity))}
}

func (i *inMemoryCache) CacheGet(key *Key, results chan<- *OpResult) {
	// TODO(maruel): Copy the object to remove aliasing. That's a huge pain with ndb.
	obj, ok := i.Get(key.Encode())
	if !ok {
		results <- &OpResult{
			Key: key,
			Err: ErrNotFound,
		}
	} else {
		results <- &OpResult{
			Key:    key,
			Result: obj,
		}
	}
}

func (i *inMemoryCache) CacheSet(key *Key, object interface{}, expiration time.Duration) {
	// TODO(maruel): Copy the object to remove aliasing. That's a huge pain with ndb.
	// TODO(maruel): Implement expiration.
	if object == nil {
		i.Delete(key.Encode())
	} else {
		v, ok := object.(cache.Value)
		if !ok {
			// TODO(maruel): Support objects that do not implement this interface.
			// One fallback is binary.Size(), the other is
			// reflect.TypeOf(object).Size(). The main issue with TypeOf().Size() is
			// that then each field member must be scanned through, which is painful.
			panic("Oops")
		} else {
			i.Set(key.Encode(), v)
		}
	}
}

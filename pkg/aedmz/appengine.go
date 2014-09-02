// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

// +build appengine

package aedmz

// AppEngine abstraction layer.

import (
	"appengine"
	"appengine/datastore"
	"appengine/log"
	"appengine/memcache"
	"appengine/taskqueue"
	"appengine/urlfetch"
	"appengine/user"
	"code.google.com/p/goauth2/oauth"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	gorillaContext "github.com/gorilla/context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

// Interface that describes the necessary mocks to load a unit test AppContext.
//
// This exposes internal details. It is meant for use for testing only by
// aedmztest.NewAppMock()
type AppContextImpl interface {
	NewContext(r *http.Request) appengine.Context
}

// Real implementation.
type appContextImpl struct{}

func (i appContextImpl) NewContext(r *http.Request) appengine.Context {
	return appengine.NewContext(r)
}

// appContext is a singleton that holds all the details of the currently
// running application.
//
// A mock instance can be created with aedmztest.NewAppMock().
type appContext struct {
	lock       sync.Mutex
	appID      string
	appVersion string
	impl       AppContextImpl
}

// NewApp creates a new Application context.
func NewApp(appID, appVersion string) AppContext {
	return NewAppInternal(appID, appVersion, appContextImpl{})
}

// NewAppInternal returns a new Application context.
//
// This exposes internal details. It is meant for use for testing only by
// aedmztest.NewAppMock()
func NewAppInternal(appID, appVersion string, impl AppContextImpl) AppContext {
	return &appContext{
		appID:      appID,
		appVersion: appVersion,
		impl:       impl,
	}
}

func (a *appContext) NewContext(r *http.Request) RequestContext {
	c := a.impl.NewContext(r)
	return &requestContext{
		Context:  c,
		app:      a,
		db:       dbContext{c},
		cache:    makeInMemoryCache(1024 * 1024), // Default cache size per HTTP request is 1 MB.
		memCache: memcacheContext{c},
	}
}

func (a *appContext) InjectContext(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := a.NewContext(r)
		defer func() {
			// This is necessary for unit tests.
			if closer, ok := c.(io.Closer); ok {
				closer.Close()
			}
		}()
		gorillaContext.Set(r, contextKey, c)
		handler(w, r)
	}
}

// requestContext holds the local references for a single HTTP request.
type requestContext struct {
	appengine.Context // Implements the Logger interface so it needs to be embedded as is.
	app               *appContext
	db                dbContext
	cache             Cache           // Request local cache.
	memCache          memcacheContext // Application global memcache. It is in requestContext because it needs a valid appengine.Context.
}

// RequestContextAppengine adds functions that are only relevant when running
// on AppEngine.
type RequestContextAppengine interface {
	RequestContext
	AppengineContext() appengine.Context
}

func (r *requestContext) AppengineContext() appengine.Context {
	return r.Context
}

func (r *requestContext) AppID() string {
	// The value is automatically cached to reduce the number of RPC.
	app := r.app
	app.lock.Lock()
	appID := app.appID
	app.lock.Unlock()

	if appID == "" {
		// Lazy load this value because this function call does an RPC under the
		// hood.
		appID = appengine.AppID(r.Context)
		app.lock.Lock()
		app.appID = appID
		app.lock.Unlock()
	}
	return appID
}

func (r *requestContext) AppVersion() string {
	// The value is automatically cached to reduce the number of RPC.
	app := r.app
	app.lock.Lock()
	appVersion := app.appVersion
	app.lock.Unlock()

	if appVersion == "" {
		// Lazy load this value because this function call does an RPC under the
		// hood.
		appVersion = strings.Split(appengine.VersionID(r.Context), ".")[0]
		app.lock.Lock()
		app.appVersion = appVersion
		app.lock.Unlock()
	}
	return appVersion
}

// Connectivity

func (r *requestContext) getTransport() http.RoundTripper {
	return &urlfetch.Transport{Context: r}
}

// Currently valid access token for this instance for this request.
type accessToken struct {
	token      string
	expiration time.Time
}

// AccessToken returns an oauth2 token on behalf of the service account of this
// application.
func (r *requestContext) getAccessToken(scope string) (*oauth.Token, error) {
	// While this function call requires an appengine.Context due to it doing
	// RPCs under the hood, the access token is not connection or user specific.
	a, e, err := appengine.AccessToken(r.Context, scope)
	if err != nil {
		return nil, err
	}
	return &oauth.Token{AccessToken: a, Expiry: e}, nil
}

func (r *requestContext) HttpClient() (*http.Client, error) {
	return &http.Client{Transport: r.getTransport()}, nil
}

func (r *requestContext) OAuth2HttpClient(scope string) (*http.Client, error) {
	token, err := r.getAccessToken(scope)
	if err != nil {
		return nil, err
	}
	transport := &oauth.Transport{
		Token:     token,
		Transport: r.getTransport(),
	}
	return transport.Client(), nil
}

// User handling.

// User holds information about the currently logged in user for this specific
// request.
type User struct {
	user.User
}

func (r *requestContext) UserCurrent() *User {
	u := user.Current(r)
	if u == nil {
		return nil
	}
	return &User{*u}
}

// DB handling.

// KeyToAppengineKey converts a Key to a *datastore.Key.
func KeyToAppengineKey(c appengine.Context, key *Key) *datastore.Key {
	if key.Parent == nil {
		return datastore.NewKey(c, key.Kind, key.StringID, key.IntID, nil)
	}
	return datastore.NewKey(c, key.Kind, key.StringID, key.IntID, KeyToAppengineKey(c, key.Parent))
}

// KeyFromAppengineKey converts a *datastore.Key to a Key.
func KeyFromAppengineKey(key *datastore.Key) *Key {
	if key.Parent() == nil {
		return NewKey(key.Kind(), key.StringID(), nil)
	}
	return NewKey(key.Kind(), key.StringID(), KeyFromAppengineKey(key.Parent()))
}

func assertIsSlice(objects interface{}, expectedLen int) (*reflect.Value, error) {
	if reflect.TypeOf(objects).Kind() != reflect.Slice {
		return nil, errors.New("Failed to cast to []interface{}")
	}
	value := reflect.ValueOf(objects)
	objectsLen := value.Len()
	if objectsLen != expectedLen {
		return nil, fmt.Errorf("Length mismatch: len(keys) %d != len(objects) %s", expectedLen, objectsLen)
	}
	return &value, nil
}

type dbContext struct {
	appengine.Context
}

func (d *dbContext) GetMulti(keys []*Key, objects interface{}, results chan<- *OpResult) {
	// TODO(maruel): The function is fully synchronous. Eventually it would be
	// good to gain back incrementality. One way to approximate this would be
	// to use 'pages' like ndb.Query.fetch_page_async().
	value, err := assertIsSlice(objects, len(keys))
	if err != nil {
		results <- &OpResult{Err: err}
		return
	}

	dbKeys := make([]*datastore.Key, len(keys))
	for i := range keys {
		if keys[i] != nil {
			dbKeys[i] = KeyToAppengineKey(d.Context, keys[i])
		}
	}

	// TODO(maruel): Values could continue being returned from memcache. Catch
	// them?
	e := datastore.GetMulti(d.Context, dbKeys, objects)
	if e != nil {
		if allErrors, ok := e.(appengine.MultiError); !ok {
			// The thing completely failed.
			results <- &OpResult{Err: e}
		} else {
			for i := range keys {
				if dbKeys[i] == nil {
					// It was already returned either from the cache or it was an invalid
					// key in the first place.
				}
				err = allErrors[i]
				if err == datastore.ErrNoSuchEntity {
					err = ErrNotFound
				} else if _, ok := err.(*datastore.ErrFieldMismatch); ok {
					err = nil
				}
				if err != nil {
					results <- &OpResult{Key: keys[i], Index: i, Err: err}
				} else {
					item := value.Index(i).Interface()
					results <- &OpResult{Key: keys[i], Index: i, Result: item, Err: err}
				}
			}
		}
	} else {
		for i := range keys {
			item := value.Index(i).Interface()
			results <- &OpResult{Key: keys[i], Index: i, Result: item}
		}
	}
}

func (d *dbContext) PutMulti(keys []*Key, objects interface{}, results chan<- *OpResult) {
	_, err := assertIsSlice(objects, len(keys))
	if err != nil {
		results <- &OpResult{Err: err}
		return
	}

	dbKeys := make([]*datastore.Key, len(keys))
	for i := range keys {
		dbKeys[i] = KeyToAppengineKey(d.Context, keys[i])
	}
	newDbKeys, e := datastore.PutMulti(d.Context, dbKeys, objects)
	if e != nil {
		if allErrors, ok := e.(appengine.MultiError); !ok {
			// The thing completely failed.
			results <- &OpResult{Err: e}
		} else {
			for i := range keys {
				k := KeyFromAppengineKey(newDbKeys[i])
				results <- &OpResult{Key: k, Index: i, Err: allErrors[i]}
				if allErrors[i] == nil {
					//d.cache.CacheSet(k, objects[i], 0)
				}
			}
		}
	} else {
		for i := range keys {
			k := KeyFromAppengineKey(newDbKeys[i])
			results <- &OpResult{Key: k, Index: i}
		}
	}
}

func (d *dbContext) DeleteMulti(keys []*Key, results chan<- *OpResult) {
	// Warning: items may still be in cache after the delete.

	// TODO(maruel): The function is fully synchronous. Eventually it would be
	// good to gain back incrementality. One way to approximate this would be
	// to use 'pages' like ndb.Query.fetch_page_async().
	dbKeys := make([]*datastore.Key, len(keys))
	for i := range keys {
		dbKeys[i] = KeyToAppengineKey(d.Context, keys[i])
	}
	e := datastore.DeleteMulti(d.Context, dbKeys)
	if e != nil {
		if allErrors, ok := e.(appengine.MultiError); !ok {
			// The thing completely failed.
			results <- &OpResult{Err: e}
		} else {
			for i := range keys {
				err := allErrors[i]
				if err == datastore.ErrNoSuchEntity {
					err = ErrNotFound
				}
				results <- &OpResult{Key: keys[i], Index: i, Err: err}
			}
		}
	} else {
		for i := range keys {
			results <- &OpResult{Key: keys[i], Index: i}
		}
	}
}

func (d *dbContext) RunInTransaction(tx func(db DB) error) error {
	return datastore.RunInTransaction(d.Context, func(c appengine.Context) error {
		// Creates a new temporary dbContext with this transactional context.
		return tx(&dbContext{c})
	}, nil)
}

func (r *requestContext) UncachedDB() TransactionDB {
	return &r.db
}

func (r *requestContext) GetMulti(keys []*Key, objects interface{}, results chan<- *OpResult) {
	cacheResults := make(chan *OpResult)
	for i := range keys {
		// Tries to get in the local cache or in memcache.
		go r.CacheGet(keys[i], cacheResults)
	}
	loop := true
	for loop {
		select {
		case cacheResult := <-cacheResults:
			// TODO(maruel): Figure out index.
			i := 0
			results <- &OpResult{Key: keys[i], Index: i, Result: cacheResult.Result}
			keys[i] = nil
		case <-time.After(5 * time.Millisecond):
			loop = false
		}
	}
	// Fallback to DB.
	r.db.GetMulti(keys, objects, results)
}

func (r *requestContext) PutMulti(keys []*Key, objects interface{}, results chan<- *OpResult) {
	itermediaryResults := make(chan *OpResult)
	go func() {
		r.db.PutMulti(keys, objects, itermediaryResults)
		close(itermediaryResults)
	}()
	for o := range itermediaryResults {
		// Update the cache.
		r.cache.CacheSet(o.Key, o.Result, 0)
		results <- o
	}
}

func (r *requestContext) DeleteMulti(keys []*Key, results chan<- *OpResult) {
	r.db.DeleteMulti(keys, results)
	for _, k := range keys {
		r.cache.CacheSet(k, nil, 0)
	}
}

// Cache.

type memcacheContext struct {
	appengine.Context
}

func mangleKey(key *Key) string {
	encoded := key.Encode()
	if len(encoded) > 250 {
		h := sha256.New()
		io.WriteString(h, encoded)
		encoded = hex.EncodeToString(h.Sum(nil))
	}
	return encoded
}

func (m *memcacheContext) CacheGet(key *Key, results chan<- *OpResult) {
	encoded := mangleKey(key)
	item, err := memcache.Get(m.Context, encoded)
	if err == memcache.ErrCacheMiss {
		results <- &OpResult{
			Key: key,
			Err: ErrNotFound,
		}
	} else if err != nil {
		results <- &OpResult{
			Key: key,
			Err: err,
		}
	} else {
		results <- &OpResult{
			Key:    key,
			Result: item.Object,
		}
	}
}

func (m *memcacheContext) CacheSet(key *Key, object interface{}, expiration time.Duration) {
	encoded := mangleKey(key)
	if object == nil {
		memcache.Delete(m.Context, encoded)
	} else {
		item := &memcache.Item{
			Key:        encoded,
			Object:     object,
			Expiration: expiration,
		}
		memcache.Set(m.Context, item)
	}
}

func (r *requestContext) CacheGet(key *Key, results chan<- *OpResult) {
	// Looks up in-process request-locale cache, then external cache.
	cacheResults := make(chan *OpResult)
	r.cache.CacheGet(key, cacheResults)
	cacheResult := <-cacheResults
	if cacheResult.Err == nil {
		// It is present in the local cache, use this.
		results <- cacheResult
		return
	}
	r.memCache.CacheGet(key, results)
}

func (r *requestContext) CacheSet(key *Key, object interface{}, expiration time.Duration) {
	r.cache.CacheSet(key, object, expiration)
	r.memCache.CacheSet(key, object, expiration)
}

// Logging: Nothing to implement, the interface is implemented by
// appengine.Context.

// LogService.

type AppLog log.AppLog
type Record log.Record

func (r *requestContext) run(q *log.Query, entries chan<- *Record) {
	result := q.Run(r.Context)
	for {
		record, _ := result.Next()
		if record == nil {
			break
		}
		entries <- (*Record)(record)
	}
}

func (r *requestContext) ScanLogs(start, end time.Time, minLevel int, versions []string, entries chan<- *Record) {
	r.run(
		&log.Query{
			StartTime:     start,
			EndTime:       end,
			Incomplete:    true,
			AppLogs:       true,
			ApplyMinLevel: (minLevel >= 0),
			MinLevel:      minLevel,
			Versions:      versions,
		},
		entries)
}

func (r *requestContext) GetLogEntry(requestIDs []string, entries chan<- *Record) {
	r.run(
		&log.Query{
			Incomplete: true,
			AppLogs:    true,
			RequestIDs: requestIDs,
		},
		entries)
}

// Task handling.

func (r *requestContext) TaskEnqueue(url, taskName string, payload []byte) error {
	// https://developers.google.com/appengine/docs/go/taskqueue/reference
	t := &taskqueue.Task{Path: url, Payload: payload, Method: "POST"}
	_, err := taskqueue.Add(r, t, taskName)
	return err
}

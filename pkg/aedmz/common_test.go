// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package aedmz

import (
	"github.com/maruel/ut"
	"net/http"
	"testing"
	"time"
)

func TestAppIdentity(t *testing.T) {
	app := newAppMock(nil)
	req, err := http.NewRequest("GET", "http://localhost/", nil)
	ut.AssertEqual(t, nil, err)
	c := app.NewContext(req)
	defer CloseRequest(c)

	ut.AssertEqual(t, "Yo", c.AppID())
	ut.AssertEqual(t, "v1", c.AppVersion())
}

func TestConnectivity(t *testing.T) {
	app := newAppMock(nil)
	req, err := http.NewRequest("GET", "http://localhost/", nil)
	ut.AssertEqual(t, nil, err)
	c := app.NewContext(req)
	defer CloseRequest(c)

	r, err := c.HttpClient()
	if r == nil {
		t.Fatal("Expected transport")
	}
	ut.AssertEqual(t, nil, err)

	o, err := c.OAuth2HttpClient("scope")
	if o == nil {
		t.Fatal("Expected transport")
	}
	ut.AssertEqual(t, nil, err)
}

type entityA struct {
	A int
	B string
	C []byte
	D time.Time
}

type entityC struct {
	E float64
}

// Utility function to reduce copy-paste.
func setupSingle(t testing.TB) (RequestContext, *Key, *entityA) {
	c := newAppMock(nil).NewContext(nil)
	k := NewKey("Kind", "Name", nil)
	obj := &entityA{1, "a", []byte{255, 254}, time.Date(2001, 2, 3, 4, 5, 6, 7, time.UTC)}
	return c, k, obj
}

func compareEntities(t testing.TB, expected *entityA, actual *entityA) {
	// Sadly, serialization may affect the .ns value of a time.Time, resulting in
	// slightly different values. So do the comparison by hand.
	ut.AssertEqual(t, expected.A, actual.A)
	ut.AssertEqual(t, expected.B, actual.B)
	ut.AssertEqual(t, expected.C, actual.C)
	// Ignores sub millisecond resolution.
	format := "2006-01-02T15:04:05.999Z07:00"
	ut.AssertEqual(t, expected.D.UTC().Format(format), actual.D.UTC().Format(format))
}

func TestDBSingleItemGet(t *testing.T) {
	c, k, obj := setupSingle(t)
	defer CloseRequest(c)
	err := Get(c, k, obj)
	ut.AssertEqual(t, ErrNotFound, err)
}

func TestDBSingleItemPutGet(t *testing.T) {
	c, k, obj := setupSingle(t)
	defer CloseRequest(c)
	k2, err := Put(c, k, obj)
	ut.AssertEqual(t, nil, err)
	ut.AssertEqual(t, k, k2)

	obj2 := &entityA{}
	err = Get(c, k, obj2)
	ut.AssertEqual(t, nil, err)
	compareEntities(t, obj2, obj)
}

func TestDBSingleItemPutDeleteGet(t *testing.T) {
	c, k, obj := setupSingle(t)
	defer CloseRequest(c)
	k2, err := Put(c, k, obj)
	ut.AssertEqual(t, nil, err)
	ut.AssertEqual(t, k, k2)

	err = Delete(c, k)
	ut.AssertEqual(t, nil, err)

	err = Get(c, k, obj)
	ut.AssertEqual(t, ErrNotFound, err)
}

func TestDBSingleItemDeleteGet(t *testing.T) {
	c, k, obj := setupSingle(t)
	defer CloseRequest(c)
	err := Delete(c, k)
	// On AppEngine, it currently returns nil. :(
	if err != nil {
		ut.AssertEqual(t, ErrNotFound, err)
	}

	err = Get(c, k, obj)
	ut.AssertEqual(t, ErrNotFound, err)
}

// The Multi equivalent follow this pattern:
// 3 keys with 2 different entity types, index 0 and 2 have an object set.

// Utility function to reduce copy-paste.
func setupMulti(t testing.TB) (RequestContext, []*Key, []interface{}, chan *OpResult, *entityA, *entityC) {
	c := newAppMock(nil).NewContext(nil)
	k1 := NewKey("Kind1", "Name1", nil)
	k2 := NewKey("Kind1", "Name2", nil)
	k3 := NewKey("Kind2", "Foo", nil)
	objA := &entityA{1, "a", []byte{255, 254}, time.Date(2001, 2, 3, 4, 5, 6, 7, time.UTC)}
	objC := &entityC{42.1}
	// index 1 is intentionally an invalid type.
	objs := []interface{}{new(entityA), new(int), new(entityC)}
	results := make(chan *OpResult)
	return c, []*Key{k1, k2, k3}, objs, results, objA, objC
}

// assertChannelIsClosed asserts the channel is closed.
func assertChannelIsClosed(t testing.TB, results <-chan *OpResult) {
	_, ok := <-results
	ut.AssertEqual(t, false, ok)
}

func TestDBMultiGet(t *testing.T) {
	c, keys, objs, results, _, _ := setupMulti(t)
	defer CloseRequest(c)
	go func() {
		c.GetMulti(keys, objs, results)
		close(results)
	}()
	ut.AssertEqual(t, OpResult{Key: keys[0], Index: 0, Err: ErrNotFound}, *(<-results))
	ut.AssertEqual(t, OpResult{Key: keys[1], Index: 1, Err: ErrNotFound}, *(<-results))
	ut.AssertEqual(t, OpResult{Key: keys[2], Index: 2, Err: ErrNotFound}, *(<-results))
	assertChannelIsClosed(t, results)
}

func TestDBMultiPutGet(t *testing.T) {
	c, keys, objs, results, objA, objC := setupMulti(t)
	defer CloseRequest(c)
	go func() {
		// Put index 0,2, Get 0,1,2.
		c.PutMulti([]*Key{keys[0], keys[2]}, []interface{}{objA, objC}, results)
		c.GetMulti(keys, objs, results)
		close(results)
	}()

	// Put
	ut.AssertEqual(t, OpResult{Key: keys[0], Index: 0}, *(<-results))
	ut.AssertEqual(t, OpResult{Key: keys[2], Index: 1}, *(<-results))

	// Get
	ut.AssertEqual(t, OpResult{Key: keys[0], Index: 0, Result: objs[0]}, *(<-results))
	ut.AssertEqual(t, OpResult{Key: keys[1], Index: 1, Err: ErrNotFound}, *(<-results))
	ut.AssertEqual(t, OpResult{Key: keys[2], Index: 2, Result: objs[2]}, *(<-results))
	assertChannelIsClosed(t, results)
}

func TestDBMultiPutDeleteGet(t *testing.T) {
	c, keys, objs, results, objA, objC := setupMulti(t)
	defer CloseRequest(c)
	go func() {
		// Put index 0,2, Delete 1,2, Get 0,1,2.
		c.PutMulti([]*Key{keys[0], keys[2]}, []interface{}{objA, objC}, results)
		c.DeleteMulti([]*Key{keys[1], keys[2]}, results)
		c.GetMulti(keys, objs, results)
		close(results)
	}()

	// Put
	ut.AssertEqual(t, OpResult{Key: keys[0], Index: 0}, *(<-results))
	ut.AssertEqual(t, OpResult{Key: keys[2], Index: 1}, *(<-results))

	// Delete
	r := <-results
	// On AppEngine, it currently returns nil. :(
	if r.Err != nil {
		ut.AssertEqual(t, OpResult{Key: keys[1], Index: 0, Err: ErrNotFound}, *r)
	} else {
		ut.AssertEqual(t, OpResult{Key: keys[1], Index: 0}, *r)
	}
	ut.AssertEqual(t, OpResult{Key: keys[2], Index: 1}, *(<-results))

	// Get
	ut.AssertEqual(t, OpResult{Key: keys[0], Index: 0, Result: objs[0]}, *(<-results))
	ut.AssertEqual(t, OpResult{Key: keys[1], Index: 1, Err: ErrNotFound}, *(<-results))
	ut.AssertEqual(t, OpResult{Key: keys[2], Index: 2, Err: ErrNotFound}, *(<-results))
	assertChannelIsClosed(t, results)
}

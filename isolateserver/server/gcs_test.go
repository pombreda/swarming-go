// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

import (
	"github.com/maruel/aedmztest"
	"github.com/maruel/ut"
	"testing"
)

func TestNewURLSigner(t *testing.T) {
	c := aedmztest.NewAppMock(nil).NewContext(nil)
	defer aedmztest.CloseRequest(c)
	clientID := "client"
	bucket := "bucket"
	// TODO(maruel): Test with real private key.
	s := newURLSigner(c, bucket, clientID, "")
	actual := s.getSignedURL("file1", "HEAD", 10, "application/junk", []byte("1234"), 100000)
	expected := "https://bucket.storage.googleapis.com/file1?Expires=100010&GoogleAccessId=client&Signature=fakesig"
	ut.AssertEqual(t, expected, actual)
}

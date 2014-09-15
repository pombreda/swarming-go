// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

import (
	"errors"
	"github.com/maruel/aedmz/aedmztest"
	"github.com/maruel/ut"
	"testing"
	"time"
)

func TestParseIP(t *testing.T) {
	var d = []struct {
		value         string
		expectedType  string
		expectedValue int64
	}{
		{"0.0.0", "", 0},
		{"0.0.0.0.0", "", 0},
		{"0.0.0.0", "v4", 0},
		{"0.0.0.1", "v4", 1},
		{"0.0.0.255", "v4", 255},
		{"0.0.0.256", "", 0},
		{"0.0.1.0", "v4", 256},
		{"0.0.1.1", "v4", 257},
		{"0.1.0.0", "v4", 65536},
		{"0.1.0.1", "v4", 65537},
		{"1.0.0.0", "v4", 16777216}, //10
		{"0:0:0:0:0:0:0", "", 0},
		{"0:0:0:0:0:0:0:0:0", "", 0},
		{"0:0:0:0:0:0:0:0", "v6", 0},
		{"0:0:0:0:0:0:0:1", "v6", 1},
		{"0:0:0:0:0:0:0:FF", "v6", 0xFF},
		{"0:0:0:0:0:0:0:FFFF", "v6", 0xFFFF},
		{"0:0:0:0:0:0:1:0", "v6", 65536},
		{"0:0:0:0:0:0:1:1", "v6", 65537},
	}
	for i, v := range d {
		ipType, ipValue := parseIP(v.value)
		ut.AssertEqualIndex(t, i, v.expectedType, ipType)
		ut.AssertEqualIndex(t, i, v.expectedValue, ipValue)
	}
}

func TestGenerateToken(t *testing.T) {
	accessID := "AccessId"
	secret := []byte("very secret")
	tokenData := map[string]string{"foo": "bar", "baz": "biz"}
	now := time.Unix(10000000, 0)
	actualToken := generateTokenInternal(accessID, secret, 10, tokenData, now)
	// TODO(maruel): Figure out why the access token is not deterministic.
	if actualToken != "Zm9vAGJhcgBiYXoAYml6AF94ADEwMDAwMDAwm0yItR8-MFI=" && actualToken != "YmF6AGJpegBmb28AYmFyAF94ADEwMDAwMDAwLFF5fzJw-Uc=" {
		t.Fatalf("Unexpected accessToken %s", actualToken)
	}

	result, err := validateToken(actualToken, accessID, secret, now)
	ut.AssertEqual(t, nil, err)
	ut.AssertEqual(t, tokenData, result)

	// Ensure backward is not accepted.
	result, err = validateToken(actualToken, accessID, secret, now.Add(-1).Add(-tokenExpiration))
	ut.AssertEqual(t, errors.New("token is in the future"), err)
	ut.AssertEqual(t, map[string]string(nil), result)

	// Ensure expired is not accepted.
	result, err = validateToken(actualToken, accessID, secret, now.Add(tokenExpiration))
	ut.AssertEqual(t, errors.New("token expired 7200 sec ago"), err)
	ut.AssertEqual(t, map[string]string(nil), result)
}

func TestSecret(t *testing.T) {
	c := aedmztest.NewAppMock(nil).NewContext(nil)
	defer aedmztest.CloseRequest(c)
	ut.AssertEqual(t, "token-secret--Yo", string(getTokenSecret(c)))
}

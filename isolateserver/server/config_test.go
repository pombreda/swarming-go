// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

import (
	"github.com/maruel/aedmztest"
	"github.com/maruel/ut"
	"testing"
)

func TestSettings(t *testing.T) {
	c := aedmztest.NewAppMock(nil).NewContext(nil)
	defer aedmztest.CloseRequest(c)
	expected := &GlobalConfig{RetentionDays: 7, GSBucket: c.AppID()}
	actual := settings(c)
	ut.AssertEqual(t, expected, actual)
}

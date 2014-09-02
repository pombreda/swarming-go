// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

// Instance specific settings.
//
// Use the datastore editor to change the default values.
//
// TODO(maruel): Add frontend to edit the values.

import (
	"github.com/maruel/swarming-go/pkg/aedmz"
)

// GlobalConfig represents application wide settings for this specific server
// instance.
type GlobalConfig struct {
	// The number of days a cache entry must be kept for before it is evicted.
	// Note: this doesn't applies to namespaces where is_temporary is True. For
	// these, the retention is always 1 day.
	RetentionDays int `datastore:"retention_days,noindex"`

	// Secret key used to generate XSRF tokens and signatures.
	GlobalSecret []byte `datastore:"global_secret,noindex"`

	// The Google Cloud Storage bucket where to save the data. By default it's the
	// name of the application instance.
	GSBucket string `datastore:"gs_bucket,noindex"`

	// Email address of Service account used to access Google Storage.
	GSClientIdEmail string `datastore:"gs_client_id_email,noindex"`

	// Secret key used to sign Google Storage URLs: base64 encoded *.der file.
	// TODO(maruel): Should be store as []byte but kept as string for
	// compatibility with the python implementation.
	GSPrivateKey string `datastore:"gs_private_key,noindex"`

	// Comma separated list of email addresses that will receive exception reports.
	// If not set, all admins will receive the message.
	MonitoringRecipients string `datastore:"monitoring_recipients,noindex"`
}

// settings loads GlobalConfig or create one if not present.
//
// Saves any default value that could be missing from the stored entity.
// TODO(maruel): Add cache.
func settings(c aedmz.RequestContext) *GlobalConfig {
	g := &GlobalConfig{RetentionDays: 7, GSBucket: c.AppID()}
	// TODO(maruel): surface error? Not present == defaults is fine.
	k := aedmz.NewKey("GlobalConfig", "global_config", nil)
	err := aedmz.Get(c, k, g)
	if err != nil {
		if err == aedmz.ErrNotFound {
			if _, err = aedmz.Put(c, k, g); err != nil {
				c.Errorf("Failed to save default GlobalConfig: %s", err)
			}
		} else {
			c.Errorf("Failed to load GlobalConfig: %s", err)
		}
	}
	return g
}

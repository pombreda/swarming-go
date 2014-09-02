// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

// Package ofh is OAuth2 For Humans.
//
// It supports both 'installed app' and 'service account' flows. The user can
// use each of these seamlessly.
package ofh

import (
	"errors"
	"net/http"
)

// OAuth2ClientProvider is a reference to an OAuth2 enabled *http.Client
// provider.
//
// All of OAuth2Settings, InstalledApp and ServiceAccount implement this
// interface.
type OAuth2ClientProvider interface {
	// GetClient returns an *http.Client enabled for the corresponding scope on
	// the specified http.RoundTripper. If r is nil, a default transport will be
	// used.
	GetClient(scope string, r http.RoundTripper) (*http.Client, error)
}

// OAuth2Settings is a serializable struct that holds the oauth2 information to
// identify this server to a remote service.
//
// It is a grab bag instance that can be used when you don't know in advance if
// the application will use a user token or a service account token. The
// service account will be used first if configured.
type OAuth2Settings struct {
	InstalledApp   InstalledApp
	ServiceAccount ServiceAccount
}

// MakeOAuth2Settings returns an initialized OAuth2Settings instance with
// commonly used parameters.
func MakeOAuth2Settings() *OAuth2Settings {
	return &OAuth2Settings{
		InstalledApp: *MakeInstalledApp(),
	}
}

// GetClient returns a local client style OAuth2 http.Client with the
// configured credentials.
func (o *OAuth2Settings) GetClient(scope string, r http.RoundTripper) (*http.Client, error) {
	if o.ServiceAccount.ClientID != "" {
		return o.ServiceAccount.GetClient(scope, r)
	}
	return o.InstalledApp.GetClient(scope, r)
}

// StubProvider implements OAuth2ClientProvider but doesn't do anything, it is
// only meant for testing.
type StubProvider struct {
	client *http.Client
	Scopes []string
}

// MakeStubProvider returns an initialized StubProvider.
func MakeStubProvider(client *http.Client) *StubProvider {
	return &StubProvider{client, []string{}}
}

func (s *StubProvider) GetClient(scope string, r http.RoundTripper) (*http.Client, error) {
	s.Scopes = append(s.Scopes, scope)
	if s.client == nil {
		return nil, errors.New("No client")
	}
	return s.client, nil
}

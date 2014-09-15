// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

// Contains all the ACL logic.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	gorillaContext "github.com/gorilla/context"
	"github.com/maruel/aedmz"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// How many bytes of HMAC to use as a signature.
	hmacHashBytes = 8
	// How long token lives.
	tokenExpiration = 2 * time.Hour

	aclKey contextKeyType = 2
)

// Items where the IP address is allowed.
//
// The key is the ip as returned by ipToString(*parseIP(ip)).
type WhitelistedIP struct {
	// Logs who made the change.
	Timestamp time.Time `datastore:"timestamp"` // auto_now=True
	Who       []byte    `datastore:"who"`       // ndb.UserProperty(auto_current_user=True)

	// This is used for sharing token. Use case: a slave are multiple HTTP proxies
	// which different public IP used in a round-robin fashion, so the slave looks
	// like a different IP at each request, but reuses the original token.
	Group string `datastore:"group,noindex"`

	// The textual representation of the IP of the machine to whitelist. Not used
	// in practice, just there since the canonical representation is hard to make
	// sense of.
	IP string `datastore:"ip,noindex"`

	// Is only for maintenance purpose.
	Comment string `datastore:"comment,noindex"`
}

// Domain from which users can use the isolate server.
//
// The key is the domain name, like 'example.com'.
type WhitelistedDomain struct {
	// Logs who made the change.
	Timestamp time.Time `datastore:"timestamp"` // auto_now=True
	Who       []byte    `datastore:"who"`       // ndb.UserProperty(auto_current_user=True)
}

// parseIP returns a long number representing the IP and its type, 'v4' or 'v6'.
//
// This works around potentially different representations of the same value,
// like 1.1.1.1 vs 1.01.1.1 or hex case difference in IPv6.
func parseIP(ipstr string) (string, int64) {
	var factor int64
	var iptype string
	values := make([]int, 0, 8)
	if strings.Count(ipstr, ".") == 3 {
		// IPv4.
		for _, v := range strings.Split(ipstr, ".") {
			vi, err := strconv.Atoi(v)
			if err != nil {
				return "", 0
			}
			if vi < 0 || vi > 255 {
				return "", 0
			}
			values = append(values, vi)
		}
		factor = 256
		iptype = "v4"
	} else if strings.Count(ipstr, ":") == 7 {
		// IPv6.
		for _, v := range strings.Split(ipstr, ":") {
			vi, err := strconv.ParseInt(v, 16, 32)
			if err != nil {
				return "", 0
			}
			if vi < 0 || vi > 65535 {
				return "", 0
			}
			values = append(values, int(vi))
		}
		factor = 65536
		iptype = "v6"
	} else {
		return "", 0
	}
	value := int64(0)
	for _, i := range values {
		value = value*factor + int64(i)
	}
	return iptype, value
}

func ipToString(iptype string, ipvalue int64) string {
	if iptype == "" {
		return ""
	}
	return fmt.Sprintf("%s-%d", iptype, ipvalue)
}

// generateHMACSignature returns HMAC of a list of strings.
//
// Arguments:
//  secret: secret key to sign with.
//  strings: list of strings to sign.
//
// Returns:
//  Signature (as str object with binary data) of length HMAC_HASH_BYTES.
func generateHMACSignature(secret []byte, str []string) []byte {
	// Ensure data is a non empty list of strings that do not contain '\0'.
	// Unicode strings are not allowed.
	if len(secret) == 0 {
		return nil
	}
	for _, v := range str {
		if strings.Contains(v, "\x00") {
			return nil
		}
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strings.Join(str, "\x00")))
	return mac.Sum(nil)[:hmacHashBytes]
}

// generateTokenInternal returns new token that expires after |expiration|
// seconds.
//
// Arguments:
//   accessID: identifies a client this token is issued to.
//   secret: secret key to sign token with.
//   expiration: how long token will be valid.
//   tokenData: an optional dict with string keys and values that will be put
//               in the token. Keys starting with '_' are reserved for internal
//               use. This data is publicly visible.
//
// Returns:
//   Base64 encoded token string.
func generateTokenInternal(accessID string, secret []byte, expiration time.Duration, tokenData map[string]string, now time.Time) string {
	if len(accessID) == 0 || len(secret) == 0 || expiration <= 0 {
		return ""
	}

	// Convert dict to a flat list of key-value pairs, append expiration timestamp.
	e := fmt.Sprintf("%d", now.Add(expiration).Unix())

	p := make([]string, 0, len(tokenData)*2+2)
	for k, v := range tokenData {
		p = append(p, k, v)
	}
	p = append(p, "_x", e)
	//assert all('\0' not in x for x in p)

	// Append accessID and sign it with secret key. accessID is not in the token itself.
	p2 := make([]string, len(p)+1)
	copy(p2, p)
	p2[len(p)] = accessID
	sig := generateHMACSignature(secret, p2)

	// Final token is base64 encoded p + sig.
	x := []byte(strings.Join(p, "\x00"))
	x = append(x, sig...)
	return base64.URLEncoding.EncodeToString(x)
}

// validateToken checks token signature and expiration, decodes data embedded into it.
//
// The following holds:
//   token = generateToken(secret, expiration_sec, tokenData)
//   assert validateToken(token, secret) == tokenData
//
// Arguments:
//   token: token produced by generateToken call.
//   accessID: identifies a client this token should belong to.
//   secret: secret used to sign the token.
//
// Returns:
//   A dict with public data embedded into the token.
func validateToken(token, accessID string, secret []byte, now time.Time) (map[string]string, error) {
	// Reverse actions performed in generateToken to encode the token.
	blob, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, errors.New("Bad token format")
	}
	// TODO(maruel): Errrr...
	p := strings.Split(string(blob[:len(blob)-hmacHashBytes]), "\x00")
	s := blob[len(blob)-hmacHashBytes:]
	// Flat list of key-value pairs can't have odd length.
	if len(p)%2 != 0 {
		return nil, errors.New("Bad token format")
	}

	// Calculate a correct signature for given secret and p. The signature
	// includes accessID.
	p2 := make([]string, len(p)+1)
	copy(p2, p)
	p2[len(p)] = accessID
	sig := generateHMACSignature(secret, p2)
	// It should be equal to provided signature.
	if subtle.ConstantTimeCompare(sig, s) != 1 {
		return nil, errors.New("Token signature is invalid")
	}

	// At this point we're sure that token was generated by us. It still can be
	// expired though, so check it next.
	t := make(map[string]string)
	for i := 0; i < len(p); i += 2 {
		// Convert flat list of key-value pairs back to dict.
		t[p[i]] = p[i+1]
	}
	// Ensure timestamp is there and has a valid format, also remove it from dict.
	e, err := strconv.ParseInt(t["_x"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Invalid timestamp format: %s, %s", t["_x"])
	}
	et := time.Unix(e, 0)
	// Check timestamp for expiration.
	if now.After(et) {
		return nil, fmt.Errorf("Token expired %d sec ago", int(now.Sub(et).Seconds()))
	}
	if now.Before(et.Add(-tokenExpiration)) {
		return nil, fmt.Errorf("Token is in the future")
	}
	delete(t, "_x")
	// Token is valid and non-expired.
	return t, nil
}

type aclContext struct {
	AccessID  string
	TokenData map[string]string
}

func setACLContext(r *http.Request, acl *aclContext) {
	gorillaContext.Set(r, aclKey, acl)
}

func GetACLContext(r *http.Request) *aclContext {
	return gorillaContext.Get(r, aclKey).(*aclContext)
}

// GetAccessID should only be called by handshake.
func GetAccessID(c aedmz.RequestContext, r *http.Request) string {
	u := c.UserCurrent()
	var accessID string
	if u != nil {
		accessID = checkUser(c, u)
	} else {
		accessID = checkIP(c, strings.Split(r.RemoteAddr, ":")[0])
	}
	c.Infof("AccessID: %s", accessID)
	return accessID
}

// ACL adds ACL to gorilla context to the request handler.
//
// It also enforces the user has a valid token.
func ACL(handler http.HandlerFunc) http.HandlerFunc {
	// Token data dict embedded into token via 'generateToken'. Valid only for
	// POST or PUT requests.
	//tokenData = None

	// Ensures that only users from valid domains can continue, and that users
	// from invalid domains receive an error message.
	return func(w http.ResponseWriter, r *http.Request) {
		// Set to the uniquely identifiable id, either the userid or the IP address.
		c := aedmz.GetContext(r)
		a := &aclContext{AccessID: GetAccessID(c, r)}
		// Do not use sendError here since we don't want this in the logs.
		if a.AccessID == "" {
			http.Error(w, "Please login first", http.StatusUnauthorized)
			return
		}
		if r.Method == "POST" || r.Method == "PUT" {
			// TODO(maruel): This adds an implicit 10mb limit on POST.
			r.ParseForm()
			a.TokenData = enforceValidToken(c, a.AccessID, r.Form.Get("token"))
			if a.TokenData == nil {
				c.Warningf("Invalid token")
				http.Error(w, "Invalid token", http.StatusForbidden)
				return
			}
		}
		handler(w, r)
	}
}

// checkIP verifies the IP is whitelisted.
//
// It returns an empty string in case the IP is not whitelisted.
func checkIP(c aedmz.RequestContext, ip string) string {
	// TODO(maruel): Hack.
	if ip == "127.0.0.1" {
		return ip
	}
	ipType, ipValue := parseIP(ip)
	w := new(WhitelistedIP)
	k := aedmz.NewKey("WhitelistedIP", ipToString(ipType, ipValue), nil)
	err := aedmz.Get(c, k, w)
	if err != nil {
		c.Warningf("Blocking IP %s", ip)
		return ""
	}
	if w.Group != "" {
		// Any member of of the group can impersonate others. This is to enable
		// support for slaves behind proxies with multiple IPs.
		return w.Group
	}
	return ip
}

// checkUser verifies the user is whitelisted.
//
// It returns an empty string in case the user is not whitelisted.
func checkUser(c aedmz.RequestContext, user *aedmz.User) string {
	id := user.ID
	if id == "" {
		id = user.Email
	}
	if user.Admin {
		c.Infof("User is admin")
		return user.ID
	}
	domain := strings.SplitN(user.Email, "@", 1)[1]
	w := new(WhitelistedDomain)
	k := aedmz.NewKey("WhitelistedDomain", domain, nil)
	if err := aedmz.Get(c, k, w); err != nil {
		c.Warningf("Disallowing %s, invalid domain", user.Email)
		return ""
	}
	// user_id() is only set with Google accounts, fallback to the email address
	// otherwise.
	return id
}

// enforceValidToken returns a map of the encoded token if valid.
func enforceValidToken(c aedmz.RequestContext, accessID, token string) map[string]string {
	if token == "" {
		return nil
	}
	t, err := validateToken(token, accessID, getTokenSecret(c), time.Now())
	if err != nil {
		return nil
	}
	return t
}

// getTokenSecret returns secret key used to sign or validate a token.
func getTokenSecret(c aedmz.RequestContext) []byte {
	return []byte(fmt.Sprintf("token-secret-%s-%s", settings(c).GlobalSecret, c.AppID()))
}

// generateToken returns a valid access token for this request.
//
// Arguments:
//   tokenData: optional dict with string keys and values that will be
//              embedded into the token. It's later accessible as
//              self.tokenData. It's publicly visible.
func generateToken(c aedmz.RequestContext, accessID string, tokenData map[string]string) string {
	return generateTokenInternal(accessID, getTokenSecret(c), tokenExpiration, tokenData, time.Now())
}

// TODO(maruel): Add back code to edit the ACL. This will be superseeded by
// Vadim's work anyway.

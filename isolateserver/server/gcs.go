// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

// Accesses files on Google Cloud Storage via Google Cloud Storage Client API.
//
// References:
//  http://godoc.org/code.google.com/p/google-api-go-client/storage/v1beta2
//  https://developers.google.com/storage/docs/accesscontrol#Signed-URLs

import (
	"bytes"
	"code.google.com/p/google-api-go-client/storage/v1beta2"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/maruel/aedmz"
	"io"
	"io/ioutil"
	"net/url"
	"time"
)

// Object that can generated signed Google Storage URLs.
type urlSigner struct {
	c                 aedmz.RequestContext
	defaultExpiration time.Duration // Default expiration time for signed links.
	gsURL             string        // Google Storage URL template for a singed link.
	bucket            string
	clientID          string
	privateKey        *rsa.PrivateKey
}

func newURLSigner(c aedmz.RequestContext, bucket string, clientID string, privateKey string) *urlSigner {
	return &urlSigner{
		c,
		4 * time.Hour,
		"https://%s.storage.googleapis.com/%s?%s",
		bucket,
		clientID,
		loadPrivateKey(c, privateKey),
	}
}

// loadPrivateKey converts base64 *.der private key into RSA key instance.
func loadPrivateKey(c aedmz.RequestContext, privateKey string) *rsa.PrivateKey {
	// Empty private key is ok in a dev mode.
	if privateKey == "" {
		return nil
	}
	binary, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		c.Errorf("Failed to base64 decode private key: %s", err)
		return nil
	}
	key, err := x509.ParsePKCS1PrivateKey(binary)
	if err != nil {
		c.Errorf("Failed to load private key: %s\n%d bytes", err, len(binary))
		return nil
	}
	return key
}

// generateSignature signs |data_to_sign| with a private key and returns a
// base64 encoded signature.
//
// Signs it with RSA-SHA-256.
func (u *urlSigner) generateSignature(dataToSign []byte) string {
	// Signatures are not used in a dev mode.
	if u.privateKey == nil {
		return "fakesig"
	}
	h := sha256.New()
	_, _ = h.Write(dataToSign)
	s, err := rsa.SignPKCS1v15(rand.Reader, u.privateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		u.c.Errorf("Failed to sign: %s", err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(s)
}

// getSignedURL returns signed URL that can be used by clients to access a file.
func (u *urlSigner) getSignedURL(filename string, httpVerb string, expiration time.Duration, contentType string, contentMD5 []byte, now int64) string {
	if expiration == 0 {
		expiration = u.defaultExpiration
	}
	// Prepare data to sign.
	e := fmt.Sprintf("%d", now+int64(expiration))
	dataToSign := fmt.Sprintf("%s\n%s\n%s\n%s\n/%s/%s", httpVerb, contentMD5, contentType, e, u.bucket, filename)
	v := url.Values{}
	v.Set("GoogleAccessId", u.clientID)
	v.Set("Expires", e)
	v.Set("Signature", u.generateSignature([]byte(dataToSign)))
	return fmt.Sprintf(u.gsURL, u.bucket, filename, v.Encode())
}

// GetDownloadURL returns signed URL that can be used to download a file to GS.
func (u *urlSigner) GetDownloadURL(filename string, expiration time.Duration) string {
	now := time.Now().Unix()
	return u.getSignedURL(filename, "GET", expiration, "", nil, now)
}

// GetUploadURL returns signed URL that can be used to upload a file to GS.
func (u *urlSigner) GetUploadURL(filename string, expiration time.Duration, contentType string, contentMD5 []byte) string {
	now := time.Now().Unix()
	return u.getSignedURL(filename, "PUT", expiration, contentType, contentMD5, now)
}

// getFileInfo metadata about an object from a bucket.
func getFileInfo(c aedmz.RequestContext, bucket, filePath string) (*storage.Object, error) {
	// Note: doing a HEAD on the fetch request would do the job as well.
	s, err := getService(c, storage.DevstorageRead_onlyScope)
	if err != nil {
		return nil, err
	}
	res, err := s.Objects.Get(bucket, filePath).Do()
	if err != nil {
		c.Errorf("Failed to get %s/%s: %s.", bucket, filePath, err)
		return nil, err
	}
	c.Infof("The media download link for %v/%v is %v.", bucket, res.Name, res.MediaLink)
	return res, nil
}

type newReadItem struct {
	io.ReadCloser
	error
}

type chainedReadCloser struct {
	// TODO(maruel): Implement ReadByte() and anything necessary to speed up
	// decompression.
	c           aedmz.Logger
	chain       chan newReadItem
	currentItem io.ReadCloser
	chunkSize   int
}

func (c *chainedReadCloser) Read(p []byte) (int, error) {
tryagain:
	if c.currentItem == nil {
		x, ok := <-c.chain
		if !ok {
			c.c.Infof("Got end")
			return 0, io.EOF
		}
		if x.error != nil {
			c.c.Infof("Got error: %s", x.error)
			// Once an error is sent, work is done.
			return 0, x.error
		}
		c.currentItem = x.ReadCloser
	}
	n, err := c.currentItem.Read(p)
	c.chunkSize += n
	if err != nil {
		if err == io.EOF {
			// Grab the next item right away.
			_ = c.currentItem.Close()
			c.currentItem = nil
			c.c.Infof("Completed a chunk %d", c.chunkSize)
			c.chunkSize = 0
			err = nil
			if n == 0 {
				goto tryagain
			}
		}
	}
	// TODO(maruel): What to do with the case of n==0 && err==nil ?
	return n, err
}

func (c *chainedReadCloser) Close() error {
	if c.currentItem != nil {
		_ = c.currentItem.Close()
		c.currentItem = nil
	}
	if c.chain != nil {
		close(c.chain)
	}
	return nil
}

// readFile reads a file transparently via multiple HTTP GET requests.
//
// This is to work around GAE limits of 10Mb up/32Mb down, see
// https://developers.google.com/appengine/docs/go/urlfetch/#Go_Quotas_and_limits
// for updated values.
func readFile(c aedmz.RequestContext, bucket, filePath string) (io.ReadCloser, error) {
	hc, err := c.OAuth2HTTPClient(storage.DevstorageRead_onlyScope)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s.storage.googleapis.com/%s", bucket, filePath)
	size, err := getSize(hc, url)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return ioutil.NopCloser(&bytes.Buffer{}), nil
	}

	// Grab 128kb at a time, 8 chunks buffered. The rationale for smaller chunks
	// is: IIRC, on AppEngine, the request will return only after the whole
	// response has been read. This increases the latency to the whole requests,
	// so to keep latency low, it's better to do several short requests.
	//
	// TODO(maruel): In practice, we'd want to only do this shewinigan on
	// AppEngine, since it is unnecessary otherwise. Still, a retry mechanism
	// would be worth keeping.
	const chunkSize = 128 * 1024
	out := make(chan newReadItem, 8)

	go func() {
		defer func() {
			out <- newReadItem{nil, io.EOF}
		}()
		for i := int64(0); i < size; i += chunkSize {
			// BUG(maruel): Retry failed fetches, it's necessary.
			max := i + chunkSize
			if max > size {
				max = size
			}
			b, err := rangeRequest(hc, url, i, max-1)
			c.Infof("Fetched %d-%d", i, max)
			out <- newReadItem{b, err}
		}
	}()

	return &chainedReadCloser{c, out, nil, 0}, nil
}

// writeFile creates a Cloud Storage file and write it as a single request.
func writeFile(c aedmz.RequestContext, bucket, filePath string, content []byte) error {
	s, err := getService(c, storage.DevstorageRead_writeScope)
	if err != nil {
		c.Errorf("Failed to get service: %s", err)
		return err
	}
	// Insert an object into a bucket.
	object := &storage.Object{Name: filePath}
	f := &bytes.Buffer{}
	res, err := s.Objects.Insert(bucket, object).Media(f).Do()
	if err != nil {
		c.Errorf("Objects.Insert failed: %v", err)
		return err
	}
	c.Infof("Created object %v at location %v", res.Name, res.SelfLink)
	return nil
}

func deleteFile(c aedmz.RequestContext, bucket, filePath string) error {
	s, err := getService(c, storage.DevstorageRead_writeScope)
	if err != nil {
		c.Errorf("Failed to get service: %s", err)
		return err
	}
	return s.Objects.Delete(bucket, filePath).Do()
}

// getService returns a wrapped http client that can be used to send RPCs to GS.
func getService(c aedmz.RequestContext, scope string) (*storage.Service, error) {
	hc, err := c.OAuth2HTTPClient(scope)
	if err != nil {
		return nil, fmt.Errorf("No OAuth2 client: %s", err)
	}
	return storage.New(hc)
}

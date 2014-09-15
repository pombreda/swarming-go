// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

// Contains HTTP handler related utilities.

import (
	"encoding/json"
	"fmt"
	"github.com/maruel/aedmz"
	"io"
	"net/http"
)

// sendData sends binary data as a response.
//
// If |offset| is zero, returns an entire |data| and sets HTTP code to 200.
// If |offset| is non-zero, returns a subrange of |data| with HTTP code
// set to 206 and 'Content-Range' header.
// If |offset| is outside of acceptable range, returns HTTP code 416.
func sendData(c aedmz.RequestContext, w http.ResponseWriter, data []byte, filename string, offset int) {
	if offset < 0 || (offset >= len(data) && !(offset == 0 && len(data) == 0)) {
		// Bad offset? Return 416.
		//http.Error(w, "", 416)
		sendError(c, w, 416, "Invalid range: %d for %d bytes of data", offset, len(data))
		return
	}
	// Common headers that are set regardless of |offset| value.
	if filename != "" {
		w.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%+q", filename))
		w.Header().Add("Content-Type", "application/octet-stream")
		w.Header().Add("Cache-Control", "public, max-age=43200")
	}
	if offset == 0 {
		// Returning an entire file.
		w.WriteHeader(200)
		w.Write(data)
	} else {
		// Returning a partial content, set Content-Range header.
		w.WriteHeader(206)
		w.Header().Add("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, len(data)-1, len(data)))
		w.Write(data[offset:])
	}
}

// sendJSON sends json encoded data as a response.
func sendJSON(w http.ResponseWriter, obj interface{}) {
	w.Header().Add("Content-Type", "application/json")
	e := json.NewEncoder(w)
	err := e.Encode(obj)
	if err != nil {
		panic(err)
	}
}

// sendError sends a text plain string as a response and logs the error.
func sendError(c aedmz.RequestContext, w http.ResponseWriter, code int, format string, v ...interface{}) {
	w.Header().Add("Content-Type", "text/plain")
	if len(v) != 0 {
		format = fmt.Sprintf(format, v...)
	}
	c.Errorf(format)
	http.Error(w, format, code)
}

// rangeRequest does a GET http requests and asks the remote server to return a
// subset of the data.
//
// Note that the range is *inclusive*. end=0 means up to the end of the file.
func rangeRequest(c *http.Client, url string, start, end int64) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if end == 0 {
		req.Header.Add("Range", fmt.Sprintf("bytes=%d-", start))
	} else {
		req.Header.Add("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 206 {
		return nil, fmt.Errorf("Unexpected code %d", resp.StatusCode)
	}
	return resp.Body, err
}

func getSize(c *http.Client, url string) (int64, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("Unexpected code %d", resp.StatusCode)
	}
	return resp.ContentLength, err
}

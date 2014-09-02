// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

import (
	"regexp"
)

const (
	// The minimum size, in bytes, an entry must be before it gets stored in
	// Google Cloud Storage, otherwise it is stored as a blob property.
	MIN_SIZE_FOR_GS = 501

	// The minimum size, in bytes, for entry that get's uploaded directly to
	// Google Cloud Storage, bypassing App engine layer.
	MIN_SIZE_FOR_DIRECT_GS = 20 * 1024

	// Maximum size of file stored in GS to be saved in memcache. The value must
	// be small enough so that the whole content can safely fit in memory.
	MAX_MEMCACHE_ISOLATED = 500 * 1024
)

// FileEntry represents a single entry to store on the server in a specific namespace.
//
// The namespace implies the compression and hashing algorithm.
type FileEntry struct {
	HexDigest  string `json:"h"`
	IsIsolated int    `json:"i"` // 1 for isolated file, 0 for rest of them
	Size       int64  `json:"s"` // Uncompressed size of the object.
}

// IsValid returns true if the FileEntry is a valid entry.
func (f *FileEntry) IsValid(re *regexp.Regexp) bool {
	if f.Size < 0 {
		return false
	}
	if f.IsIsolated != 0 && f.IsIsolated != 1 {
		return false
	}
	return re.MatchString(f.HexDigest)
}

// shouldPushToGS returns true to direct client to upload given EntryInfo
// directly to GS.
func shouldPushToGS(entry *FileEntry) bool {
	// Relatively small *.isolated files go through app engine to cache them.
	if entry.IsIsolated != 0 && entry.Size <= MAX_MEMCACHE_ISOLATED {
		return false
	}
	// All other large enough files go through GS.
	return entry.Size >= MIN_SIZE_FOR_DIRECT_GS
}

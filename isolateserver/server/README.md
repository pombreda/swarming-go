Isolate server implementation
=============================

The actual server implementation is separated in an AppEngine-agnostic package
for documentation and the removal of conditional compilation, which is in the
'isolateserver' directory containing this 'server' directory.

See doc at
[![GoDoc](https://godoc.org/github.com/maruel/swarming-go/isolateserver/server?status.svg)](https://godoc.org/github.com/maruel/swarming-go/isolateserver/server)

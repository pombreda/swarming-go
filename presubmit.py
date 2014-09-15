#!/usr/bin/env python
# Copyright 2014 Marc-Antoine Ruel. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

"""Runs all go tests."""

import optparse
import os
import subprocess
import sys
import time


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def call(cmd, reldir):
  return subprocess.Popen(
      cmd, cwd=os.path.join(ROOT_DIR, reldir),
      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def errcheck(reldir):
  cmd = ['errcheck']
  try:
    return call(cmd, reldir)
  except OSError:
    print('Warning: installing github.com/kisielk/errcheck')
    out = drain(call(['go', 'get', '-u', 'github.com/kisielk/errcheck'], '.'))
    if out:
      print out
    return call(cmd, reldir)


def drain(proc):
  out = proc.communicate()[0]
  if proc.returncode:
    return out


def main():
  parser = optparse.OptionParser(description=sys.modules[__name__].__doc__)
  parser.add_option('--gae', action='store_true')
  parser.add_option('-v', '--verbose', action='store_true')
  options, args = parser.parse_args()

  if options.gae:
    # TODO(maruel): Google AppEngine's 'goapp test' fails in some specific
    # circumstances when -v is not provided. Remove '-v' once this is working
    # again without hanging. http://b/12315827.
    cmd = [
        os.path.join(ROOT_DIR, 'tools', 'goapp.py'),
        'test',
        '-v',
    ]
  else:
    cmd = ['go', 'test']
    if options.verbose:
      cmd.append('-v')

  start = time.time()
  procs = [
    call(cmd, 'isolateserver'),
    call(cmd, 'isolateserver/server'),
    errcheck('isolateserver'),
    errcheck('isolateserver/server'),
  ]
  failed = False
  out = drain(procs.pop(0))
  if out:
    failed = True
    print out

  for p in procs:
    out = drain(p)
    if out:
      failed = True
      print out

  end = time.time()
  if failed:
    print('Presubmit checks failed in %1.3fs!' % (end-start))
    return 1
  print('Presubmit checks succeeded in %1.3fs!' % (end-start))
  return 0


if __name__ == '__main__':
  sys.exit(main())

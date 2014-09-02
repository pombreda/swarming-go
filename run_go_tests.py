#!/usr/bin/env python
# Copyright 2014 Marc-Antoine Ruel. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Runs all go test found in every subdirectories."""

import optparse
import os
import signal
import subprocess
import sys
import time
import threading

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(ROOT_DIR, 'third_party', 'swarming_client'))

import threading_utils


def find_all_testable_packages(root_dir):
  """Finds all the directories containing go tests, excluding third_party."""
  directories = set()
  for root, dirs, files in os.walk(root_dir):
    if any(f.endswith('_test.go') for f in files):
      directories.add(root)
    for i in dirs[:]:
      if i.startswith('.') or i == 'third_party':
        dirs.remove(i)
  return directories


def precompile(cmd, directory):
  """Prebuilds the dependencies of the tests to get rid of annoying messages.

  It slows the whole thing down a tad but not significantly.
  """
  try:
    with open(os.devnull, 'wb') as f:
      p = subprocess.Popen(
          cmd + ['-i'], cwd=directory, stdout=f, stderr=subprocess.STDOUT)
  except OSError as e:
    pass
  p.wait()


def timed_call(cmd, cwd, piped):
  """Calls a subprocess and returns the time it took.

  Take extra precautions to kill grand-children processes.
  """
  start = time.time()
  kwargs = {}
  if piped:
    kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  p = subprocess.Popen(cmd, cwd=cwd, preexec_fn=os.setsid, **kwargs)
  out = p.communicate()[0]
  # Kill any grand-child processes that may be left hanging around.
  try:
    os.killpg(p.pid, signal.SIGKILL)
  except OSError:
    pass
  p.wait()
  duration = time.time() - start
  return p.returncode, duration, out


def run_test_directory(cmd, verbose, directory, name):
  """Runs a single test directory.

  In Go, all the *_test.go in a directory collectively make up the unit test for
  this package. So a "directory" is a "test".
  """
  out = name
  returncode, duration, output = timed_call(cmd, directory, True)
  if returncode or verbose:
    out = '%s\n%s\n' % (name, output.strip())
  return name, returncode, out


def run_tests(cmd, verbose):
  """Runs all the Go tests in all the subdirectories of ROOT_DIR."""
  directories = sorted(find_all_testable_packages(ROOT_DIR))
  for directory in directories:
    precompile(cmd, directory)

  # Especially the GAE testing framework is ridiculously dog slow.
  offset = len(ROOT_DIR) + 1
  size = len(directories)
  progress = threading_utils.Progress([('index', 0), ('total', 0)])
  result = 0
  with threading_utils.ThreadPool(size, size, 0) as pool:
    names = set()
    for directory in directories:
      name = directory[offset:]
      names.add(name)
      progress.update_item(name, total=1)
      progress.print_update()
      pool.add_task(0, run_test_directory, cmd, verbose, directory, name)

    progress.update_item(','.join(sorted(names)))
    progress.print_update()
    for name, returncode, out in pool.iter_results():
      progress.update_item(name, index=1)
      names.remove(name)
      progress.print_update()
      result = result or returncode
      progress.update_item('\n' + ','.join(sorted(names)))
      progress.print_update()
  print('')
  return result


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
  return run_tests(cmd, options.verbose or options.gae)


if __name__ == '__main__':
  sys.exit(main())

#!/usr/bin/env python
# Copyright 2014 Marc-Antoine Ruel. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

import sys

import find_gae_sdk

args = sys.argv[1:]
if not args:
  args = ['-http=:6060']
sys.exit(find_gae_sdk.run(['godoc'] + args))

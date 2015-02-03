#!/usr/bin/python

# OpenChange Python bindings
# Copyright (C) Jelmer Vernooij <jelmer@openchange.org> 2008
#   
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#   
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#   
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

__docformat__ = 'restructuredText'

import os, sys

try:
    import samba
except ImportError:
    # Try to fix up sys.path if Samba is installed in an unusual location
    SAMBA_PREFIXES = ["/usr/local/samba", "/opt/samba"]
    for samba_prefix in SAMBA_PREFIXES:
        if not os.path.isdir(samba_prefix):
            continue
        for lib_dir in ["lib", "lib64"]:
            python_version = "%d.%d" % sys.version_info[:2]
            path = os.path.join(samba_prefix, lib_dir,
                "python%s" % python_version, "site-packages")
            if os.path.isdir(os.path.join(path, "samba")):
                sys.path.append(path)
                break
    import samba


def test_suite():
    import openchange.tests
    return openchange.tests.test_suite()


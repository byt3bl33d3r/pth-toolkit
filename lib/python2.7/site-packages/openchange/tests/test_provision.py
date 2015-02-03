#!/usr/bin/python

# OpenChange provisioning
# Copyright (C) Jelmer Vernooij <jelmer@openchange.org> 2009
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

from samba import param
from samba.credentials import Credentials
from samba.tests import TestCaseInTempDir
from samba.tests.samdb import SamDBTestCase
from openchange.provision import (install_schemas, openchangedb_provision,
    guess_names_from_smbconf, find_setup_dir)

import os
import shutil


class ExtendedSamDBTestCase(SamDBTestCase):

    def test_install_schemas(self):
        def setup_path(relpath):
            return os.path.join(find_setup_dir(), relpath)

        names = guess_names_from_smbconf(self.lp)
        creds = Credentials()
        creds.set_anonymous()
        self.lp.set("sam database", os.path.join(self.tempdir, "samdb.ldb"))
        install_schemas(setup_path, names, self.lp, creds)


class OpenChangeDBProvisionTestCase(TestCaseInTempDir):

    def test_provision(self):
        lp = param.LoadParm()
        lp.load_default()
        lp.set("private dir", self.tempdir)
        openchangedb_provision(lp)
        shutil.rmtree(os.path.join(self.tempdir, "mapistore"))
        os.unlink(os.path.join(self.tempdir, "openchange.ldb"))

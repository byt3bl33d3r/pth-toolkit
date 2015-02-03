#!/usr/bin/python

# OpenChange provisioning
# Copyright (C) Julien Kerihuel <j.kerihuel@openchange.org> 2009
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

import os
import samba
from samba import Ldb, unix2nttime
import ldb
import uuid
import time
from openchange.urlutils import *

__docformat__ = 'restructuredText'

class NoSuchServer(Exception):
    """Raised when a server could not be found."""


class OpenChangeDB(object):
    """The OpenChange database.
    """

    def __init__(self, url):
        self.url = url
        self.ldb = Ldb(self.url)
	self.nttime = samba.unix2nttime(int(time.time()))

    def reopen(self):
        self.ldb = Ldb(self.url)

    def setup(self):
        self.ldb.add_ldif("""
dn: @OPTIONS
checkBaseOnSearch: TRUE

dn: @INDEXLIST
@IDXATTR: cn

dn: @ATTRIBUTES
cn: CASE_INSENSITIVE
dn: CASE_INSENSITIVE

""")
        self.reopen()

    def add_rootDSE(self, ocserverdn, firstorg, firstou):
        self.ldb.add({"dn": "@ROOTDSE",
                      "defaultNamingContext": "CN=%s,CN=%s,%s" % (firstou, firstorg, ocserverdn),
                      "rootDomainNamingContext": ocserverdn,
                      "vendorName": "OpenChange Team (http://www.openchange.org)"})

    def add_server(self, ocserverdn, netbiosname, firstorg, firstou):
        self.ldb.add({"dn": ocserverdn,
                      "objectClass": ["top", "server"],
                      "cn": netbiosname,
                      "GlobalCount": "1",
                      "ChangeNumber": "1",
                      "ReplicaID": "1"})
        self.ldb.add({"dn": "CN=%s,%s" % (firstorg, ocserverdn),
                      "objectClass": ["top", "org"],
                      "cn": firstorg})
        self.ldb.add({"dn": "CN=%s,CN=%s,%s" % (firstou, firstorg, ocserverdn),
                      "objectClass": ["top", "ou"],
                      "cn": firstou})

    def add_root_public_folder(self, dn, fid, change_num, SystemIdx, childcount):
        self.ldb.add({"dn": dn,
                      "objectClass": ["publicfolder"],
                      "cn": fid,
                      "PidTagFolderId": fid,
                      "PidTagChangeNumber": change_num,
                      "PidTagDisplayName": "Public Folder Root",
                      "PidTagCreationTime": "%d" % self.nttime,
                      "PidTagLastModificationTime": "%d" % self.nttime,
                      "PidTagSubFolders": str(childcount != 0).upper(),
                      "PidTagFolderChildCount": str(childcount),
                      "SystemIdx": str(SystemIdx)})

    def add_sub_public_folder(self, dn, parentfid, fid, change_num, name, SystemIndex, childcount):
        self.ldb.add({"dn": dn,
                      "objectClass": ["publicfolder"],
                      "cn": fid,
                      "PidTagFolderId": fid,
                      "PidTagParentFolderId": parentfid,
                      "PidTagChangeNumber": change_num,
                      "PidTagDisplayName": name,
                      "PidTagCreationTime": "%d" % self.nttime,
                      "PidTagLastModificationTime": "%d" % self.nttime,
                      "PidTagAttributeHidden": str(0),
                      "PidTagAttributeReadOnly": str(0),
                      "PidTagAttributeSystem": str(0),
                      "PidTagContainerClass": "IPF.Note (check this)",
                      "PidTagSubFolders": str(childcount != 0).upper(),
                      "PidTagFolderChildCount": str(childcount),
                      "FolderType": str(1),
                      "SystemIdx": str(SystemIndex)})

    def add_one_public_folder(self, parent_fid, path, children, SystemIndex, names, dn_prefix = None):

        name = path[-1]
        GlobalCount = self.get_message_GlobalCount(names.netbiosname)
        ChangeNumber = self.get_message_ChangeNumber(names.netbiosname)
        ReplicaID = self.get_message_ReplicaID(names.netbiosname)
        if dn_prefix is None:
            dn_prefix = "CN=publicfolders,CN=%s,CN=%s,%s" % (names.firstou, names.firstorg, names.ocserverdn)
        fid = gen_mailbox_folder_fid(GlobalCount, ReplicaID)
        dn = "CN=%s,%s" % (fid, dn_prefix)
        change_num = gen_mailbox_folder_fid(ChangeNumber, ReplicaID)
        childcount = len(children)
        print "\t* %-40s: 0x%.16x (%s)" % (name, int(fid, 10), fid)
        if parent_fid == 0:
            self.add_root_public_folder(dn, fid, change_num, SystemIndex, childcount)
        else:
            self.add_sub_public_folder(dn, parent_fid, fid, change_num, name, SystemIndex, childcount);

        GlobalCount += 1
        self.set_message_GlobalCount(names.netbiosname, GlobalCount=GlobalCount)
        ChangeNumber += 1
        self.set_message_ChangeNumber(names.netbiosname, ChangeNumber=ChangeNumber)

        for name, grandchildren in children.iteritems():
            self.add_one_public_folder(fid, path + (name,), grandchildren[0], grandchildren[1], names, dn)

    def add_public_folders(self, names):
        pfstoreGUID = str(uuid.uuid4())
        self.ldb.add({"dn": "CN=publicfolders,CN=%s,CN=%s,%s" % (names.firstou, names.firstorg, names.ocserverdn),
                      "objectClass": ["container"],
                      "cn": "publicfolders",
                      "StoreGUID": pfstoreGUID,
                      "ReplicaID": str(1)})
        public_folders = ({
                "IPM_SUBTREE": ({}, 2),
                "NON_IPM_SUBTREE": ({
                        "EFORMS REGISTRY": ({}, 4),
                        "Events Root": ({}, -1),
                        "OFFLINE ADDRESS BOOK": ({
                                "/o=%s/cn=addrlists/cn=oabs/cn=Default Offline Address Book" % (names.firstorg): ({}, 9),
                                }, 6),
                        "SCHEDULE+ FREE BUSY": ({
                                "EX:/o=%s/ou=%s" % (names.firstorg.lower(), names.firstou.lower()): ({}, 8),
                                }, 5),
                        }, 3),
                }, 1)

        self.add_one_public_folder(0, ("Public Folder Root",), public_folders[0], public_folders[1], names)
        
    def lookup_server(self, cn, attributes=[]):
        # Step 1. Search Server object
        filter = "(&(objectClass=server)(cn=%s))" % cn
        res = self.ldb.search("", scope=ldb.SCOPE_SUBTREE,
                           expression=filter, attrs=attributes)
        if len(res) != 1:
            raise NoSuchServer(cn)
        return res[0]

    def lookup_mailbox_user(self, server, username, attributes=[]):
        """Check if a user already exists in openchange database.

        :param server: Server object name
        :param username: Username object
        :return: LDB Object of the user
        """
        server_dn = self.lookup_server(server, []).dn

        # Step 2. Search User object
        filter = "(&(objectClass=mailbox)(cn=%s))" % (username)
        return self.ldb.search(server_dn, scope=ldb.SCOPE_SUBTREE,
                           expression=filter, attrs=attributes)

    def lookup_public_folder(self, server, displayname, attributes=[]):
        """Retrieve the record for a public folder matching a specific display name

        :param server: Server Object Name
        :param displayname: Display Name of the Folder
        :param attributes: Requested Attributes
        :return: LDB Object of the Folder
        """
        server_dn = self.lookup_server(server, []).dn

        filter = "(&(objectClass=publicfolder)(PidTagDisplayName=%s))" % (displayname)
        return self.ldb.search(server_dn, scope=ldb.SCOPE_SUBTREE,
                               expression=filter, attrs=attributes)

    def get_message_attribute(self, server, attribute):
        """Retrieve attribute value from given message database (server).

        :param server: Server object name
        """
        return int(self.lookup_server(server, [attribute])[attribute][0], 10)

    def get_message_ReplicaID(self, server):
        """Retrieve current mailbox Replica ID for given message database (server).

        :param server: Server object name
        """
        return self.get_message_attribute(server, "ReplicaID")

    def get_message_GlobalCount(self, server):
        """Retrieve current mailbox Global Count for given message database (server).

        :param server: Server object name
        """
        return self.get_message_attribute(server, "GlobalCount")


    def set_message_GlobalCount(self, server, GlobalCount):
        """Update current mailbox GlobalCount for given message database (server).

        :param server: Server object name
        :param index: Mailbox new GlobalCount value
        """
        server_dn = self.lookup_server(server, []).dn

        newGlobalCount = """
dn: %s
changetype: modify
replace: GlobalCount
GlobalCount: %d
""" % (server_dn, GlobalCount)

        self.ldb.transaction_start()
        try:
            self.ldb.modify_ldif(newGlobalCount)
        finally:
            self.ldb.transaction_commit()

    def get_message_ChangeNumber(self, server):
        """Retrieve current mailbox Global Count for given message database (server).

        :param server: Server object name
        """
        return self.get_message_attribute(server, "ChangeNumber")


    def set_message_ChangeNumber(self, server, ChangeNumber):
        """Update current mailbox ChangeNumber for given message database (server).

        :param server: Server object name
        :param index: Mailbox new ChangeNumber value
        """
        server_dn = self.lookup_server(server, []).dn

        newChangeNumber = """
dn: %s
changetype: modify
replace: ChangeNumber
ChangeNumber: %d
""" % (server_dn, ChangeNumber)

        self.ldb.transaction_start()
        try:
            self.ldb.modify_ldif(newChangeNumber)
        finally:
            self.ldb.transaction_commit()

def reverse_int64counter(GlobalCount):
    rev_counter = 0
    for x in xrange(6):
        sh = x * 8
        unsh = (7-x) * 8
        rev_counter = rev_counter | (((GlobalCount >> sh) & 0xff) << unsh)

    return rev_counter

def gen_mailbox_folder_fid(GlobalCount, ReplicaID):
    """Generates a Folder ID from index.

    :param GlobalCount: Message database global counter
    :param ReplicaID: Message database replica identifier
    """

    return "%d" % (ReplicaID | reverse_int64counter(GlobalCount))

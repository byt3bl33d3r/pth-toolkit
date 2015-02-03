# fdunix.py -- OpenChange RPC-over-HTTP implementation
#
# Copyright (C) 2012  Wolfgang Sourdeau <wsourdeau@inverse.ca>
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

"""A module that provides functions to send and receive a filedescriptor over
a unix socket.

"""

from ctypes import *
from struct import pack_into, unpack_from
from os import fdopen, O_RDONLY, O_WRONLY, O_RDWR
from fcntl import fcntl, F_GETFL
from socket import fromfd, _socketobject, AF_INET, SOCK_STREAM

# definitions

SOL_SOCKET = 1
SCM_RIGHTS = 1

c_socklen_t = c_uint32


class CMSGHdr(Structure):
    _fields_ = [("cmsg_len", c_size_t),
                ("cmsg_level", c_int),
                ("cmsg_type", c_int)]

FDBuffer = (c_byte * sizeof(c_int))

class CMSG(Structure):
    # The cmsg_data must be an array of chars rather than a pointer of chars,
    # therefore we must diverge from the C struct due to the fact that ctypes
    # only accept definitions of fixed-length arrays.
    _fields_ = [("cmsg_hdr", CMSGHdr),
                ("cmsg_data", FDBuffer)]


class IOVec(Structure):
    _fields_ = [("iov_base", c_char_p),
                ("iov_len", c_size_t)]


class MSGHdr(Structure):
    _fields_ = [("msg_name", c_char_p),
                ("msg_namelen", c_socklen_t),
                ("msg_iov", POINTER(IOVec)),
                ("msg_iovlen", c_size_t),
                ("msg_control", POINTER(CMSG)),
                ("msg_controllen", c_size_t),
                ("msg_flags", c_int)]


def CMSG_ALIGN(x):
    return ((x + sizeof(c_size_t) - 1) & ~(sizeof(c_size_t) - 1))

def CMSG_SPACE(x):
    return CMSG_ALIGN(x) + CMSG_ALIGN(sizeof(CMSGHdr))

def CMSG_LEN(x):
    return CMSG_ALIGN(sizeof(CMSGHdr)) + x


# symbols setup
libc = CDLL("libc.so.6", use_errno=True)
if libc is None:
    raise RuntimeError("could not open C library")
sendmsg = libc.sendmsg
sendmsg.argtypes = (c_int, POINTER(MSGHdr), c_int)
recvmsg = libc.recvmsg
recvmsg.argtypes = (c_int, POINTER(MSGHdr), c_int)
strerror = libc.strerror
strerror.restype = c_char_p
strerror.argtypes = (c_int,)
errno = libc.errno


def send_socket(socket, sobject):
    """This function sends a filedescriptor.

    socket: must be a unix socket
    fd: must be a socket of a socket object

    Returns True on success, False otherwise

    """

    if not isinstance(sobject, _socketobject):
        raise TypeError("'sobject' must either be a file or a socket object")

    iov = IOVec()
    iov.iov_base = "A"
    iov.iov_len = 1

    cmsg = CMSG()
    cmsg.cmsg_hdr.cmsg_len = CMSG_LEN(sizeof(c_int))
    cmsg.cmsg_hdr.cmsg_level = SOL_SOCKET
    cmsg.cmsg_hdr.cmsg_type = SCM_RIGHTS
    pack_into("i", cmsg.cmsg_data, 0, sobject.fileno())

    msgh = MSGHdr()
    msgh.msg_name = None
    msgh.msg_namelen = 0
    msgh.msg_iov = (iov,)
    msgh.msg_iovlen = 1
    msgh.msg_control = pointer(cmsg)
    msgh.msg_controllen = CMSG_SPACE(sizeof(c_int))
    msgh.msg_flags = 0

    rc = sendmsg(socket.fileno(), pointer(msgh), 0)
    if rc == -1:
        errno = get_errno()
        raise OSError(errno, strerror(errno))

    return True


def receive_socket(socket):
    """This function receives a socket object via a UNIX socket.

    socket: must be a unix socket

    Returns a socket object or None if the operation fails.

    """

    iov = IOVec()
    iov.iov_base = "A"
    iov.iov_len = 1

    cmsg = CMSG()
    cmsg.cmsg_hdr.cmsg_len = CMSG_LEN(sizeof(c_int))

    msgh = MSGHdr()
    msgh.msg_name = None
    msgh.msg_namelen = 0
    msgh.msg_iov = (iov,)
    msgh.msg_iovlen = 1
    msgh.msg_control = pointer(cmsg)
    msgh.msg_controllen = CMSG_SPACE(sizeof(c_int))
    msgh.msg_flags = 0

    # rc = recvmsg(socket.fileno(), pointer(msgh), 0)
    rc = recvmsg(socket.fileno(), pointer(msgh), 0)
    if rc == -1:
        errno = get_errno()
        raise OSError(errno, strerror(errno))

    (value,) = unpack_from("i", cmsg.cmsg_data)

    # the 'mode' parameter should probably passed as part of the message
    (fd,) = unpack_from("i", cmsg.cmsg_data)
    newfile = fromfd(fd, AF_INET, SOCK_STREAM)

    return newfile

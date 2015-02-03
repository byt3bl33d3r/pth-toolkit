# NTLMAuthHandler.py -- OpenChange RPC-over-HTTP implementation
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

"""This module provides the NTLMAuthHandler class, a WSGI middleware that
enables NTLM authentication via RPC to Samba.

It works by proxying the NTLMSSP payload between the client and the samba
server. Accessorily it could be used against an MS Exchange service, but this
is untested.

"""

# TODO: security checks!

from fcntl import flock, LOCK_EX, LOCK_UN
import httplib
from os import _exit, getpid, getuid, fork, setsid, stat, umask, unlink, \
    waitpid, close as close_fd
from os.path import join, exists
from select import poll, POLLIN, POLLHUP
from socket import socket, SHUT_RDWR, AF_INET, AF_UNIX, \
    SOCK_STREAM, MSG_WAITALL, error as socket_error
from struct import pack, unpack, unpack_from, error as struct_error
import sys
from time import sleep, time
from uuid import uuid4

from openchange.utils.packets import RPCAuth3OutPacket, RPCBindACKPacket, \
    RPCBindOutPacket, RPCFaultPacket, RPCPacket, RPCPingOutPacket


# TODO: we should make use of port 135 to discover which port our service uses
SAMBA_PORT = 1024

# those are left unconfigurable, at least for now
CLIENT_TIMEOUT = 60 * 5 # 5 minutes since last use
ACTIVITY_TIMEOUT = CLIENT_TIMEOUT # 5 minutes since any socket has been used


## client-daemon protocol:
# * server knows client?
# client -> server "k" + sizeof(cookie) + cookie
# server->client = 0 or 1 (binary)
#
# * ntlm transaction
# client -> server "t" + sizeof(cookie) + cookie + sizeof(ntlm-payload) +
#      ntlm-payload
# server -> client = 0 or 1 (binary) + sizeof(ntlm-payload) + ntlm-payload


def _safe_close(socket_obj):
    try:
        socket_obj.shutdown(SHUT_RDWR)
        socket_obj.close()
    except:
        pass


class _NTLMDaemon(object):
    def __init__(self, samba_host, socket_filename, owner_pair):
        self.socket_filename = socket_filename
        self.owner_pair = owner_pair
        self.samba_host = samba_host
        self.client_data = {}

    def run(self):
        if exists(self.socket_filename):
            unlink(self.socket_filename)
        child_pid = fork()
        if child_pid == 0:
            self._daemonize()
            _exit(0)
        elif child_pid > 0:
            # we wait for the child to exit before going on
            waitpid(child_pid, 0)

            # we are the child
            # print >> sys.stderr, "waiting for ntlm daemon to create socket (%d)" % getpid()
            while not exists(self.socket_filename):
                pass
            # print >> sys.stderr, "socket of ntlm daemon now exists (%d)" % getpid()
        else:
            raise Exception("failure to fork NTLM daemon")

    def _daemonize(self):
        # this code is inspire by the recipe described here:
        # http://code.activestate.com/recipes/278731-creating-a-daemon-the-python-way/
        setsid()

        import resource
        MAXFD = 1024
            # we close all open file descriptors != sys.stderr.fileno()
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if (maxfd == resource.RLIM_INFINITY):
            maxfd = MAXFD
  
        if hasattr(sys.stderr, "fileno"):
            stderr_fileno = sys.stderr.fileno()
        else:
            # mod_wsgi replace sys.stderr with a fake file without a "fileno"
            # method
            stderr_fileno = -1
        # close all fd > 4
        for fd in xrange(3, maxfd):
            if fd != stderr_fileno:
                try:
                    close_fd(fd)
                except OSError:
                    pass

        # free up some memory
        global httplib

        del httplib
        del resource

        # print >> sys.stderr, "cleanup done"

        child_pid = fork()
        if child_pid > 0:
            _exit(0)

        print >> sys.stderr, ("NTLMAuthHandler daemon spawned with pid %d"
                              % getpid())
        
        # forked processes inherits lock created by flock, so we need to
        # unlock the file here
        # flock(lockf.fileno(), LOCK_UN)
        # lockf.close()

        # we are the daemon
        self._run_as_daemon()

    def _run_as_daemon(self):
        client_sockets = {}
        last_cleanup = time()
        last_activity = time()

        # ensure only the current user can connect to our socket
        umask(0077)

        # create socket and listen
        server_socket = socket(AF_UNIX, SOCK_STREAM)
        server_socket.bind(self.socket_filename)
        server_socket.listen(10)

        # The socket must have the same owner as its parent directory, this is
        # achieved in two ways: either we are running as root and no fence
        # shall stop us, or we cannot run as anyother used because the socket
        # creation will already have failed in the target directory.
        current_uid = getuid()
        if current_uid == 0:
            chown(self.socket_filename,
                  self.owner_pair[0], self.owner_pair[1])
        elif current_uid != self.owner_pair[0]:
            unlink(self.socket_filename)
            raise IOError("The NTLMAuthHandler daemon must either be started"
                          " as root or as the owner of the directory"
                          " specified for 'NTLMAUTHHANDLER_WORKDIR' (current"
                          " uid=%d)."
                          % current_uid)

        server_fd = server_socket.fileno()

        fd_pool = poll()
        fd_pool.register(server_fd, POLLIN)

        shutdown = False
        # loop and handle requests
        while not shutdown:
            chunks = fd_pool.poll(2000.0)
            now = time()
            if len(chunks) == 0:
                # nothing happened in the last 2 secs

                if last_activity + 30.0 < now:
                    shutdown = True
                elif last_cleanup + 60.0 < now:
                    # print >> sys.stderr, ("cleaning up old client ids (%d)"
                    #                       % getpid())
                    self._cleanup_client_data(now - CLIENT_TIMEOUT)
                    last_cleanup = now
            else:
                last_activity = now
                for data in chunks:
                    filedesc, event_no = data
                    if filedesc == server_fd:
                        # we are receiving a new connection
                        new_socket = server_socket.accept()[0]
                        new_socket_fd = new_socket.fileno()
                        client_sockets[new_socket_fd] = new_socket
                        fd_pool.register(new_socket_fd, POLLIN)
                        # print >> sys.stderr, ("registered new client socket"
                        # " %d (%d)"
                        # % (new_socket_fd, getpid()))
                    elif filedesc in client_sockets:
                        # print >> sys.stderr, ("handling event %d from client"
                        # " socket %d" % (event_no, filedesc))
                        client_socket = client_sockets[filedesc]
                        if (event_no & POLLHUP > 0
                            or not self._process_client_request(client_socket,
                                                                now)):
                            # print >> sys.stderr, ("removed client socket from"
                            # " pool (%d)" % getpid())
                            _safe_close(client_socket)
                            fd_pool.unregister(filedesc)
                            del client_sockets[filedesc]
                    else:
                        raise Exception("%d is an unknown file descriptor"
                                        " (%d)" % (filedesc, getpid()))

        # close server socket and remove fs entry
        _safe_close(server_socket)
        # unlink(self.socket_filename)
        # close client sockets
        [_safe_close(client_socket)
         for client_socket in client_sockets.itervalues()]
        
        print >> sys.stderr, ("NTLMAuthHandler daemon shutdown (%d)"
                              % getpid())

    def _cleanup_client_data(self, time_limit):
        def _cleanup_record(client_id):
            record = self.client_data[client_id]
            if "server" in record:
                # print >> sys.stderr, "closing server socket"
                server = record["server"]
                _safe_close(server)
            del self.client_data[client_id]

        # we make use of "keys()" here because we cannot use a dictionary as
        # iterator while adding or removing records
        for client_id in self.client_data.keys():
            if self.client_data[client_id]["last_used"] < time_limit:
                _cleanup_record(client_id)

    def _process_client_request(self, client_socket, now):
        success = True

        data = client_socket.recv(5, MSG_WAITALL)
        tag = data[0]
        len_client_id = unpack_from("<l", data, 1)[0]
        # print >> sys.stderr, "len_client_id: %d" % len_client_id
        # print >> sys.stderr, "type(len_client_id): %s" % type(len_client_id)
        if len_client_id > 0:
            client_id = client_socket.recv(len_client_id, MSG_WAITALL)
        else:
            client_id = ""

        if tag == "k":
            if client_id in self.client_data:
                self.client_data[client_id]["last_used"] = now
                response = 1
            else:
                response = 0
            client_socket.sendall(pack("<B", response))
        elif tag == "t":
            data = client_socket.recv(4, MSG_WAITALL)
            len_ntlm_payload = unpack_from("<l", data)[0]
            ntlm_payload = client_socket.recv(len_ntlm_payload,
                                              MSG_WAITALL)
            if client_id in self.client_data:
                self.client_data[client_id]["last_used"] = now
                response = self._handle_auth(client_id, ntlm_payload)
                ntlm_payload = ""
            else:
                (response, ntlm_payload) \
                    = self._handle_negotiate(client_id, ntlm_payload)

            if response == 0:
                # directly cleanup the client record, in order to reduce the
                # amount of sockets in use
                if "server" in self.client_data[client_id]:
                    server = self.client_data[client_id]["server"]
                    _safe_close(server)
                del self.client_data[client_id]

            len_ntlm_payload = len(ntlm_payload)
            client_socket.sendall(pack("<Bl", response, len_ntlm_payload)
                                  + ntlm_payload)
        else:
            # we force the closing of the client socket for any other tag as
            # we don't know what to answer
            success = False

        return success

    def _handle_auth(self, client_id, ntlm_payload):
        # print >> sys.stderr, "* client auth stage1"

        server = self.client_data[client_id]["server"]
        # print >> sys.stderr, "host: %s" % str(server.getsockname())

        # print >> sys.stderr, "building auth_3 and ping packets"
        packet = RPCAuth3OutPacket()
        packet.ntlm_payload = ntlm_payload
        server.sendall(packet.make())

        # FIXME, this is a hack:
        # A ping at this stage will trigger a connection close from Samba and
        # an error from Exchange. Since a successful authentication does not
        # trigger a response from the server, this provides a simple way to
        # ensure that it passed, without actually performing an RPC operation
        # on the "mgmt" interface. The choice of "mgmt" was due to the fact
        # that we want to keep this authenticator middleware to be reusable
        # for other Samba services while "mgmt" seemes to be the only
        # available interface from Samba outside of the ones provided by
        # OpenChange.
        packet = RPCPingOutPacket()
        packet.call_id = 2
        server.sendall(packet.make())
        # print >> sys.stderr, "sent auth3 and ping packets, receiving response"

        try:
            packet = RPCPacket.from_file(server)
            if isinstance(packet, RPCFaultPacket):
                if packet.header["call_id"] == 2:
                    # the Fault packet related to our Ping operation
                    response = 1
                else:
                    response = 0
            else:
                raise ValueError("unexpected packet")
        except socket_error:
            # Samba closed the connection
            response = 1
        except struct_error:
            # Samba closed the connection
            response = 1

        if response == 1:
            # authentication completed
            self.client_data[client_id]["status"] = "ok"
            del self.client_data[client_id]["server"]
        else:
            # we start over with the whole process
            del self.client_data[client_id]

        _safe_close(server)

        # print >> sys.stderr, "* done with client auth stage1"

        return response

    def _handle_negotiate(self, client_id, ntlm_payload):
        # print >> sys.stderr, "* client auth stage0"

        # print >> sys.stderr, "connecting to host"
        server = None

        connected = False
        attempt = 0
        while not connected:
            try:
                attempt = attempt + 1
                # TODO: we should query port 135 for the right service
                server = socket(AF_INET, SOCK_STREAM)
                server.connect((self.samba_host, SAMBA_PORT))
                connected = True
            except:
                print >> sys.stderr, ("NTLMAuthHandler: caught exception when"
                                      " connecting to samba host: attempt %d"
                                      % attempt)
                sleep(1)

        # print >> sys.stderr, "host: %s" % str(server.getsockname())

        # print >> sys.stderr, "building bind packet"
        packet = RPCBindOutPacket()
        packet.ntlm_payload = ntlm_payload
        
        # print >> sys.stderr, "sending bind packet"
        server.sendall(packet.make())

        # print >> sys.stderr, "sent bind packet, receiving response"

        packet = RPCPacket.from_file(server)
        # print >> sys.stderr, "response parsed: %s" % packet.pretty_dump()

        if isinstance(packet, RPCBindACKPacket):
            # print >> sys.stderr, "ACK received"
            self.client_data[client_id] = {"status": "challenged",
                                           "last_used": time(),
                                           "server": server}
            response = 1
            ntlm_payload = packet.ntlm_payload
        else:
            response = 0
            ntlm_payload = ""

        # print >> sys.stderr, "* done with client auth stage0"

        return (response, ntlm_payload)


class _NTLMAuthClient(object):
    def __init__(self, work_dir, samba_host):
        self.work_dir = work_dir
        self.samba_host = samba_host
        self.connection = None

    def server_knows_client(self, client_id):
        # print >> sys.stderr, "server knows client? (%d)" % getpid()
        payload = "k%s%s" % (pack("<l", len(client_id)), client_id)
        self._send_to_server(payload)
        payload = self._recv_from_server(1)
        if len(payload) > 0:
            code = unpack_from("<B", payload)[0]
            # print >> sys.stderr, ("server knows client: %d (%d)"
            # % (code, getpid()))
        else:
            # print >> sys.stderr, ("received empty response (%d)" % getpid())
            code = 0

        return code != 0

    def ntlm_transaction(self, client_id="", ntlm_payload=""):
        # print >> sys.stderr, "ntlm_transaction (%d)" % getpid()

        payload = ("t%s%s%s%s"
                   % (pack("<l", len(client_id)), client_id,
                      pack("<l", len(ntlm_payload)), ntlm_payload))
        self._send_to_server(payload)
        payload = self._recv_from_server(5)
        if len(payload) > 0:
            (code, len_ntlm_payload) = unpack_from("<Bl", payload)
            if len_ntlm_payload > 0:
                ntlm_payload = self._recv_from_server(len_ntlm_payload)
                if len(ntlm_payload) != len_ntlm_payload:
                    code = 0
            else:
                ntlm_payload = ""
        else:
            # print >> sys.stderr, ("received empty response (%d)" % getpid())
            code = 0
            ntlm_payload = ""

        # print >> sys.stderr, "ntlm_transaction result: %d (%d)" % (code, getpid())

        return (code != 0, ntlm_payload)

    def _send_to_server(self, payload):
        if self.connection is None:
            self._make_connection()

        # sends a series of bytes to the server and make sure it receives them
        # by restarting it if needed

        # print >>sys.stderr, "sending data (%d)" % getpid()
        sent = False
        while not sent:
            try:
                self.connection.sendall(payload)
                sent = True
            except IOError:
                # print >> sys.stderr, ("(send) reconnecting to server (%d)..."
                #                      % getpid())
                sleep(1)
                self._make_connection()
        # print >>sys.stderr, "sent data (%d)" % getpid()

    def _recv_from_server(self, nbr_bytes):
        # print >>sys.stderr, "receiving data (%d)" % getpid()

        # receives a payload from the server and returns an empty string if
        # something went wrong, just as if the actual request failed
        try:
            payload = self.connection.recv(nbr_bytes, MSG_WAITALL)
            if payload is None:
                payload = ""
        except IOError:
            # if the server has died, we must return an error anyway
            payload = ""

        # print >>sys.stderr, "received data (%d)" % getpid()

        return payload

    def _make_connection(self):
        # we create a lock in order to make sure that we would be the only
        # process or thread starting a daemon if needed

        lock_filename = join(self.work_dir, "ntlm-%s.lock" % self.samba_host)
        if not exists(lock_filename):
            lockf = open(lock_filename, "w+")
            lockf.close()
        lockf = open(lock_filename, "r")
        # print >> sys.stderr, "acquiring lock (%d)" % getpid()
        lock_fd = lockf.fileno()
        flock(lock_fd, LOCK_EX)
        # print >> sys.stderr, "acquired lock (%d)" % getpid()
        self.connection = self._connect_to_daemon(self.work_dir,
                                                  self.samba_host)
        flock(lock_fd, LOCK_UN)
        lockf.close()

    @staticmethod
    def _connect_to_daemon(work_dir, samba_host):
        socket_filename = join(work_dir, "ntlm-%s" % samba_host)
        stat_s = stat(work_dir)
        connection = socket(AF_UNIX, SOCK_STREAM)
        try:
            connection.connect(socket_filename)
        except socket_error:
            # the socket does not exist or is invalid, therefore we need to
            # respawn the daemon
            daemon = _NTLMDaemon(samba_host, socket_filename, (stat_s.st_uid, stat_s.st_gid))
            daemon.run()
            connection.connect(socket_filename)

        return connection

    def close(self):
        if self.connection is not None:
            _safe_close(self.connection)
            self.connection = None


class NTLMAuthHandler(object):
    """
    HTTP/1.0 ``NTLM`` authentication middleware

    Parameters: application -- the application object that is called only upon
    successful authentication.

    """

    def __init__(self, application):
        self.application = application

    def __call__(self, env, start_response):
        (work_dir, samba_host, cookie_name, has_auth) \
            = self._read_environment(env)

        connection = _NTLMAuthClient(work_dir, samba_host)

        # TODO: validate authorization payload

        cookies = self._get_cookies(env)
        if cookie_name in cookies:
            client_id = cookies[cookie_name]
            server_knows_client = connection.server_knows_client(client_id)
            # print >> sys.stderr, \
                # "server knows client (pid: %d): %s" % (getpid(),
            # str(server_knows_client))
        else:
            server_knows_client = False
            # print >> sys.stderr, "client did not pass auth cookie"

        if has_auth:
            auth = env["HTTP_AUTHORIZATION"]
            ntlm_payload = auth[5:].decode("base64")
            if server_knows_client:
                # stage 1, where the client has already received the challenge
                # from the server and is now sending an AUTH message
                # server_knows_client implies that client_id is valid
                (success, payload) \
                    = connection.ntlm_transaction(client_id, ntlm_payload)
                if success:
                    connection.close()
                    response = self.application(env, start_response)
                else:
                    response = self._in_progress_response(start_response)
            else:
                # stage 0, where the cookie has not been set yet and where we
                # know the NTLM payload is a NEGOTIATE message
                client_id = str(uuid4())
                (success, ntlm_payload) \
                    = connection.ntlm_transaction(client_id, ntlm_payload)
                if success:
                    response = self._in_progress_response(start_response,
                                                          ntlm_payload,
                                                          client_id,
                                                          cookie_name)
                else:
                    response = self._in_progress_response(start_response)
        else:
            if server_knows_client:
                # authenticated, where no NTLM payload is provided anymore
                connection.close()
                response = self.application(env, start_response)
            else:
                # this client has never been seen
                # note: this is the only case where the "connection" object is
                # uselessly instantiated
                response = self._in_progress_response(start_response, None)

        connection.close()

        return response

    @staticmethod
    def _read_environment(env):
        if "NTLMAUTHHANDLER_WORKDIR" in env:
            work_dir = env["NTLMAUTHHANDLER_WORKDIR"]
            if not exists(work_dir):
                raise ValueError("the directory specified for"
                                 " 'NTLMAUTHHANDLER_WORKDIR' does not exist:"
                                 " '%s'" % work_dir)
        else:
            raise ValueError("'NTLMAUTHHANDLER_WORKDIR' is not set in"
                             " the environment")

        if "SAMBA_HOST" in env:
            samba_host = env["SAMBA_HOST"]
        else:
            print >> sys.stderr, \
                "'SAMBA_HOST' not configured, 'localhost' will be used"
            samba_host = "localhost"

        if "NTLMAUTHHANDLER_COOKIENAME" in env:
            cookie_name = env["NTLMAUTHHANDLER_COOKIENAME"]
        else:
            cookie_name = "oc-ntlm-auth"

        has_auth = "HTTP_AUTHORIZATION" in env

        return (work_dir, samba_host, cookie_name, has_auth)

    @staticmethod
    def _get_cookies(env):
        cookies = {}
        if "HTTP_COOKIE" in env:
            cookie_str = env["HTTP_COOKIE"]
            for pair in cookie_str.split(";"):
                (key, value) = pair.strip().split("=")
                cookies[key] = value

        return cookies

    @staticmethod
    def _in_progress_response(start_response, ntlm_data=None,
                              client_id=None, cookie_name=None):
        status = "401 %s" % httplib.responses[401]
        content = "More data needed..."
        headers = [("Content-Type", "text/plain"),
                   ("Content-Length", "%d" % len(content))]
        if ntlm_data is None:
            www_auth_value = "NTLM"
        else:
            enc_ntlm_data = ntlm_data.encode("base64")
            www_auth_value = ("NTLM %s"
                              % enc_ntlm_data.strip().replace("\n", ""))

        if client_id is not None:
            # MUST occur when ntlm_data is None, can still occur otherwise
            headers.append(("Set-Cookie", "%s=%s" % (cookie_name, client_id)))

        headers.append(("WWW-Authenticate", www_auth_value))
        start_response(status, headers)

        return [content]


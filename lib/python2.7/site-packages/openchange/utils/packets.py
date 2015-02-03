# packets.py -- OpenChange RPC-over-HTTP implementation
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

import logging
from socket import _socketobject, MSG_WAITALL
from struct import pack, unpack_from
from uuid import UUID


PFC_FIRST_FRAG = 1
PFC_LAST_FRAG = 2
PFC_PENDING_CANCEL = 4
PFC_SUPPORT_HEADER_SIGN = 4
PFC_RESERVED_1 = 8
PFC_CONC_MPX = 16
PFC_DID_NOT_EXECUTE = 32
PFC_MAYBE = 64
PFC_OBJECT_UUID = 128
PFC_FLAG_LABELS = ("PFC_FIRST_FRAG",
                   "PFC_LAST_FRAG", 
                   "PFC_(PENDING_CANCEL|SUPPORT_HEADER_SIGN)", 
                   "PFC_RESERVED_1", 
                   "PFC_CONC_MPX", 
                   "PFC_DID_NOT_EXECUTE",
                   "PFC_MAYBE", 
                   "PFC_OBJECT_UUID")


# taken from dcerpc.idl
DCERPC_PKT_REQUEST = 0
DCERPC_PKT_PING = 1
DCERPC_PKT_RESPONSE = 2
DCERPC_PKT_FAULT = 3
DCERPC_PKT_WORKING = 4
DCERPC_PKT_NOCALL = 5
DCERPC_PKT_REJECT = 6
DCERPC_PKT_ACK = 7
DCERPC_PKT_CL_CANCEL = 8
DCERPC_PKT_FACK = 9
DCERPC_PKT_CANCEL_ACK = 10
DCERPC_PKT_BIND = 11
DCERPC_PKT_BIND_ACK = 12
DCERPC_PKT_BIND_NAK = 13
DCERPC_PKT_ALTER = 14
DCERPC_PKT_ALTER_RESP = 15
DCERPC_PKT_AUTH_3 = 16
DCERPC_PKT_SHUTDOWN = 17
DCERPC_PKT_CO_CANCEL = 18
DCERPC_PKT_ORPHANED = 19
DCERPC_PKT_RTS = 20
DCERPC_PKG_LABELS = ("DCERPC_PKT_REQUEST",
                     "DCERPC_PKT_PING",
                     "DCERPC_PKT_RESPONSE",
                     "DCERPC_PKT_FAULT",
                     "DCERPC_PKT_WORKING",
                     "DCERPC_PKT_NOCALL",
                     "DCERPC_PKT_REJECT",
                     "DCERPC_PKT_ACK",
                     "DCERPC_PKT_CL_CANCEL",
                     "DCERPC_PKT_FACK",
                     "DCERPC_PKT_CANCEL_ACK",
                     "DCERPC_PKT_BIND",
                     "DCERPC_PKT_BIND_ACK",
                     "DCERPC_PKT_BIND_NAK",
                     "DCERPC_PKT_ALTERA",
                     "DCERPC_PKT_ALTER_RESP",
                     "DCERPC_PKT_AUTH_3",
                     "DCERPC_PKT_SHUTDOWN",
                     "DCERPC_PKT_CO_CANCEL",
                     "DCERPC_PKT_ORPHANED",
                     "DCERPC_PKT_RTS")

RTS_FLAG_NONE = 0
RTS_FLAG_PING = 1
RTS_FLAG_OTHER_CMD = 2
RTS_FLAG_RECYCLE_CHANNEL = 4
RTS_FLAG_IN_CHANNEL = 8
RTS_FLAG_OUT_CHANNEL = 0x10
RTS_FLAG_EOF = 0x20
RTS_FLAG_ECHO = 0x40
RTS_FLAG_LABELS = ("RTS_FLAG_PING",
                   "RTS_FLAG_OTHER_CMD",
                   "RTS_FLAG_RECYCLE_CHANNEL",
                   "RTS_FLAG_IN_CHANNEL",
                   "RTS_FLAG_OUT_CHANNEL",
                   "RTS_FLAG_EOF",
                   "RTS_FLAG_ECHO")

RTS_CMD_RECEIVE_WINDOW_SIZE = 0
RTS_CMD_FLOW_CONTROL_ACK = 1
RTS_CMD_CONNECTION_TIMEOUT = 2
RTS_CMD_COOKIE = 3
RTS_CMD_CHANNEL_LIFETIME = 4
RTS_CMD_CLIENT_KEEPALIVE = 5
RTS_CMD_VERSION = 6
RTS_CMD_EMPTY = 7
RTS_CMD_PADDING = 8
RTS_CMD_NEGATIVE_ANCE = 9
RTS_CMD_ANCE = 10
RTS_CMD_CLIENT_ADDRESS = 11
RTS_CMD_ASSOCIATION_GROUP_ID = 12
RTS_CMD_DESTINATION = 13
RTS_CMD_PING_TRAFFIC_SENT_NOTIFY = 14

RTS_CMD_SIZES = (8, 28, 8, 20, 8, 8, 8, 4, 8, 4, 4, 8, 20, 8, 8)
RTS_CMD_DATA_LABELS = ("ReceiveWindowSize",
                       "FlowControlAck",
                       "ConnectionTimeout",
                       "Cookie",
                       "ChannelLifetime",
                       "ClientKeepalive",
                       "Version",
                       "Empty",
                       "Padding",
                       "NegativeANCE",
                       "ANCE",
                       "ClientAddress",
                       "AssociationGroupId",
                       "Destination",
                       "PingTrafficSentNotify")

RPC_C_AUTHN_NONE = 0x0
RPC_C_AUTHN_GSS_NEGOTIATE = 0x9 # SPNEGO
RPC_C_AUTHN_WINNT = 0xa # NTLM
RPC_C_AUTHN_GSS_SCHANNEL = 0xe # TLS
RPC_C_AUTHN_GSS_KERBEROS = 0x10 # Kerberos
RPC_C_AUTHN_NETLOGON = 0x44 # Netlogon
RPC_C_AUTHN_DEFAULT = 0xff # (NTLM)

RPC_C_AUTHN_LEVEL_DEFAULT = 0
RPC_C_AUTHN_LEVEL_NONE = 1
RPC_C_AUTHN_LEVEL_CONNECT = 2
RPC_C_AUTHN_LEVEL_CALL = 3
RPC_C_AUTHN_LEVEL_PKT = 4
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6


class RTSParsingException(IOError):
    """This exception occurs when a serious issue occurred while parsing an
    RTS packet.

    """

    pass


class RPCPacket(object):
    def __init__(self, data, logger=None):
        self.logger = logger

        # BLOB level
        self.data = data
        self.size = 0

        # parsed offset from the start of the "data" blob
        self.offset = 0

        # header is common to all PDU
        self.header = None

    @staticmethod
    def from_file(input_file, logger=None):
        """This static method acts as a constructor and returns an input
        packet with the proper class, based on the packet headers.
        The "input_file" parameter must either be a file or a sockect object.

        """

        if isinstance(input_file, _socketobject):
            def read_file(count):
                return input_file.recv(count, MSG_WAITALL)
        elif hasattr(file, "read") and callable(file.read):
            def read_file(count):
                return input_file.read(count)
        else:
            raise ValueError("'input_file' must either be a socket object or"
                             " provide a 'read' method")

        fields = ("rpc_vers", "rpc_vers_minor", "ptype", "pfc_flags", "drep",
                  "frag_length", "auth_length", "call_id")

        header_data = read_file(16)
        # len_header_data = len(header_data)
        # if len_header_data < 16:
        #     raise RTSParsingException("read only %d header bytes from input"
        #                               % len_header_data)

        # TODO: value validation
        values = unpack_from("<bbbblhhl", header_data)
        if values[2] == DCERPC_PKT_FAULT:
            packet_class = RPCFaultPacket
        elif values[2] == DCERPC_PKT_BIND_ACK:
            packet_class = RPCBindACKPacket
        elif values[2] == DCERPC_PKT_BIND_NAK:
            packet_class = RPCBindNAKPacket
        elif values[2] == DCERPC_PKT_RTS:
            packet_class = RPCRTSPacket
        else:
            packet_class = RPCPacket
        body_data = read_file(values[5] - 16)
        # len_body_data = len(body_data)
        # if len_body_data < (values[5] - 16):
        #     raise RTSParsingException("read only %d body bytes from input"
        #                               % len_body_data)

        packet = packet_class(header_data + body_data, logger)
        packet.header = dict(zip(fields, values))
        packet.offset = 16
        packet.size = values[5]
        packet.parse()

        return packet

    def parse(self):
        pass

    def pretty_dump(self):
        (fields, values) = self.make_dump_output()

        output = ["%s: %s" % (fields[pos], str(values[pos]))
                  for pos in xrange(len(fields))]

        return "; ".join(output)

    def make_dump_output(self):
        values = []
        
        ptype = self.header["ptype"]
        values.append(DCERPC_PKG_LABELS[ptype])

        flags = self.header["pfc_flags"]
        if flags == 0:
            values.append("None")
        else:
            flag_values = []
            for exp in xrange(7):
                flag = 1 << exp
                if flags & flag > 0:
                    flag_values.append(PFC_FLAG_LABELS[exp])
            values.append(", ".join(flag_values))

        fields = ["ptype", "pfc_flags", "drep", "frag_length",
                  "auth_length", "call_id"]
        for field in fields[2:]:
            values.append(self.header[field])

        return (fields, values)



# fault PDU (stub)
class RPCFaultPacket(RPCPacket):
    def __init__(self, data, logger=None):
        RPCPacket.__init__(self, data, logger)


# bind_ack PDU (incomplete)
class RPCBindACKPacket(RPCPacket):
    def __init__(self, data, logger=None):
        RPCPacket.__init__(self, data, logger)
        self.ntlm_payload = None
        
    def parse(self):
        auth_offset = self.header["frag_length"] - self.header["auth_length"]
        self.ntlm_payload = self.data[auth_offset:]


# bind_nak PDU (stub)
class RPCBindNAKPacket(RPCPacket):
    def __init__(self, data, logger=None):
        RPCPacket.__init__(self, data, logger)


# FIXME: command parameters are either int32 values or binary blobs, both when
# parsing and when producing
class RPCRTSPacket(RPCPacket):
    parsers = None

    def __init__(self, data, logger=None):
        RPCPacket.__init__(self, data, logger)

        # RTS commands
        self.commands = []

    def parse(self):
        fields = ("flags", "nbr_commands")
        values = unpack_from("<hh", self.data, self.offset)
        self.offset = self.offset + 4
        self.header.update(zip(fields, values))

        for counter in xrange(self.header["nbr_commands"]):
            self._parse_command()

        if (self.size != self.offset):
            raise RTSParsingException("sizes do not match: expected = %d,"
                                      " actual = %d"
                                      % (self.size, self.offset))

    def _parse_command(self):
        (command_type,) = unpack_from("<l", self.data, self.offset)
        if command_type < 0 or command_type > 15:
            raise RTSParsingException("command type unknown: %d"
                                      % command_type)
        self.offset = self.offset + 4

        command = {"type": command_type}
        command_size = RTS_CMD_SIZES[command_type]
        if command_size > 4:
            data_size = command_size - 4
            if command_type in self.parsers:
                parser = self.parsers[command_type]
                data_value = parser(self, data_size)
            elif data_size == 4:
                # commands with int32 values
                (data_value,) = unpack_from("<l", self.data, self.offset)
                self.offset = self.offset + 4
            else:
                raise RTSParsingException("command is badly handled: %d"
                                          % command_type)

            data_label = RTS_CMD_DATA_LABELS[command_type]
            command[data_label] = data_value

        self.commands.append(command)

    def _parse_command_flow_control_ack(self, data_size):
        data_blob = self.data[self.offset:self.offset+data_size]
        self.offset = self.offset + data_size
        # dumb method
        return data_blob
    
    def _parse_command_cookie(self, data_size):
        data_blob = self.data[self.offset:self.offset+data_size]
        self.offset = self.offset + data_size
        # dumb method
        return data_blob

    def _parse_command_padding_data(self, data_size):
        # the length of the padding bytes is specified in the
        # ConformanceCount field
        (count,) = unpack_from("<l", self.data, self.offset)
        self.offset = self.offset + 4

        data_blob = self.data[self.offset:self.offset+count]
        self.offset = self.offset + count

        return data_value

    def _parse_command_client_address(self, data_blob):
        (address_type,) = unpack_from("<l", self.data, self.offset)
        self.offset = self.offset + 4

        if address_type == 0: # ipv4
            address_size = 4
        elif address_type == 1: # ipv6
            address_size = 16
        else:
            raise RTSParsingException("unknown client address type: %d"
                                      % address_type)

        data_blob = self.data[self.offset:self.offset+address_size]

        # compute offset with padding, which is ignored
        self.offset = self.offset + address_size + 12

        return data_value

    def make_dump_output(self):
        (fields, values) = RPCPacket.make_dump_output(self)
        fields.extend(("flags", "nbr_commands"))

        flags = self.header["flags"]
        if flags == RTS_FLAG_NONE:
            values.append("RTS_FLAG_NONE")
        else:
            flags_value = []
            for exp in xrange(7):
                flag = 1 << exp
                if flags & flag > 0:
                    flags_value.append(RTS_FLAG_LABELS[exp])
            values.append(", ".join(flags_value))

        values.append(self.header["nbr_commands"])

        return (fields, values)


# Those are the parser method for commands with a size > 4. They are defined
# here since the "RPCRTSPacket" symbol is not accessible as long as the class
# definition is not over
RPCRTSPacket.parsers = {RTS_CMD_FLOW_CONTROL_ACK: RPCRTSPacket._parse_command_flow_control_ack,
                        RTS_CMD_COOKIE: RPCRTSPacket._parse_command_cookie,
                        RTS_CMD_ASSOCIATION_GROUP_ID: RPCRTSPacket._parse_command_cookie,
                        RTS_CMD_PADDING: RPCRTSPacket._parse_command_padding_data,
                        RTS_CMD_CLIENT_ADDRESS: RPCRTSPacket._parse_command_client_address}



### OUT packets

# bind PDU (strict minimum required for NTLMSSP auth)
class RPCBindOutPacket(object):
    def __init__(self, logger=None):
        self.logger = logger

        self.size = 0
        self.data = None

        self.call_id = 1
        self.ntlm_payload = None

    def make(self):
        if self.data is None:
            self._make_packet_data()

        return self.data

    def _make_packet_data(self):
        if self.ntlm_payload is None:
            raise ValueError("'ntlm_payload' attribute must not be None")

        ntlm_payload_size = len(self.ntlm_payload)
        align_modulo = ntlm_payload_size % 4
        if align_modulo > 0:
            padding = (4 - align_modulo) * "\0"
        else:
            padding = ""
        len_padding = len(padding)


        # rfr: 1544f5e0-613c-11d1-93df-00c04fd7bd09, v1
        # mgmt: afa8bd80-7d8a-11c9-bef4-08002b102989, v1
        svc_guid = UUID('{afa8bd80-7d8a-11c9-bef4-08002b102989}')
        iface_version_major = 1
        iface_version_minor = 0

        p_content_elem = ("\x01\x00\x00\x00\x00\x00\x01\x00"
                          "%s%s"
                          "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00"
                          "\x2b\x10\x48\x60\x02\x00\x00\x00"
                          % (svc_guid.bytes_le,
                             pack("<hh",
                                  iface_version_major,
                                  iface_version_minor)))
        # p_content_elem = ("\x00\x00\x00\x00")
        len_p_content_elem = len(p_content_elem)

        header_data = pack("<bbbbbbbbhhl hhl %ds bbbbl" % len_p_content_elem,

                           ## common headers:
                           5, 0, # rpc_vers, rpc_vers_minor
                           DCERPC_PKT_BIND, # ptype
                           # pfc_flags:
                           PFC_FIRST_FRAG
                           | PFC_LAST_FRAG
                           | PFC_SUPPORT_HEADER_SIGN,
                           # | PFC_CONC_MPX,
                           # drep: RPC spec chap14.htm (Data Representation Format Label)
                           (1 << 4) | 0, 0, 0, 0,
                           (32 + ntlm_payload_size + len_padding + len_p_content_elem), # frag_length
                           ntlm_payload_size + len_padding, # auth_length
                           self.call_id, # call_id

                           ## bind specific:
                           4088, 4088, # max_xmit/recv_frag
                           0, # assoc_group_id

                           # p_context_elem
                           p_content_elem,

                           # p_context_elem (flattened to int32):
                           # 0,

                           # sec_trailer:
                           RPC_C_AUTHN_WINNT, # auth_verifier.auth_type
                           # auth_verifier.auth_level:
                           RPC_C_AUTHN_LEVEL_CONNECT,
                           len_padding, # auth_verifier.auth_pad_length
                           0, # auth_verifier.auth_reserved
                           1 # auth_verifier.auth_context_id
                           )
        self.size = len(header_data) + ntlm_payload_size + len_padding
        self.data = header_data + self.ntlm_payload + padding


# auth_3 PDU
class RPCAuth3OutPacket(object):
    def __init__(self, logger=None):
        self.logger = logger

        self.size = 0
        self.data = None

        self.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG
        self.call_id = 1

        self.ntlm_payload = None

    def make(self):
        if self.data is None:
            self._make_packet_data()

        return self.data

    def _make_packet_data(self):
        if self.ntlm_payload is None:
            raise ValueError("'ntlm_payload' attribute must not be None")

        ntlm_payload_size = len(self.ntlm_payload)
        align_modulo = ntlm_payload_size % 4
        if align_modulo > 0:
            len_padding = (4 - align_modulo)
        else:
            len_padding = 0

        header_data = pack("<bbbbbbbbhhl 4s bbbbl",
                           5, 0, # rpc_vers, rpc_vers_minor
                           DCERPC_PKT_AUTH_3, # ptype
                           # pfc_flags
                           self.pfc_flags,
                           # drep: RPC spec chap14.htm (Data Representation Format Label)
                           (1 << 4) | 0, 0, 0, 0,
                           (28 + ntlm_payload_size + len_padding), # frag_length
                           ntlm_payload_size + len_padding, # auth_length
                           self.call_id, # call_id

                           ## auth 3 specific:
                           "",

                           # sec_trailer:
                           RPC_C_AUTHN_WINNT, # auth_verifier.auth_type
                           # auth_verifier.auth_level:
                           RPC_C_AUTHN_LEVEL_CONNECT,
                           len_padding, # auth_verifier.auth_pad_length
                           0, # auth_verifier.auth_reserved
                           1 # auth_verifier.auth_context_id
                           )
        self.size = len(header_data) + ntlm_payload_size + len_padding
        self.data = header_data + self.ntlm_payload + len_padding * "\x00"


# ping PDU
class RPCPingOutPacket(object):
    def __init__(self, logger=None):
        self.logger = logger

        self.size = 0
        self.data = None

        self.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG
        self.call_id = 1

    def make(self):
        if self.data is None:
            self._make_packet_data()

        return self.data

    def _make_packet_data(self):
        header_data = pack("<bbbbbbbbhhl",

                           ## common headers:
                           5, 0, # rpc_vers, rpc_vers_minor
                           DCERPC_PKT_PING, # ptype
                           # pfc_flags
                           self.pfc_flags,
                           # drep: RPC spec chap14.htm (Data Representation Format Label)
                           (1 << 4) | 0, 0, 0, 0,
                           16, # frag_length
                           0, # auth_length
                           self.call_id # call_id
                           )
        self.size = len(header_data)
        self.data = header_data


# rts PDU
class RPCRTSOutPacket(object):
    def __init__(self, logger=None):
        self.logger = logger
        self.size = 0

        # RTS packets
        self.flags = RTS_FLAG_NONE
        self.command_data = []

    def make(self):
        if self.command_data is None:
            raise RTSParsingException("packet already returned")

        self._make_header()

        data = "".join(self.command_data)
        data_size = len(data)

        if (data_size != self.size):
            raise RTSParsingException("sizes do not match: declared = %d,"
                                      " actual = %d" % (self.size, data_size))
        self.command_data = None

        if self.logger is not None:
            self.logger.debug("returning packet: %s" % repr(data))

        return data

    def _make_header(self):
        header_data = pack("<bbbbbbbbhhlhh",
                           5, 0, # rpc_vers, rpc_vers_minor
                           DCERPC_PKT_RTS, # ptype
                           PFC_FIRST_FRAG | PFC_LAST_FRAG, # pfc_flags
                           # drep: RPC spec chap14.htm (Data Representation Format Label)
                           (1 << 4) | 0, 0, 0, 0,
                           (20 + self.size), # frag_length
                           0, # auth_length
                           0, # call_id
                           self.flags,
                           len(self.command_data))
        self.command_data.insert(0, header_data)
        self.size = self.size + 20

    def add_command(self, command_type, *args):
        if command_type < 0 or command_type > 15:
            raise RTSParsingException("command type unknown: %d (%s)" %
                                      (command_type, str(type(command_type))))

        self.size = self.size + 4

        values = [pack("<l", command_type)]

        command_size = RTS_CMD_SIZES[command_type]
        if command_size > 4:
            if command_type == RTS_CMD_FLOW_CONTROL_ACK:
                data = self._make_command_flow_control_ack(args[0])
            elif (command_type == RTS_CMD_COOKIE
                  or command_type == RTS_CMD_ASSOCIATION_GROUP_ID):
                data = self._make_command_cookie(args[0])
            elif command_type == RTS_CMD_PADDING:
                data = self._make_command_padding_data(args[0])
            elif command_type == RTS_CMD_CLIENT_ADDRESS:
                data = self._make_command_client_address(args[0])
            else:
                # command with int32 value
                if self.logger is not None:
                    self.logger.debug("cmd %s with data %d"
                                      % (RTS_CMD_DATA_LABELS[command_type], args[0]))
                data = pack("<l", args[0])
                self.size = self.size + 4
            values.append(data)

        self.command_data.append("".join(values))
        
    def _make_command_flow_control_ack(self, data_blob):
        # dumb method
        len_data = len(data_blob)
        if len_data != 24:
            raise RTSParsingException("expected a length of %d bytes,"
                                      " received %d" % (24, len_data))
        self.size = self.size + len_data

        return data_blob
    
    def _make_command_cookie(self, data_blob):
        # dumb method
        len_data = len(data_blob)
        if len_data != 16:
            raise RTSParsingException("expected a length of %d bytes,"
                                      " received %d" % (16, len_data))
        self.size = self.size + len_data

        return data_blob

    def _make_command_padding_data(self, data_blob):
        len_data = len(data_blob)
        data = pack("<l", len_data) + data_blob
        self.size = self.size + 4 + len_data

        return data

    def _make_command_client_address(self, data_blob):
        len_data = len(data_blob)
        if len_data == 4:
            address_type = 0 # ipv4
        elif len_data == 16:
            address_type = 1 # ipv6
        else:
            raise RTSParsingException("cannot deduce address type from data"
                                      " length: %d" % len_data)

        data = pack("<l", address_type) + data_blob + 12 * chr(0)
        self.size = self.size + 4 + len_data + 12

        return data

"""Module for handling DNS Packets"""

import socket
from random import getrandbits
from struct import Struct


class DNSRaw:
    """Class to hold the raw packet data from the wire"""

    s_pack = None
    s_pack_start = None
    s_pack_end = None

    def set_pack(self, pack, loc=0):
        self.set_pack = pack
        self.s_pack_start = loc
        self.s_pack_end = len(pack)

    def get_size(self):
        return self.s_pack_end - self.s_pack_start

    def get_pack(self):
        return self.s_pack

    def to_str(self):
        return "|".join(
            [
                str(self.s_pack_start),
                str(self.s_pack_end),
                repr(self.s_pack[self.s_pack_start : self.s_pack_end]),
            ]
        )


class DNSHeader(DNSRaw):
    """Class to hold all data related to the DNS header"""

    struct = Struct("!HBBHHHH")
    id = None
    notquery = False
    opcode = 0
    AA = False  # Authoritative Answer
    TC = False  # Truncated
    RD = False  # Recursion Desired
    RA = False  # Recursion Available
    Z = 0  # ?
    r_code = 0
    qd_count = 0
    an_count = 0
    ns_count = 0
    ar_count = 0

    def __init__(self, header_pack=None):
        if header_pack:
            self.set_from_pack(header_pack)
        else:
            self.id = getrandbits(16)
            self.RD = True  # Recursion Desired

    def get_size(self):
        return self.struct.size

    def get_pack(self):
        bits16_23 = (
            self.notquery << 7
            | ((self.opcode & 0xF) << 3)
            | self.AA << 2
            | self.TC << 1
            | self.RD
        )
        bits24_31 = self.RA << 7 | ((self.Z & 0x7) << 4) | self.r_code
        return self.struct.pack(
            self.id,
            bits16_23,
            bits24_31,
            self.qd_count,
            self.an_count,
            self.ns_count,
            self.ar_count,
        )

    def set_from_pack(self, packed):
        self.s_pack_start = 0
        self.s_pack_end = self.struct.size
        self.s_pack = packed
        (
            self.id,
            bits16_23,
            bits24_31,
            self.qd_count,
            self.an_count,
            self.ns_count,
            self.ar_count,
        ) = self.struct.unpack(packed[0 : self.struct.size])

        self.notquery = bool(bits16_23 & (0x1 << 7))
        self.opcode = (bits16_23 & (0xF << 3)) >> 3
        self.AA = bool(bits16_23 & (0x1 << 2))
        self.TC = bool(bits16_23 & (0x1 << 1))
        self.RD = bool(bits16_23 & 0x1)

        self.RA = bool(bits24_31 & (0x1 << 7))
        self.Z = (bits24_31 & (0x7 << 4)) >> 4
        self.r_code = bits24_31 & 0xF

    def str_me(self):
        ret_array = ["id = %d" % self.id]
        if self.notquery:
            ret_array.append("Answer")
        else:
            ret_array.append("Query")
        ret_array.append("opcode = %d" % self.opcode)
        if self.AA:
            ret_array.append("Authoritative Answer")
        if self.TC:
            ret_array.append("Truncated")
        if self.RD:
            ret_array.append("Recursion Desired")
        if self.RA:
            ret_array.append("Recursion Available")
        line1 = " | ".join(ret_array)
        ret_array = [
            "return_code = %d" % self.r_code,
            "questions = %d" % self.qd_count,
            "answers = %d" % self.an_count,
            "authority = %d" % self.ns_count,
            "additional = %d" % self.ar_count,
        ]
        line2 = " | ".join(ret_array)
        return "\n".join([line1, line2])


class DNSName(DNSRaw):
    """Class to hold a packed web address"""

    name_array = []

    def __init__(self, name_array=None, pack=None, index=None):
        if pack and (index or index == 0):
            orig_size, array = self.from_pack(pack, index)
            self.s_pack = pack
            self.s_pack_start = index
            self.s_pack_end = index + orig_size
            self.name_array = array
        elif name_array:
            self.name_array = name_array
        elif pack or index or name_array:
            raise SyntaxError("Invalid initializer parameters")

    @classmethod
    def init_from_name(cls, name):
        return cls(name_array=cls.from_name(name))

    @classmethod
    def init_from_pack(cls, pack, index=0):
        return cls(pack=pack, index=index)

    def set_from_name(self, name):
        self.name_array = self.from_name(name)
        self.s_pack = None
        self.s_pack_start = None
        self.s_pack_end = None

    @staticmethod
    def from_name(name):
        retl = []
        if name[-1] != ".":
            name = name + "."
        for label in name.split("."):
            if len(label) > 65:
                raise SyntaxError("Labels can't be longer then 65 chars")
            retl.append(label.encode())
        return retl

    def get_name(self):
        return b".".join(self.name_array)

    def set_from_pack(self, pack, index):
        orig_size, array = self.from_pack(pack, index)
        self.name_array = array
        self.s_pack = pack
        self.s_pack_start = index
        self.s_pack_end = index + orig_size

    @staticmethod
    def from_pack(pack, sloc=0):
        retl = []
        pack_size = None
        loc = sloc
        label_size = 1  # Prepare to read the first octet
        while label_size > 0:
            if ord(pack[loc : loc + 1]) & 0xC0 == 0xC0:  # If octet is name pointer
                if not pack_size:  # If this is the first pointer
                    pack_size = loc - sloc + 2  # pack_size ends w/ 2 octets
                loc = (
                    (ord(pack[loc : loc + 1]) << 8) | ord(pack[loc + 1 : loc + 2])
                ) & 0x3FFF
                if loc >= len(pack):
                    raise SyntaxError("DNS name pointer outside packet")
            label_size = ord(pack[loc : loc + 1])
            loc += 1
            retl.append(pack[loc : loc + label_size])
            loc += label_size
        if not pack_size:
            pack_size = loc - sloc
        return pack_size, retl

    def get_oct_name(self):
        retl = []
        for label in self.name_array:
            retl.append(chr(len(label)).encode())
            retl.append(label)
        return b"".join(retl)

    def get_size(self):
        if self.s_pack:
            return self.s_pack_end - self.s_pack_start
        else:
            return len(self.get_oct_name())

    def get_pack(self):
        return self.get_oct_name()

    def str_me(self):
        return (self.get_name()[0:-1]).decode()  # take off . after TLD


class DNSQuestion(DNSRaw):
    """Class to represent a DNS question"""

    struct = Struct("!HH")
    q_name = None
    q_type = None
    q_class = None

    def __init__(self, name=None, qtype=0x1, qclass=0x1, pack=None, index=None):
        if pack and index:
            self.from_pack(pack, index)
        elif pack or index:
            raise SyntaxError("pack and index both needed")
        else:
            self.q_name = DNSName().init_from_name(name)
            self.q_type = qtype
            self.q_class = qclass

    def get_size(self):
        return self.q_name.get_size() + self.struct.size

    def get_pack(self):
        return b"".join(
            [self.q_name.get_pack(), self.struct.pack(self.q_type, self.q_class)]
        )

    def from_pack(self, pack, index):
        self.s_pack = pack
        self.s_pack_start = index
        self.q_name = DNSName().init_from_pack(pack, index)
        index += self.q_name.get_size()
        (self.q_type, self.q_class) = self.struct.unpack_from(pack, index)
        self.s_pack_end = index + self.struct.size

    def str_me(self):
        return " | ".join(["What is", self.q_name.str_me()])


class DNSResource(DNSRaw):
    """Class to represent a DNS Resource (Answer, Authority, Additional)"""

    struct = Struct("!HHLH")
    a_name = None
    a_type = None
    a_class = None
    a_ttl = None
    r_d_length = None
    r_data = None

    def __init__(self, pack=None, index=None):
        if pack and index:
            self.from_pack(pack, index)
        else:
            raise SyntaxError("Creation of answers w/o packet not supported")

    def get_size(self):
        return self.a_name.get_size() + self.struct.size + self.r_d_length

    def get_pack(self):
        return "".join(
            [
                self.a_name.get_pack(),
                self.struct.pack(
                    self.a_type, self.a_class, self.a_ttl, self.r_d_length
                ),
                self.r_data,
            ]
        )

    def from_pack(self, pack, index):
        self.s_pack = pack
        self.s_pack_start = index
        self.a_name = DNSName().init_from_pack(pack, index)
        index += self.a_name.get_size()
        (
            self.a_type,
            self.a_class,
            self.a_ttl,
            self.r_d_length,
        ) = self.struct.unpack_from(pack, index)
        index += self.struct.size
        if self.a_type == 0x0001:
            self.r_data = pack[index : index + self.r_d_length]
            index += self.r_d_length
            if self.r_d_length != 4:
                raise SyntaxError("Type is A, length isn't 4 bytes")
        if self.a_type == 0x0002 or self.a_type == 0x0005:
            self.r_data = DNSName().init_from_pack(pack, index)
            index += self.r_data.get_size()
        self.s_pack_end = index

    def str_me(self):
        if self.a_type == 0x0001:
            if self.r_d_length == 4:
                return "Host %s | A: %s | %d" % (
                    self.a_name.str_me(),
                    socket.inet_ntoa(self.r_data),
                    self.a_ttl,
                )
            else:
                return "Badly formed A type response"
        elif self.a_type == 0x0002:
            return "Host %s | NS: %s | %d" % (
                self.a_name.str_me(),
                self.r_data.str_me(),
                self.a_ttl,
            )
        elif self.a_type == 0x0005:
            return "Host %s | CNAME: %s | %d" % (
                self.a_name.str_me(),
                self.r_data.str_me(),
                self.a_ttl,
            )
        else:
            return "Resource type >%d< not supported" % self.a_type


class DNSPacket(DNSRaw):
    """Class to represent a DNS packet, be it query or response"""

    header = DNSHeader()
    questions = []
    answers = []
    authority = []
    additional = []

    def add_q(self, name, q_type=0x1):
        question = DNSQuestion(name=name, qtype=q_type)
        self.questions.append(question)
        self.header.qd_count += 1

    def get_size(self):
        length = self.header.get_size()
        for i in range(self.header.qd_count):
            length += self.questions[i].get_size()
        for i in range(self.header.an_count):
            length += self.answers[i].get_size()
        for i in range(self.header.ns_count):
            length += self.authority[i].get_size()
        for i in range(self.header.ar_count):
            length += self.additional[i].get_size()
        return length

    def get_pack(self):
        retl = [self.header.get_pack()]
        for i in range(self.header.qd_count):
            retl.append(self.questions[i].get_pack())
        for i in range(self.header.an_count):
            retl.append(self.answers[i].get_pack())
        for i in range(self.header.ns_count):
            retl.append(self.authority[i].get_pack())
        for i in range(self.header.ar_count):
            retl.append(self.additional[i].get_pack())
        return b"".join(retl)

    def from_pack(self, pack):
        self.s_pack = pack
        self.header.set_from_pack(pack)
        if self.header.TC:
            raise ValueError("Packet is truncated, use TCP")
        loc = self.header.get_size()
        for i in range(self.header.qd_count):
            self.questions.append(DNSQuestion(pack=pack, index=loc))
            loc += self.questions[i].get_size()
        for i in range(self.header.an_count):
            self.answers.append(DNSResource(pack=pack, index=loc))
            loc += self.answers[i].get_size()
        for i in range(self.header.ns_count):
            self.authority.append(DNSResource(pack=pack, index=loc))
            loc += self.authority[i].get_size()
        for i in range(self.header.ar_count):
            self.additional.append(DNSResource(pack=pack, index=loc))
            loc += self.additional[i].get_size()

    def str_me(self):
        ret_array = [self.header.str_me()]
        if self.header.qd_count:
            ret_array.append("Question:")
        for i in range(self.header.qd_count):
            ret_array.append(self.questions[i].str_me())
        if self.header.an_count:
            ret_array.append("Answer:")
        for i in range(self.header.an_count):
            ret_array.append(self.answers[i].str_me())
        if self.header.ns_count:
            ret_array.append("Authority:")
        for i in range(self.header.ns_count):
            ret_array.append(self.authority[i].str_me())
        if self.header.ar_count:
            ret_array.append("Additional:")
        for i in range(self.header.ar_count):
            ret_array.append(self.additional[i].str_me())
        return "\n".join(ret_array)

    def str_answers(self):
        if self.header.r_code == 0:
            ret_array = [
                "--- Answer is%s Authoritative ---" % ("" if self.header.AA else " not")
            ]
            for i in range(self.header.an_count):
                ret_array.append(self.answers[i].str_me())
        elif self.header.r_code == 1:
            ret_array = ["--- Format Error ---"]
        elif self.header.r_code == 2:
            ret_array = ["--- Server Failure ---"]
        elif self.header.r_code == 3:
            ret_array = ["--- Name Error ---"]
            if self.header.AA:
                ret_array.append("Hostname does not exist")
        elif self.header.r_code == 4:
            ret_array = ["--- Not Implemented (on DNS server) ---"]
        elif self.header.r_code == 5:
            ret_array = ["--- Refused (on DNS server) ---"]
        else:
            ret_array = ["--- Unknown Error ---"]
        return "\n".join(ret_array)

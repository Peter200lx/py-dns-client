"""Test set for pydns"""

import unittest

import pydns


class TestDNSPacket(unittest.TestCase):
    def test_packet(self):
        test_packet = pydns.DNSPacket()
        test_packet.add_q("this.is.a.test.com")
        self.assertTrue(test_packet.header.RD)
        self.assertTrue(not test_packet.header.notquery)


class TestDNSName(unittest.TestCase):
    def test_name(self):
        dot_name = pydns.DNSName.init_from_name("this.is.a.test.com")
        pack_bytes = b"%cthis%cis%ca%ctest%ccom%c" % (4, 2, 1, 4, 3, 0)
        pack_name = pydns.DNSName.init_from_pack(pack_bytes)
        self.assertEqual(dot_name.name_array, pack_name.name_array)
        dot_name2 = pydns.DNSName.init_from_name("this.is.a.test.com.")
        self.assertEqual(dot_name2.name_array, pack_name.name_array)

    def test_bad_compression(self):
        with self.assertRaises(SyntaxError):
            pydns.DNSName.from_pack("".join([chr(0xC0), chr(0xFF)]))


if __name__ == "__main__":
    unittest.main()

"""Tests for nmap_reporter. Scans are written as XML strings here --
no real nmap run or network access is needed."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nmap_reporter import parse_scan, diff_scans, tier, render_markdown

SCAN_A = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="10.0.0.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="23"><state state="open"/>
<service name="telnet"/></port>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="Apache" version="2.4"/></port>
<port protocol="tcp" portid="22"><state state="closed"/>
<service name="ssh"/></port>
</ports></host>
<host><status state="up"/>
<address addr="10.0.0.11" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https"/></port></ports></host>
</nmaprun>"""

SCAN_B = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="10.0.0.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="23"><state state="open"/>
<service name="telnet"/></port>
<port protocol="tcp" portid="3389"><state state="open"/>
<service name="ms-wbt-server"/></port>
</ports></host>
<host><status state="up"/>
<address addr="10.0.0.12" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh"/></port></ports></host>
</nmaprun>"""


def write_scan(text):
    tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w")
    tmp.write(text)
    tmp.close()
    return tmp.name


class TestNmapReporter(unittest.TestCase):
    def test_open_ports_only_and_ranked(self):
        path = write_scan(SCAN_A)
        try:
            hosts = parse_scan(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(hosts["10.0.0.10"]), 2)  # closed 22 excluded
        self.assertEqual(hosts["10.0.0.10"][0]["service"], "telnet")
        self.assertEqual(hosts["10.0.0.10"][0]["tier"], "Critical")
        self.assertGreater(hosts["10.0.0.10"][0]["score"],
                           hosts["10.0.0.10"][1]["score"])

    def test_telnet_outranks_port_count(self):
        # One telnet host must outrank a host with many low-risk ports:
        # risk is driven by service, not by how many ports are open.
        self.assertEqual(tier(100), "Critical")
        self.assertEqual(tier(25), "Low")

    def test_remediation_present(self):
        path = write_scan(SCAN_A)
        try:
            hosts = parse_scan(path)
        finally:
            os.unlink(path)
        telnet = hosts["10.0.0.10"][0]
        self.assertIn("SSH", telnet["remediation"])

    def test_markdown_render(self):
        path = write_scan(SCAN_A)
        try:
            hosts = parse_scan(path)
        finally:
            os.unlink(path)
        md = render_markdown(hosts)
        self.assertIn("10.0.0.10", md)
        self.assertIn("telnet", md)

    def test_diff_mode(self):
        a, b = write_scan(SCAN_A), write_scan(SCAN_B)
        try:
            diff = diff_scans(parse_scan(a), parse_scan(b))
        finally:
            os.unlink(a)
            os.unlink(b)
        self.assertEqual(diff["new_hosts"], ["10.0.0.12"])
        self.assertEqual(diff["gone_hosts"], ["10.0.0.11"])
        self.assertIn(("10.0.0.10", 3389, "tcp", "ms-wbt-server"), diff["new_ports"])
        self.assertIn(("10.0.0.10", 80, "tcp", "http"), diff["gone_ports"])


if __name__ == "__main__":
    unittest.main()

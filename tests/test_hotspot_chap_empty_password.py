"""Code-only cards (password = username) must log in when the Hotspot page
sends an empty password with CHAP, e.g. User Manager cards imported with an
empty password. Runs the real FreeRADIUS when it is installed (Debian/Ubuntu
freeradius 3.2 + radclient): the stock config plus exactly the
sites-available/default edits from docker/freeradius/entrypoint.sh."""
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / 'docker/freeradius/entrypoint.sh'
STOCK = Path('/etc/freeradius/3.0')


def site_edits():
    """The entrypoint section that edits sites-available/default."""
    text = ENTRYPOINT.read_text(encoding='utf-8')
    start = text.index('# 3. Enable SQL')
    return text[start:text.index('# Preserve maxcap accounting', start)]


class WiringTests(unittest.TestCase):
    def test_rule_is_in_the_core_entrypoint(self):
        block = site_edits()
        self.assertIn('HOTSPOT_SINGLE_FIELD_CHAP_FALLBACK', block)
        self.assertIn('reject = 1', block)
        self.assertIn('(&control:Cleartext-Password == &User-Name)', block)
        self.assertIn('(!&Framed-Protocol || (&Framed-Protocol != "PPP"))', block)
        self.assertLess(block.index('HOTSPOT_SINGLE_FIELD_CARD_FALLBACK'), block.index('HOTSPOT_SINGLE_FIELD_CHAP_FALLBACK'))
        self.assertIn('COPY entrypoint.sh /entrypoint.sh', (ROOT / 'docker/freeradius/Dockerfile').read_text(encoding='utf-8'))


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(shutil.which('freeradius') and shutil.which('radclient') and STOCK.is_dir() and os.geteuid() == 0,
                     'needs root and a local FreeRADIUS 3 with radclient')
class RealFreeRadiusTests(unittest.TestCase):
    CASES = (
        # name, attributes, expected
        ('code card, PAP, empty', 'User-Name=card123,User-Password=""', 'Accept'),
        ('code card, CHAP, empty', 'User-Name=card123,CHAP-Password=""', 'Accept'),
        ('code card, CHAP, username', 'User-Name=card123,CHAP-Password="card123"', 'Accept'),
        ('code card, CHAP, wrong', 'User-Name=card123,CHAP-Password="xyz"', 'Reject'),
        ('account, CHAP, empty', 'User-Name=user1,CHAP-Password=""', 'Reject'),
        ('account, CHAP, own password', 'User-Name=user1,CHAP-Password="secret1"', 'Accept'),
        ('account, CHAP, username as password', 'User-Name=user1,CHAP-Password="user1"', 'Reject'),
        ('code card, PPP CHAP, empty', 'User-Name=card123,CHAP-Password="",Framed-Protocol=PPP', 'Reject'),
    )

    def build(self, edits):
        conf = Path(tempfile.mkdtemp()) / 'raddb'
        self.addCleanup(shutil.rmtree, conf.parent)
        shutil.copytree(STOCK, conf, symlinks=True)
        subprocess.run(['bash', '-c', edits], env=dict(os.environ, CONF_DIR=str(conf)), check=True)
        site = conf / 'sites-available/default'
        text = re.sub(r'^(\s*)sql$', r'\1-sql', site.read_text(), flags=re.M)   # no database in this test
        port = free_udp_port()
        kept, last = [], 0
        for block in re.finditer(r'^listen \{.*?^\}\n', text, re.S | re.M):
            kept.append(text[last:block.start()])
            body = block.group(0)
            if re.search(r'^\s*ipv6addr\s*=', body, re.M):
                body = ''                                  # IPv6 may be unavailable
            elif re.search(r'^\s*type = auth\s*$', body, re.M):
                body = re.sub(r'^(\s*)ipaddr = \*', r'\1ipaddr = 127.0.0.1', body, flags=re.M)
                body = re.sub(r'^(\s*)port = 0', rf'\1port = {port}', body, flags=re.M)
            else:
                body = ''                                  # acct listener not needed
            kept.append(body)
            last = block.end()
        kept.append(text[last:])
        site.write_text(''.join(kept))
        users = conf / 'mods-config/files/authorize'
        users.write_text('card123 Cleartext-Password := "card123"\nuser1 Cleartext-Password := "secret1"\n' + users.read_text())
        radiusd = conf / 'radiusd.conf'
        radiusd.write_text(re.sub(r'^(\s*)(user|group) = freerad', r'\1\2 = root', radiusd.read_text(), flags=re.M))
        return conf, port

    def results(self, edits):
        conf, port = self.build(edits)
        server = subprocess.Popen(['freeradius', '-f', '-d', str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(server.kill)
        got = {}
        try:
            for name, attrs, _ in self.CASES:
                for _attempt in range(20):
                    out = subprocess.run(['radclient', '-r1', '-t2', f'127.0.0.1:{port}', 'auth', 'testing123'],
                                         input=attrs, capture_output=True, text=True).stdout
                    match = re.search(r'Received Access-(Accept|Reject)', out)
                    if match or server.poll() is not None:
                        break
                    time.sleep(0.3)
                self.assertIsNone(server.poll(), 'FreeRADIUS exited; run freeradius -X -d on the test config')
                got[name] = match.group(1) if match else 'no reply'
        finally:
            server.kill()
            server.wait()
        return got

    def test_before_the_rule_the_imported_card_was_rejected(self):
        edits = site_edits()
        edits = edits[:edits.index('    # Same rule for CHAP.')] + edits[edits.index('    # Inject Reply-Message forwarding'):]
        self.assertEqual(self.results(edits)['code card, CHAP, empty'], 'Reject')

    def test_with_the_rule_only_the_code_card_case_changes(self):
        self.assertEqual(self.results(site_edits()), {name: expected for name, _, expected in self.CASES})

    def test_rule_is_inserted_once(self):
        conf, _ = self.build(site_edits())
        subprocess.run(['bash', '-c', site_edits()], env=dict(os.environ, CONF_DIR=str(conf)), check=True)
        self.assertEqual((conf / 'sites-available/default').read_text().count('HOTSPOT_SINGLE_FIELD_CHAP_FALLBACK'), 1)


if __name__ == '__main__':
    unittest.main()

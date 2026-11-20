"""Self-tests for check_test_data.py: run with `python3 -m unittest discover -s .github/content-checks`."""

import unittest
from pathlib import Path

import check_test_data as c

POLICY = c.load_policy(Path(__file__).resolve().parent / "test_data_policy.yaml")


def kinds(text: str, path: str = "log_types/x/tests/case.yaml", private=()) -> list[tuple[str, str]]:
    return [(f.kind.split()[0], f.value) for f in c.scan_file(POLICY, path, text, list(private))]


class Addresses(unittest.TestCase):
    def test_documentation_ranges_pass(self):
        self.assertEqual(kinds("raw_sample: 'from 192.0.2.1 198.51.100.2 203.0.113.3 2001:db8::5 fe80::1%eth0'"), [])

    def test_public_and_private_ipv4_fail(self):
        self.assertEqual(kinds("raw_sample: 'from 8.8.8.8 port 1 and 10.0.0.7'"),
                         [("IPv4", "8.8.8.8"), ("IPv4", "10.0.0.7")])

    def test_public_ipv6_fails(self):
        self.assertEqual(kinds("raw_sample: 'from 2a00:1450:4001::1 port 1'"), [("IPv6", "2a00:1450:4001::1")])

    def test_versions_times_and_fingerprints_are_not_addresses(self):
        text = ("raw_sample: 'Chrome/124.0.6367.91 at 09:59:58 OID 1.3.6.1.4.1 "
                "MD5:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff'")
        self.assertEqual(kinds(text), [])

    def test_vrl_comments_are_checked_for_addresses(self):
        self.assertEqual(kinds("# from 10.0.0.1 port 22\nx = 1\n", "log_types/x/parser.vrl"), [("IPv4", "10.0.0.1")])


class Names(unittest.TestCase):
    def test_reserved_domains_pass(self):
        self.assertEqual(kinds("raw_sample: 'rhost=cafe.example.com h.test a@example.org x.example'"), [])

    def test_real_domain_and_email_fail(self):
        self.assertEqual(kinds("raw_sample: 'mail from jane@acme-corp.de via mx.acme-corp.de'"),
                         [("email", "jane@acme-corp.de"), ("domain", "mx.acme-corp.de")])

    def test_ip_prefixed_hostname_is_a_domain(self):
        self.assertEqual(kinds("raw_sample: 'rhost=1.2.3.4.nip.io'"), [("domain", "1.2.3.4.nip.io")])

    def test_yaml_keys_and_ocsf_paths_are_ignored(self):
        self.assertEqual(kinds("expected:\n  actor.user.name: bob\n  metadata.event_code: user.session.start\n"), [])

    def test_vrl_code_paths_are_ignored(self):
        self.assertEqual(kinds('x = string(.src.id) ?? ""\n', "log_types/x/parser.vrl"), [])

    def test_ssh_algorithm_identifiers_pass(self):
        self.assertEqual(kinds("raw_sample: 'chacha20-poly1305@openssh.com curve25519-sha256@libssh.org'"), [])


class FalsePositives(unittest.TestCase):
    def test_json_keys_are_not_domains(self):
        self.assertEqual(kinds('raw_sample: \'{"container.id":"abc"}\''), [])

    def test_json_values_are_still_scanned(self):
        self.assertEqual(kinds('raw_sample: \'{"host":"api.acme.io"}\''),
                         [("domain", "api.acme.io")])

    def test_filenames_are_not_domains(self):
        self.assertEqual(kinds("raw_sample: 'see README.md, install.sh, check.py and foo.tar.gz'"), [])

    def test_vrl_comment_filename_is_not_a_domain(self):
        self.assertEqual(kinds("# see SCHEMA.md\n", "log_types/x/parser.vrl"), [])

    def test_falco_field_name_value_is_not_a_domain(self):
        self.assertEqual(kinds('raw_sample: \'{"container.info":"container.info"}\''), [])

    def test_ocsf_ip_suffix_is_not_a_domain(self):
        self.assertEqual(kinds("# see src_endpoint.ip\n", "log_types/x/parser.vrl"), [])

    def test_real_domains_are_still_flagged(self):
        self.assertEqual(kinds("raw_sample: 'api.acme.io and api.acme.id'"),
                         [("domain", "api.acme.io"), ("domain", "api.acme.id")])

    def test_vendor_domain_is_still_flagged(self):
        self.assertEqual(kinds("expected:\n  metadata.product.vendor_name: goauthentik.io\n"),
                         [("domain", "goauthentik.io")])


class Denylists(unittest.TestCase):
    def test_public_denylist(self):
        self.assertEqual(kinds("# see registry.procyde.online\n", "log_types/x/parser.vrl")[-1][0], "matches")

    def test_private_denylist_hides_the_term(self):
        found = c.scan_file(POLICY, "log_types/x/tests/a.yaml", "raw_sample: 'host ACMEBANK-DC1'", ["acmebank"])
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].secret)
        self.assertNotIn("acmebank", found[0].render().lower())
        self.assertNotIn("acmebank", found[0].annotation().lower())


class Exceptions(unittest.TestCase):
    def test_exception_matches_value_and_path(self):
        ex = c.Exception_("8.8.8.8", ["log_types/x/*"], "public resolver named by the vendor's sample")
        self.assertTrue(ex.covers("log_types/x/tests/a.yaml", "8.8.8.8"))
        self.assertFalse(ex.covers("log_types/y/tests/a.yaml", "8.8.8.8"))

    def test_exception_without_reason_is_a_policy_error(self):
        import tempfile
        text = (Path(__file__).resolve().parent / "test_data_policy.yaml").read_text().replace(
            "exceptions: []", "exceptions:\n  - value: 8.8.8.8\n    paths: ['log_types/*']\n    reason: ''")
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as f:
            f.write(text)
            f.flush()
            with self.assertRaises(c.PolicyError):
                c.load_policy(Path(f.name))


if __name__ == "__main__":
    unittest.main()

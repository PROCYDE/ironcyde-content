"""Self-tests for check_test_data.py: run with `python3 -m unittest discover -s .github/content-checks`."""

import tempfile
import unittest
from unittest import mock
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

    def test_ipv4_mapped_documentation_addresses_pass(self):
        self.assertEqual(kinds("raw_sample: 'from ::ffff:192.0.2.4 port 1'"), [])

    def test_ipv4_mapped_public_addresses_fail(self):
        self.assertEqual(kinds("raw_sample: 'from ::ffff:8.8.8.8 port 1'"),
                         [("IPv4", "8.8.8.8"), ("IPv6", "::ffff:8.8.8.8")])

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

    def test_ssh_algorithm_identifiers_need_an_exception(self):
        # No global allowance: a real address at openssh.com must not pass with them.
        self.assertEqual(kinds("raw_sample: 'chacha20-poly1305@openssh.com alice@openssh.com'"),
                         [("email", "chacha20-poly1305@openssh.com"), ("email", "alice@openssh.com")])

    def test_vrl_string_literals_are_checked(self):
        self.assertEqual(kinds('.host = "customer.acme.com"\n.raw = s\'api.acme.io\'\n', "log_types/x/parser.vrl"),
                         [("domain", "customer.acme.com"), ("domain", "api.acme.io")])

    def test_vrl_inline_comments_are_checked(self):
        self.assertEqual(kinds('x = 1 # see mx.acme-corp.de\n', "log_types/x/parser.vrl"),
                         [("domain", "mx.acme-corp.de")])

    def test_yaml_inline_comments_are_checked(self):
        self.assertEqual(kinds("expected:\n  class_uid: 3002 # from mx.acme-corp.de\n"),
                         [("domain", "mx.acme-corp.de")])

    def test_field_paths_in_vrl_strings_are_ignored(self):
        self.assertEqual(kinds('x = get(.fields, ["user.name"]) ?? "src_endpoint.ip"\n', "log_types/x/parser.vrl"),
                         [])

    def test_url_hosts_are_checked_whatever_their_tld(self):
        self.assertEqual(kinds("raw_sample: 'see https://portal.customer.travel/login and user.name'"),
                         [("domain", "portal.customer.travel")])

    def test_url_hosts_ignore_file_name_and_field_path_exclusions(self):
        self.assertEqual(kinds("raw_sample: 'see https://portal.customer.sh/login and https://container.id/'"),
                         [("domain", "portal.customer.sh"), ("domain", "container.id")])

    def test_excluded_bare_name_does_not_hide_a_later_url(self):
        self.assertEqual(kinds("raw_sample: 'field container.id, host https://container.id/'"),
                         [("domain", "container.id")])

    def test_documentation_url_hosts_pass(self):
        self.assertEqual(kinds("raw_sample: 'see https://portal.example.com/login'"), [])

    def test_email_exception_does_not_allow_its_domain_elsewhere(self):
        self.assertEqual(kinds("raw_sample: 'chacha20-poly1305@openssh.com https://openssh.com/customer'"),
                         [("email", "chacha20-poly1305@openssh.com"), ("domain", "openssh.com")])

    def test_quoted_text_in_yaml_comments_is_checked(self):
        self.assertEqual(kinds('expected:\n  class_uid: 3002 # see "mx.acme-corp.de"\n'), [("domain", "mx.acme-corp.de")])

    def test_apostrophe_before_a_yaml_comment_does_not_hide_it(self):
        self.assertEqual(kinds("note: it's here # mx.acme-corp.de 'x'\n"), [("domain", "mx.acme-corp.de")])

    def test_vrl_comment_after_a_hash_in_a_string_is_checked(self):
        self.assertEqual(kinds('x = "#" # see "mx.acme-corp.de"\n', "log_types/x/parser.vrl"),
                         [("domain", "mx.acme-corp.de")])


class DecodedStrings(unittest.TestCase):
    def test_json_escapes_do_not_hide_addresses(self):
        self.assertEqual(kinds('raw_sample: \'{"sourceIPAddress":"\\u0038.8.8.8"}\''), [("IPv4", "8.8.8.8")])

    def test_yaml_escapes_do_not_hide_emails(self):
        self.assertIn(("email", "alice@acme.com"), kinds('raw_sample: "mail \\x61lice@acme.com"'))

    def test_plain_addresses_are_reported_once(self):
        self.assertEqual(kinds("raw_sample: 'from 8.8.8.8'"), [("IPv4", "8.8.8.8")])

    def test_escaped_keys_do_not_hide_private_terms(self):
        found = c.scan_private("log_types/x/tests/a.yaml", 'expected:\n  "\\x41CMEBANK": 1\n', ["acmebank"])
        self.assertEqual([(f.kind, f.secret) for f in found], [("private denylist", True)])

    def test_keys_in_json_samples_do_not_hide_private_terms(self):
        found = c.scan_file(POLICY, "log_types/x/tests/a.yaml", 'raw_sample: \'{"\\u0061cmebank": 1}\'', ["acmebank"])
        self.assertEqual([(f.kind, f.secret) for f in found], [("private denylist", True)])

    def test_unreadable_file_does_not_print_a_private_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "log_types" / "acmebank" / "tests" / "a.yaml").mkdir(parents=True)  # a directory, not a file
            policy = c.Policy(scan=["log_types/**"], networks=[], domains=[], tlds=set(), non_domain_suffixes=set(),
                              non_domains=set(), denylist=[])
            with mock.patch.object(c, "tracked_files", return_value=["log_types/acmebank/tests/a.yaml"]):
                found = c.run(root, policy, ["acmebank"])
        self.assertEqual([f.kind for f in found], ["file cannot be read"])
        self.assertNotIn("acmebank", found[0].render().lower())
        self.assertNotIn("acmebank", found[0].annotation().lower())

    def test_escapes_do_not_hide_private_terms(self):
        found = c.scan_private("log_types/x/tests/a.yaml", 'raw_sample: "\\x41CMEBANK"', ["acmebank"])
        self.assertEqual([(f.kind, f.secret) for f in found], [("private denylist", True)])


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

    def test_private_term_in_another_finding_is_hidden(self):
        found = c.scan_file(POLICY, "log_types/x/tests/a.yaml", "raw_sample: 'from Jane@ACMEBANK.com'", ["acmebank"])
        self.assertGreaterEqual(len(found), 2)
        for f in found:
            self.assertTrue(f.secret)
            self.assertNotIn("acmebank", f.render().lower())
            self.assertNotIn("acmebank", f.annotation().lower())

    def test_private_term_in_the_path_is_hidden(self):
        found = c.scan_file(POLICY, "log_types/acmebank/tests/a.yaml", "raw_sample: 'from 8.8.8.8'", ["acmebank"])
        self.assertEqual(len(found), 2)
        for f in found:
            self.assertNotIn("acmebank", f.render().lower())
            self.assertNotIn("acmebank", f.annotation().lower())

    def test_private_only_checks_nothing_else(self):
        found = c.scan_private("log_types/x/tests/a.yaml", "raw_sample: 'ACMEBANK at 8.8.8.8'", ["acmebank"])
        self.assertEqual([(f.kind, f.secret) for f in found], [("private denylist", True)])


class Exceptions(unittest.TestCase):
    def test_exception_matches_value_and_path(self):
        ex = c.Exception_("8.8.8.8", ["log_types/x/*"], "public resolver named by the vendor's sample")
        self.assertTrue(ex.covers("log_types/x/tests/a.yaml", "8.8.8.8"))
        self.assertFalse(ex.covers("log_types/y/tests/a.yaml", "8.8.8.8"))

    def test_exception_without_reason_is_a_policy_error(self):
        import re
        import tempfile
        # Prepends the entry, so the test holds whether the policy lists exceptions or none.
        text = re.sub(
            r"(?m)^exceptions:.*$",
            "exceptions:\n  - value: 8.8.8.8\n    paths: ['log_types/*']\n    reason: ''",
            (Path(__file__).resolve().parent / "test_data_policy.yaml").read_text(),
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as f:
            f.write(text)
            f.flush()
            with self.assertRaises(c.PolicyError):
                c.load_policy(Path(f.name))


if __name__ == "__main__":
    unittest.main()

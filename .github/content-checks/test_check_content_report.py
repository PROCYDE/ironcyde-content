"""Self-tests for check_content_report.py: run with `python3 -m unittest discover -s .github/content-checks`."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import check_content_report as c

RECOMMENDED = 'status_id: validation_attribute_recommended_missing (Recommended attribute "status_id" is missing.)'
DEPRECATED = 'http_status: validation_attribute_deprecated (Attribute "http_status" is deprecated.)'


def case(**fields) -> dict:
    base = {"name": "a", "passed": True, "file": "log_types/x/tests/a.yaml",
            "output": {"class_uid": 3002, "metadata": {"profiles": []}}}
    base.update(fields)
    return base


def report(*cases: dict, **log_type) -> dict:
    return {"log_types": [{"key": "x", "cases": list(cases), **log_type}]}


def messages(rep: dict) -> list[str]:
    return [f.message for f in c.check_report(rep)]


class Warnings(unittest.TestCase):
    def test_clean_case_passes(self):
        self.assertEqual(messages(report(case())), [])

    def test_missing_recommended_attributes_are_tolerated(self):
        self.assertEqual(messages(report(case(warnings=[RECOMMENDED, RECOMMENDED]))), [])

    def test_every_other_warning_fails(self):
        sibling = 'rcode: validation_attribute_enum_sibling_incorrect (expected "NXDomain".)'
        klass = '$: validation_class_deprecated (Class "account_change" uid 3001 is deprecated.)'
        self.assertEqual(messages(report(case(warnings=[RECOMMENDED, DEPRECATED, sibling, klass]))),
                         [f"a: {DEPRECATED}", f"a: {sibling}", f"a: {klass}"])

    def test_warning_without_a_code_fails(self):
        self.assertEqual(messages(report(case(warnings=["something new"]))), ["a: something new"])

    def test_warning_objects_are_read_by_message(self):
        self.assertEqual(messages(report(case(warnings=[{"message": RECOMMENDED}, {"message": DEPRECATED}]))),
                         [f"a: {DEPRECATED}"])

    def test_code_is_matched_as_a_whole_word(self):
        longer = "x: validation_attribute_recommended_missing_extra (new code)"
        self.assertEqual(messages(report(case(warnings=[longer]))), [f"a: {longer}"])


class Problems(unittest.TestCase):
    def test_case_problems_fail(self):
        self.assertEqual(messages(report(case(passed=False, problems=["did not normalize (abort): no_match"], output=None))),
                         ["a: did not normalize (abort): no_match"])

    def test_log_type_problems_fail_with_their_file(self):
        found = c.check_report({"log_types": [{"key": "x", "problems": [{"file": "log_types/x/parser.vrl", "message": "vector failed"}]}]})
        self.assertEqual([(f.path, f.message) for f in found], [("log_types/x/parser.vrl", "x: vector failed")])

    def test_log_type_without_cases_fails(self):
        self.assertEqual(messages({"log_types": [{"key": "x", "cases": []}]}), ["x: the report has no cases for this Log Type"])

    def test_case_path_falls_back_to_its_name(self):
        found = c.check_report(report(case(file=None, problems=["p"])))
        self.assertEqual(found[0].path, "log_types/x/tests/a.yaml")


class Profiles(unittest.TestCase):
    def test_event_without_profiles_fails(self):
        self.assertEqual(len(messages(report(case(output={"class_uid": 3002, "metadata": {"version": "1.9.0"}})))), 1)
        self.assertEqual(len(messages(report(case(output={"class_uid": 3002})))), 1)
        self.assertEqual(len(messages(report(case(output={"class_uid": 3002, "metadata": {"profiles": None}})))), 1)

    def test_declared_profiles_pass(self):
        self.assertEqual(messages(report(case(output={"metadata": {"profiles": ["host", "cloud"]}}))), [])


class Reports(unittest.TestCase):
    def test_other_json_is_rejected(self):
        for bad in ([], {}, {"log_types": {}}, {"log_types": ["x"]}):
            with self.assertRaises(ValueError):
                c.check_report(bad)

    def run_main(self, content: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(content, encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = c.main([str(path)])
            return status, out.getvalue()

    def test_exit_status(self):
        self.assertEqual(self.run_main(json.dumps(report(case())))[0], 0)
        self.assertEqual(self.run_main(json.dumps(report(case(warnings=[DEPRECATED]))))[0], 1)
        self.assertEqual(self.run_main("not json")[0], 2)
        self.assertEqual(self.run_main("[]")[0], 2)

    def test_missing_report_or_argument(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(c.main(["/nonexistent/report.json"]), 2)
            self.assertEqual(c.main([]), 2)


class Rendering(unittest.TestCase):
    def test_workflow_commands_are_escaped(self):
        line = c.Finding("log_types/a,b/x.yaml", "bad\n::error::injected 100%").render(True)
        self.assertEqual(line, "::error file=log_types/a%2Cb/x.yaml,title=Content quality::bad%0A::error::injected 100%25")

    def test_long_messages_are_cut(self):
        self.assertLessEqual(len(c.Finding("p", "x" * 5000).render(False)), c.MAX_MESSAGE + 10)


if __name__ == "__main__":
    unittest.main()

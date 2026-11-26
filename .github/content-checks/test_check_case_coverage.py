"""Self-tests for check_case_coverage.py: run with `python3 -m unittest discover -s .github/content-checks`."""

import tempfile
import unittest
from pathlib import Path

import check_case_coverage as c

CASE = "raw_sample: 'x'\nexpected:\n  class_uid: 3002\n  type_uid: 300201\n  metadata.profiles: []\n"


def messages(text: str) -> list[str]:
    return [f.message for f in c.check_case("log_types/x/tests/case.yaml", text)[0]]


def repo(parser: str, cases: dict[str, str]) -> list[str]:
    """Findings for a repository with one Log Type, as "path: message"."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        tests = root / "log_types" / "x" / "tests"
        tests.mkdir(parents=True)
        (root / "log_types" / "x" / "parser.vrl").write_text(parser, encoding="utf-8")
        for name, text in cases.items():
            (tests / name).write_text(text, encoding="utf-8")
        return [f.render(False) for f in c.check(root)]


class EmittedClasses(unittest.TestCase):
    def test_assignments_and_object_literals_emit(self):
        vrl = 'class_uid = 4001\n. = {"class_uid": 3002}\n.class_uid = 4003\n  class_uid=1007\n'
        self.assertEqual(c.emitted_classes(vrl), {4001, 3002, 4003, 1007})

    def test_comparisons_emit_nothing(self):
        vrl = "if class_uid == 2001 {\n  class_uid = 2004\n}\nif class_uid != 4001 && class_uid >= 1000 { x = 1 }\n"
        self.assertEqual(c.emitted_classes(vrl), {2004})

    def test_conditional_assignment_emits_every_branch(self):
        vrl = "class_uid = if a { 4003 } else if b { 4002 } else { 4001 }\n"
        self.assertEqual(c.emitted_classes(vrl), {4001, 4002, 4003})

    def test_conditional_assignment_over_several_lines(self):
        vrl = "class_uid = if a {\n  4003\n} else if b {\n  4002\n} else {\n  4001\n}\nx = if c { 9999 } else { 8888 }\n"
        self.assertEqual(c.emitted_classes(vrl), {4001, 4002, 4003})

    def test_conditional_stops_at_its_last_branch(self):
        vrl = "class_uid = if a { 4003 } else { 4001 }\nother = { 5001 }\nif z { y = { 6001 } }\n"
        self.assertEqual(c.emitted_classes(vrl), {4001, 4003})

    def test_unclosed_conditional_does_not_hang(self):
        self.assertEqual(c.emitted_classes("class_uid = if a { 4003 } else {"), {4003})

    def test_accepted_input_classes_emit(self):
        vrl = "class_uid = to_int(raw.class_uid) ?? 0\nif !includes([2004, 3002,4001], class_uid) {\n  class_uid = 1007\n}\n"
        self.assertEqual(c.emitted_classes(vrl), {1007, 2004, 3002, 4001})

    def test_other_includes_lists_emit_nothing(self):
        self.assertEqual(c.emitted_classes("known = includes([4624, 4625], eid)\nclass_uid = 3002\n"), {3002})

    def test_comment_lines_emit_nothing(self):
        vrl = "# class_uid = 2001 was the old class\n  # class_uid: 5001\nclass_uid = 2004\n"
        self.assertEqual(c.emitted_classes(vrl), {2004})

    def test_derived_values_emit_nothing(self):
        vrl = 'type_uid = class_uid * 100 + activity_id\n.category_uid = to_int(floor(class_uid / 1000))\n'
        self.assertEqual(c.emitted_classes(vrl), set())

    def test_extension_classes_have_six_digits(self):
        self.assertEqual(c.emitted_classes("class_uid = 201002\n"), {201002})


class Cases(unittest.TestCase):
    def test_complete_case_passes(self):
        self.assertEqual(messages(CASE), [])
        self.assertEqual(c.check_case("p", CASE)[1], 3002)

    def test_missing_assertions_are_named(self):
        self.assertEqual(messages("raw_sample: 'x'\nexpected:\n  class_uid: 3002\n"),
                         ["does not assert type_uid", "does not assert metadata.profiles"])

    def test_case_without_expected_fails(self):
        self.assertEqual(len(messages("raw_sample: 'x'\n")), 1)
        self.assertEqual(len(messages("raw_sample: 'x'\nexpected: []\n")), 1)

    def test_profiles_must_be_a_list(self):
        text = CASE.replace("metadata.profiles: []", "metadata.profiles: null")
        self.assertEqual(messages(text), ["metadata.profiles must be a list; write [] when the branch declares none"])
        self.assertEqual(messages(CASE.replace("[]", "[host, cloud]")), [])

    def test_type_uid_must_match_class_and_activity(self):
        self.assertEqual(messages(CASE + "  activity_id: 2\n"), ["type_uid 300201 is not class_uid 3002 * 100 + activity_id 2"])
        self.assertEqual(messages(CASE + "  activity_id: 1\n"), [])

    def test_type_uid_must_belong_to_the_class(self):
        self.assertEqual(messages(CASE.replace("300201", "400101")), ["type_uid 400101 does not belong to class_uid 3002"])

    def test_extension_class_type_uid(self):
        text = CASE.replace("3002\n", "201002\n").replace("300201", "20100202")
        self.assertEqual(messages(text), [])

    def test_class_uid_must_be_an_integer(self):
        self.assertEqual(messages(CASE.replace("class_uid: 3002", "class_uid: '3002'")), ["class_uid must be an integer"])
        self.assertEqual(messages(CASE.replace("class_uid: 3002", "class_uid: true")), ["class_uid must be an integer"])

    def test_invalid_yaml_is_a_finding(self):
        self.assertTrue(messages("expected: [unclosed\n")[0].startswith("not valid YAML"))


class Coverage(unittest.TestCase):
    def test_every_emitted_class_with_a_case_passes(self):
        self.assertEqual(repo("class_uid = 3002\n", {"a.yaml": CASE}), [])

    def test_class_without_a_case_fails(self):
        self.assertEqual(repo("class_uid = 3002\nif x { class_uid = 1007 }\n", {"a.yaml": CASE}),
                         ["log_types/x/parser.vrl: can emit class_uid 1007, but no case asserts it; add a regression case "
                          "for that branch"])

    def test_log_type_without_cases_fails(self):
        found = repo("class_uid = 3002\n", {})
        self.assertEqual(found[0], "log_types/x: has no regression cases")
        self.assertEqual(len(found), 2)

    def test_parser_without_a_class_literal_fails(self):
        found = repo("class_uid = to_int(raw.class_uid) ?? 0\n", {"a.yaml": CASE})
        self.assertEqual(len(found), 1)
        self.assertIn("names no class_uid literal", found[0])

    def test_case_findings_carry_the_case_path(self):
        found = repo("class_uid = 3002\n", {"a.yaml": CASE, "b.yaml": "raw_sample: 'x'\nexpected:\n  class_uid: 3002\n  type_uid: 300201\n"})
        self.assertEqual(found, ["log_types/x/tests/b.yaml: does not assert metadata.profiles"])

    def test_this_repository_is_clean(self):
        self.assertEqual([f.render(False) for f in c.check(Path(__file__).resolve().parents[2])], [])


class Rendering(unittest.TestCase):
    def test_workflow_commands_are_escaped(self):
        line = c.Finding("log_types/a,b:c/x.yaml", "bad\n::error::injected").render(True)
        self.assertEqual(line, "::error file=log_types/a%2Cb%3Ac/x.yaml,title=Case coverage::bad%0A::error::injected")


if __name__ == "__main__":
    unittest.main()

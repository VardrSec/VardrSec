"""Offline coverage for the CVE-2026-84243 runtime probe helpers.

No Docker, network access or image execution is required.
Run: python -m unittest discover -s tests -p 'test_glibc_locale.py'
"""

import gettext
import io
import unittest

import glibc_locale_acceptance as probe


class CatalogTests(unittest.TestCase):
    def test_catalog_is_a_valid_gnu_mo_with_translations(self):
        data = probe.build_catalog({probe.SOURCE: probe.ORDINARY})
        catalog = gettext.GNUTranslations(io.BytesIO(data))
        self.assertEqual(catalog.gettext(probe.SOURCE), probe.ORDINARY)
        self.assertEqual(catalog.gettext("untranslated"), "untranslated")
        self.assertEqual(catalog.charset(), "UTF-8")

    def test_ordinary_and_traversal_catalogs_differ(self):
        ordinary = probe.build_catalog({probe.SOURCE: probe.ORDINARY})
        traversal = probe.build_catalog({probe.SOURCE: probe.TRAVERSAL})
        self.assertNotEqual(ordinary, traversal)


class EnvironmentTests(unittest.TestCase):
    def test_only_locale_variables_are_kept(self):
        raw = (
            b"PATH=/usr/bin\0DATABASE_URL=postgresql://u:secret@db/x\0LANG=C.UTF-8\0"
            b"BACKEND_JWT_SECRET=hunter2\0LC_ALL=C\0LANGUAGE=../x\0LOCPATH=/tmp\0"
            b"LANGUAGES=not-a-locale-variable\0MY_LANG=x\0"
        )
        found = probe.locale_variables(raw)
        self.assertEqual(
            found,
            {"LANG": "C.UTF-8", "LC_ALL": "C", "LANGUAGE": "../x", "LOCPATH": "/tmp"},
        )
        self.assertNotIn("secret", repr(found))

    def test_empty_and_malformed_blocks(self):
        self.assertEqual(probe.locale_variables(b""), {})
        self.assertEqual(probe.locale_variables(b"LANG\0\0=x\0"), {})

    def test_c_locales_are_not_reported(self):
        self.assertEqual(probe.unexpected_locales("C\nC.utf8\nPOSIX\n"), [])
        self.assertEqual(
            probe.unexpected_locales("C\nC.UTF-8\nen_US.utf8\n"), ["en_US.utf8"]
        )


class ParsingTests(unittest.TestCase):
    def test_gettext_output(self):
        self.assertEqual(
            probe.parse_gettext("ordinary=a\ntraversal=b-c\nnoise\n"),
            {"ordinary": "a", "traversal": "b-c"},
        )

    def test_role_row(self):
        self.assertEqual(
            probe.parse_role("t|f|f|f\n"),
            {"superuser": True, "createrole": False, "createdb": False, "bypassrls": False},
        )

    def test_role_row_rejects_unexpected_output(self):
        for row in ("", "t|f", "yes|no|no|no", "t|f|f|f|f"):
            with self.assertRaises(ValueError):
                probe.parse_role(row)


class CheckTests(unittest.TestCase):
    ignored = {"ordinary": probe.SOURCE, "traversal": probe.SOURCE}

    def good(self):
        c_only = {
            "locale_environment": {"LANG": "C.UTF-8"},
            "locales": ["C", "C.utf8", "POSIX"],
            "gettext": {"image default": self.ignored, "C.UTF-8": self.ignored},
        }
        return {
            "api": c_only,
            "web": {**c_only, "locale_environment": {}},
            "runner": c_only,
            "db": {
                "locale_environment": {"LANG": "en_US.utf8"},
                "locales": ["C", "C.utf8", "POSIX", "en_US.utf8"],
                "gettext": {
                    "en_US.utf8": {
                        "ordinary": probe.ORDINARY,
                        "traversal": probe.TRAVERSAL,
                    },
                    "C.UTF-8": self.ignored,
                },
            },
        }

    def test_expected_observations_pass(self):
        self.assertEqual(probe.check(self.good()), [])

    def test_extra_locale_variable_fails(self):
        data = self.good()
        data["api"]["locale_environment"]["LANGUAGE"] = "../x"
        self.assertTrue(any("LANGUAGE" in line for line in probe.check(data)))

    def test_extra_locale_in_c_only_image_fails(self):
        data = self.good()
        data["runner"]["locales"].append("en_US.utf8")
        self.assertTrue(any("non-C locales" in line for line in probe.check(data)))

    def test_loaded_catalog_under_c_utf8_fails(self):
        data = self.good()
        data["web"]["gettext"]["C.UTF-8"] = {
            "ordinary": probe.SOURCE,
            "traversal": probe.TRAVERSAL,
        }
        self.assertTrue(any("catalog loaded" in line for line in probe.check(data)))

    def test_invalid_positive_control_fails(self):
        data = self.good()
        data["db"]["gettext"]["en_US.utf8"]["ordinary"] = probe.SOURCE
        self.assertTrue(any("fixture" in line for line in probe.check(data)))

    def test_missing_database_locale_fails(self):
        data = self.good()
        data["db"]["locales"] = ["C", "POSIX"]
        self.assertTrue(any("en_US.utf8 missing" in line for line in probe.check(data)))


if __name__ == "__main__":
    unittest.main()

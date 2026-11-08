"""Real reviewed-case-to-reader query regression; every application boundary is mocked."""

import copy
import unittest
from unittest.mock import Mock
from urllib.parse import urlsplit

import nm2_worker_acceptance as acceptance
import nm2_worker_persistent_projection as projection
import test_nm2_worker_persistent_projection as vectors


def original_requests(number=1):
    fixture = object.__new__(acceptance.Fixture)
    fixture.project = "vardrsec-nm2-queryunit"

    def api(path, body=None, **options):
        if path == "/engagements":
            return {"id": "engagement-query"}
        if path.endswith("/authorizations"):
            return {"id": "authorization-query"}
        if path.endswith("/test-cases"):
            return {"id": "case-query", **copy.deepcopy(body)}
        if path.endswith("/jobs"):
            return {"id": "job-query"}
        return {}

    fixture.api = Mock()
    fixture.api.request.side_effect = api
    _, _, _, case = fixture.new_job(f"persistent-{number:02d}", marker=True)
    spec = case["spec"]
    urls = [
        (identity["id"], "GET", identity["preflight"]["url"])
        for identity in spec["identities"]
        if "preflight" in identity
    ] + [
        (identity["id"], spec["request"]["method"], spec["request"]["url"])
        for identity in spec["identities"]
    ]
    rows = []
    for index, (identity, method, url) in enumerate(urls, 1):
        parsed = urlsplit(url)
        assert f"{parsed.scheme}://{parsed.netloc}" == acceptance.ORIGIN
        rows.append(
            {
                "identity": identity,
                "method": method,
                "path": parsed.path + ("?" + parsed.query if parsed.query else ""),
                "received_monotonic_ns": index,
            }
        )
    return rows


class ReviewedQuery(unittest.TestCase):
    def test_real_reviewed_case_and_marker_project_exactly_five_requests(self):
        for number in (1, 35):
            with self.subTest(number=number):
                rows = original_requests(number)
                self.assertEqual(len(rows), 5)
                self.assertIn("view=full&include=owner&", rows[2]["path"])
                self.assertEqual(projection.requests(rows, number), (1, 5))

    def test_each_category_requires_exact_reviewed_query_without_duplicates(self):
        marker = "nm2_case=persistent-01"
        session, resource = "/session?", "/fixed/records/42?"
        changes = [
            (0, session + marker + "&view=full"),
            (0, session + marker + "&include=owner"),
            (0, session + marker + "&" + marker),
            (0, session + "view=full"),
            (0, session + "nm2_case=persistent-02"),
            (2, resource + marker + "&view=full"),
            (2, resource + marker + "&include=owner"),
            (2, resource + "view=full&include=owner"),
            (2, resource + marker + "&view=other&include=owner"),
            (2, resource + marker + "&view=full&include=peer"),
            (2, resource + marker + "&view=&include=owner"),
            (2, resource + marker + "&view=full&include="),
            (2, resource + marker + "&view=full&include=owner&view=full"),
            (2, resource + marker + "&view=full&include=owner&include=owner"),
            (2, resource + marker + "&view=full&include=owner&" + marker),
            (2, resource + marker + "&view=full&include=owner&extra=value"),
            (2, resource + "nm2_case=persistent-02&view=full&include=owner"),
        ]
        for index, path in changes:
            with self.subTest(index=index, path=path):
                rows = original_requests()
                rows[index]["path"] = path
                with self.assertRaises(ValueError):
                    projection.requests(rows, 1)

    def test_method_path_origin_principal_marker_and_five_count_stay_bound(self):
        changes = [
            (0, "method", "POST"),
            (2, "method", "POST"),
            (0, "identity", "anonymous"),
            (2, "identity", "peer"),
            (2, "path", "/other?view=full&include=owner&nm2_case=persistent-01"),
            (
                2,
                "path",
                "http://foreign.test/fixed/records/42?view=full&include=owner&nm2_case=persistent-01",
            ),
            (
                2,
                "path",
                "//foreign.test/fixed/records/42?view=full&include=owner&nm2_case=persistent-01",
            ),
            (
                2,
                "path",
                "/fixed/records/42?view=full&include=owner&nm2_case=persistent-01#extra",
            ),
        ]
        for index, field, changed in changes:
            with self.subTest(index=index, field=field):
                rows = original_requests()
                rows[index][field] = changed
                with self.assertRaises(ValueError):
                    projection.requests(rows, 1)
        for count in (4, 6):
            with self.subTest(count=count):
                rows = original_requests()
                rows = rows[:count] if count == 4 else rows + [copy.deepcopy(rows[-1])]
                with self.assertRaises(ValueError):
                    projection.requests(rows, 1)

    def test_full_availability_reader_accepts_actual_queries_with_existing_gates(self):
        raw, selection = vectors.vector()
        case = raw["cases"]["persistent_availability"]
        for number, measured in enumerate(case["attempts"], 1):
            actual = original_requests(number)
            for old, original in zip(measured["requests"], actual, strict=True):
                old.update(
                    {key: original[key] for key in ("identity", "method", "path")}
                )
        public = projection.project(raw, selection)
        self.assertEqual(public["measurements"]["target_request_count"], 175)
        self.assertEqual(public["measurements"]["last_sequence"], "35")
        self.assertEqual(
            public["measurements"]["limits"],
            {"max_attempts": None, "idle_timeout_seconds": None},
        )
        for field, changed in (
            ("idle_seconds", 69),
            ("target_request_count", 174),
            ("last_sequence", "34"),
        ):
            with self.subTest(field=field):
                invalid = copy.deepcopy(raw)
                invalid["cases"]["persistent_availability"][field] = changed
                with self.assertRaises(projection.ProjectionRefused):
                    projection.project(invalid, selection)

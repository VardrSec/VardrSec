"""Pure fixed-log witness checks; no Docker or HTTP."""

import unittest

from nm2_worker_launch_acceptance import budget_witness_count, duration_witness_count


class DurationWitnessTests(unittest.TestCase):
    def test_exact_map_warning_and_cardinality(self):
        line = b"2026-11-07 11:27:07,387 WARNING managed_http managed_claim_duration_exhausted"
        self.assertEqual(duration_witness_count(line + b"\r\n"), 1)
        self.assertEqual(duration_witness_count(line + b"\n" + line), 2)

    def test_generic_409_or_substring_is_not_a_witness(self):
        raw = (
            b'INFO: owned - "POST /jobs/owned/managed/claim HTTP/1.1" 409 Conflict\n'
            b"2026-11-07 11:27:07,387 WARNING other managed_claim_duration_exhausted\n"
            b"2026-11-07 11:27:07,387 WARNING managed_http managed_claim_duration_exhausted extra\n"
            b"managed_claim_duration_exhausted\n"
        )
        self.assertEqual(duration_witness_count(raw), 0)


    def test_target_witness_is_exact_and_separate_from_duration(self):
        prefix = b"2026-11-07 11:27:07,387 WARNING managed_http "
        duration = prefix + b"managed_claim_duration_exhausted"
        target = prefix + b"managed_claim_target_exhausted"
        raw = b"\r\n".join([duration, target, target + b" extra", target])
        self.assertEqual(budget_witness_count(raw, "target"), 2)
        self.assertEqual(duration_witness_count(raw), 1)
        self.assertEqual(budget_witness_count(duration, "target"), 0)

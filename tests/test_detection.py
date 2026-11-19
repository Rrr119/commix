#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import unittest

from src.core.controller import detection

class ResponseDifferenceEvidence(unittest.TestCase):
  """
  What makes a page worth believing, rather than only different.
  """
  BASELINE = ("<html><body><p>Record for 127.0.0.1</p>"
              "<p>the rest of the page stands still</p></body></html>")

  def test_a_complete_marker_pair_is_enough(self):
    marker = "AAAAAA42BBBBBB"
    candidate = self.BASELINE.replace("the rest", marker + " the rest")
    evidence = detection.score_response_difference(self.BASELINE, candidate, markers=[marker])
    self.assertTrue(evidence.strong)
    self.assertEqual([marker], evidence.marker_hits)

  def test_a_marker_already_on_the_baseline_is_not_evidence(self):
    marker = "AAAAAA42BBBBBB"
    baseline = self.BASELINE.replace("the rest", marker + " the rest")
    candidate = baseline.replace("stands still", "stands still here")
    evidence = detection.score_response_difference(baseline, candidate, markers=[marker])
    self.assertFalse(evidence.strong)
    self.assertEqual([], evidence.marker_hits)

  def test_the_control_answer_is_not_the_command_answer(self):
    marker = "AAAAAA42BBBBBB"
    control = self.BASELINE.replace("the rest", marker + " the rest")
    evidence = detection.score_response_difference(self.BASELINE, control, control=control,
                                                   markers=[marker])
    self.assertFalse(evidence.strong)
    self.assertLessEqual(evidence.score, 10.0)
    self.assertIn("control", evidence.reason)

  def test_a_page_that_did_not_move_is_not_evidence(self):
    evidence = detection.score_response_difference(self.BASELINE, self.BASELINE,
                                                   markers=["AAAAAA42BBBBBB"])
    self.assertEqual(0.0, evidence.score)
    self.assertFalse(evidence.strong)

  def test_the_payload_itself_is_not_an_answer(self):
    payload = "127.0.0.1;AAAAAA42BBBBBB"
    candidate = self.BASELINE.replace("127.0.0.1", payload)
    evidence = detection.score_response_difference(self.BASELINE, candidate,
                                                   markers=["AAAAAA42BBBBBB"],
                                                   payload=payload)
    self.assertFalse(evidence.strong)
    self.assertEqual([], evidence.marker_hits)

  def test_a_difference_without_a_marker_stays_below_the_bar(self):
    candidate = self.BASELINE.replace("Record for", "No record for")
    evidence = detection.score_response_difference(self.BASELINE, candidate, markers=[])
    self.assertFalse(evidence.strong)
    self.assertIn("without a marker", evidence.reason)

class TimeBlindEvidence(unittest.TestCase):
  """
  The paired timing reading, including the request that never came back.
  """
  def test_one_lucky_late_request_is_not_a_finding(self):
    controls = iter([0.10, 0.10])
    delayed = iter([1.0, 0.11])
    evidence = detection.verify_time_based_blind(lambda: next(controls), lambda: next(delayed),
                                                 1.0, attempts=2)
    self.assertFalse(evidence.confirmed)
    self.assertEqual(1, evidence.hits)

  def test_the_delay_has_to_reproduce(self):
    controls = iter([0.10, 0.11])
    delayed = iter([1.10, 1.12])
    evidence = detection.verify_time_based_blind(lambda: next(controls), lambda: next(delayed),
                                                 1.0, attempts=2)
    self.assertTrue(evidence.confirmed)
    self.assertEqual(2, evidence.hits)
    self.assertEqual(2, evidence.attempts)

  def test_a_missing_pair_is_retried_rather_than_counted_as_no(self):
    controls = iter([None, 0.10, 0.10])
    delayed = iter([None, 1.10, 1.10])
    evidence = detection.verify_time_based_blind(lambda: next(controls), lambda: next(delayed),
                                                 1.0, attempts=3)
    self.assertTrue(evidence.confirmed)
    self.assertEqual(2, evidence.attempts)

  def test_a_failed_request_is_not_a_zero_second_answer(self):
    controls = iter([False, 0.10, 0.10])
    delayed = iter([False, 1.10, 1.10])
    evidence = detection.verify_time_based_blind(lambda: next(controls), lambda: next(delayed),
                                                 1.0, attempts=3)
    self.assertTrue(evidence.confirmed)
    self.assertEqual(2, evidence.attempts)

class BoundedRetries(unittest.TestCase):
  """
  A caller asking again only while the answer is unusable.
  """
  def test_a_missing_answer_is_asked_again(self):
    answers = iter([None, False, "ok"])
    self.assertEqual("ok", detection.retry_call(lambda attempt: next(answers), attempts=3))

  def test_the_retry_stops_on_the_first_accepted_answer(self):
    seen = []
    def answer(attempt):
      seen.append(attempt)
      return "ok" if attempt == 0 else "late"
    self.assertEqual("ok", detection.retry_call(answer, attempts=3))
    self.assertEqual([0], seen)

  def test_the_last_answer_is_handed_back_when_the_budget_is_spent(self):
    answers = iter([None, None, "last"])
    self.assertEqual("last", detection.retry_call(lambda attempt: next(answers), attempts=3))

if __name__ == "__main__":
  unittest.main()

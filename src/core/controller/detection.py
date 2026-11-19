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

import difflib

from src.utils import settings

"""
Evidence read off a response, rather than off one regular expression.

The heuristic's markers are random, but a page can still carry them for a reason that is not the
command: the parameter is reflected, a filter quotes the payload back, or the page happens to move
between the two requests. A score puts those readings together, so that a marker found only in the
answer the command was asked for, and only after the payload itself was taken out, is worth more
than a page that merely changed.
"""
class ResponseEvidence(object):
  def __init__(self, score, marker_hits, marker_total, baseline_similarity,
               control_similarity, strong, reason):
    self.score = score
    self.marker_hits = marker_hits
    self.marker_total = marker_total
    self.baseline_similarity = baseline_similarity
    self.control_similarity = control_similarity
    self.strong = strong
    self.reason = reason

  def __repr__(self):
    return ("ResponseEvidence(score=" + str(round(self.score, 1)) +
            ", markers=" + str(len(self.marker_hits)) + "/" + str(self.marker_total) +
            ", reason='" + str(self.reason) + "')")

"""
A pair of timing answers, and whether the delayed one stands clear of the ordinary one often
enough to be believed.
"""
class TimeBlindEvidence(object):
  def __init__(self, confirmed, hits, attempts, control_times, delayed_times, margin, reason):
    self.confirmed = confirmed
    self.hits = hits
    self.attempts = attempts
    self.control_times = control_times
    self.delayed_times = delayed_times
    self.margin = margin
    self.reason = reason

  def __repr__(self):
    return ("TimeBlindEvidence(confirmed=" + str(self.confirmed) +
            ", hits=" + str(self.hits) + "/" + str(self.attempts) +
            ", reason='" + str(self.reason) + "')")

def _text(page):
  return page if isinstance(page, str) else ""

"""
How alike two pages are, from 0 to 1.

The same sequence matcher the rest of the run compares pages with, kept here without importing the
controller back into itself. Pages too large to read character by character fall back to their
lengths, which is still enough to notice that one is not the other.
"""
def page_similarity(first, second):
  first, second = _text(first), _text(second)
  if first == second:
    return 1.0
  if not first or not second:
    return 0.0
  if max(len(first), len(second)) > getattr(settings, "MAX_COMPARISON_LENGTH", 1000000):
    ratio = 1.0 * len(first) / len(second)
    return ratio if ratio <= 1 else 1.0 / ratio
  try:
    return difflib.SequenceMatcher(None, first, second).quick_ratio()
  except (MemoryError, TypeError, ValueError):
    return 0.0

"""
Score how much of an answer is evidence rather than page noise, from 0 to 100.

'markers' are the strings that only a command's output should carry - normally the random marker
pair around the computed value. A marker already on the baseline page, or on the control answer,
is not this answer's evidence. 'control' is the same question asked with a value that cannot be
the command's output; a candidate that reads like that control is the request being echoed, not
the command being run.
"""
def score_response_difference(baseline, candidate, control=None, markers=None,
                              threshold=None, payload=None):
  threshold = settings.DETECTION_SCORE_THRESHOLD if threshold is None else threshold
  baseline, candidate = _text(baseline), _text(candidate)
  control = None if control is None else _text(control)
  if payload:
    # The exact payload is the cheapest reflection to take out. A caller that has already done the
    # target's rewrites (through checks.remove_reflected_values) can leave this out.
    baseline = baseline.replace(payload, "")
    candidate = candidate.replace(payload, "")
    if control is not None:
      control = control.replace(payload, "")
  markers = [str(marker) for marker in (markers or []) if marker]

  if not candidate:
    return ResponseEvidence(0.0, [], len(markers), 0.0, 0.0, False, "empty answer")

  baseline_similarity = page_similarity(baseline, candidate)
  control_similarity = page_similarity(control, candidate) if control is not None else None
  changed = max(0.0, 1.0 - baseline_similarity)
  control_changed = max(0.0, 1.0 - control_similarity) if control is not None else changed

  marker_hits = []
  for marker in markers:
    if marker not in candidate:
      continue
    if marker in baseline:
      continue
    if control is not None and marker in control:
      continue
    marker_hits.append(marker)

  # One complete marker pair is already a command's answer. The count is reported so a caller can
  # see how many separators answered, but the first one is what makes this evidence at all.
  marker_score = 100.0 if marker_hits else 0.0

  """
  Once the payload itself has been taken back out, a real result is usually a small number of
  characters added to a page that is otherwise unchanged - so a marker carries most of the weight,
  and the page difference and the control only decide whether that marker is believable.
  """
  if marker_hits:
    score = (0.70 * marker_score +
             0.15 * min(100.0, changed * 100.0) +
             0.15 * min(100.0, control_changed * 100.0))
  else:
    score = (0.50 * min(100.0, changed * 100.0) +
             0.50 * min(100.0, control_changed * 100.0))

  reason = "marker evidence"
  if control is not None and candidate == control and candidate != baseline:
    score = min(score, 10.0)
    reason = "answer matches the control"
  elif not marker_hits and not changed:
    score = 0.0
    reason = "answer matches the baseline"
  elif not marker_hits:
    reason = "response difference without a marker"

  return ResponseEvidence(score, marker_hits, len(markers), baseline_similarity,
                          control_similarity, score >= threshold, reason)

"""
The number only, for callers that do not need the reasons behind it.
"""
def response_difference_score(baseline, candidate, control=None, markers=None,
                              threshold=None, payload=None):
  return score_response_difference(baseline, candidate, control, markers, threshold,
                                   payload).score

"""
Call something again while it has no usable answer, up to a bounded number of attempts.

'accept' is asked of every result; without one, anything other than None/False is accepted. The
last result is handed back where the budget runs out, so the caller still sees what the target
last said rather than an invented failure.
"""
def retry_call(call, attempts=None, accept=None):
  attempts = max(1, int(attempts if attempts is not None else settings.FALSE_POSITIVE_RETRIES))
  last = None
  for attempt in range(attempts):
    try:
      last = call(attempt)
    except (KeyboardInterrupt, SystemExit):
      raise
    except Exception:
      last = None
    if accept is not None:
      if accept(last):
        return last
    elif last is not None and last is not False:
      return last
  return last

def _elapsed(value):
  if isinstance(value, (tuple, list)):
    value = value[0] if value else None
  if value is None or value is False:
    return None
  try:
    return float(value)
  except (TypeError, ValueError):
    return None

"""
Confirm that the target runs a command by timing one that waits and one that does not.

The two are asked as a pair, so what is compared is this target's own pace at this moment rather
than a delay against zero. A request that failed is retried, and one pair that is late enough is
not enough on its own: a delayed answer has to clear the ordinary one by the configured share of
the delay that was asked for, on enough of the paired attempts to be a pattern.

The callbacks return either elapsed seconds or a tuple whose first item is elapsed seconds.
"""
def verify_time_based_blind(send_control, send_delayed, delay, attempts=None):
  delay = float(delay)
  attempts = max(1, int(attempts if attempts is not None else settings.FALSE_POSITIVE_RETRIES))
  ratio = getattr(settings, "DETECTION_TIME_BLIND_RATIO", 0.6)
  margin = max(getattr(settings, "MIN_VALID_DELAYED_RESPONSE", 0.5), delay * ratio)
  control_times, delayed_times = [], []
  usable_pairs = 0
  hits = 0
  reason = "not enough paired answers"

  for attempt in range(attempts):
    try:
      control = _elapsed(send_control())
      delayed = _elapsed(send_delayed())
    except (KeyboardInterrupt, SystemExit):
      raise
    except Exception:
      control = delayed = None
    if control is None or delayed is None:
      reason = "a paired answer was not retrieved"
      continue
    control_times.append(control)
    delayed_times.append(delayed)
    usable_pairs += 1
    if delayed - control >= margin:
      hits += 1
      reason = "delayed answer cleared the ordinary one"
    else:
      reason = "delayed and ordinary answers were too close"

  if not usable_pairs:
    return TimeBlindEvidence(False, 0, attempts, control_times, delayed_times, margin, reason)

  required = max(1, min(getattr(settings, "DETECTION_TIME_BLIND_HITS", 2), usable_pairs))
  confirmed = hits >= required
  if confirmed:
    reason = "delay reproduced on " + str(hits) + "/" + str(usable_pairs) + " paired answers"
  return TimeBlindEvidence(confirmed, hits, usable_pairs, control_times, delayed_times,
                           margin, reason)

# eof

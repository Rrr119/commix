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

Three offline labs compare the blind channels, and the real CLI is run against them for the
scan-mode combinations: GET, POST, time-based and additive out-of-band.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.argv = ["commix.py"]

from tests.blind_testbed import BlindLab, LabServer
from src.utils import settings
from src.core.controller import checks
from src.core.techniques.boolean_based import bb_payloads
from src.core.techniques.time_based import tb_payloads
from src.core.techniques.oob import oob_payloads


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
PROFILES = ("page-oracle", "time-oracle", "oob-only")


def _hostname(token):
  return "corrtestcorrtest1234" + token + ".test.local"


def _run_commix(arguments, before="", timeout=120):
  """
  The CLI in a process of its own, with the same entry point a user reaches.
  """
  output_dir = tempfile.mkdtemp(prefix="commix-blind-detection-")
  code = ("import sys, os\n"
          "sys.path.insert(0, os.getcwd())\n" + before +
          "\nimport src.core.main as _main\n"
          "sys.argv = ['commix.py'] + sys.argv[1:]\n"
          "_main.entry_point()\n")
  try:
    process = subprocess.run(
      [sys.executable, "-c", code] + list(arguments) +
      ["--batch", "--disable-stats", "--skip-waf", "--output-dir=" + output_dir],
      cwd=ROOT,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,
      stdin=subprocess.PIPE,
      timeout=timeout,
    )
    output = process.stdout.decode("utf-8", errors="replace")
  finally:
    shutil.rmtree(output_dir, ignore_errors=True)
  return ANSI.sub("", output)


def _channel_patch(log_path):
  return ("from tests.blind_testbed import FileChannel\n"
          "from src.core.oob import provider as _provider\n"
          "_provider.build = lambda: FileChannel(%r)\n" % log_path)


@unittest.skipUnless(os.name == "posix", "the blind labs execute a POSIX shell")
class BlindDetectionRateAcrossThreeLabs(unittest.TestCase):
  """
  The three labs expose one blind channel each: an exit-status page, a working delay and outbound
  requests. The comparison asks each real payload builder which lab it can prove, which is the
  same evidence the production technique reads.
  """
  STATE = ("TARGET_OS", "OOB_SCHEME", "OOB_PORT", "SKIP_CALC", "BOOLEAN_PRINTED_STATE",
           "CMD_SUB_PREFIX", "CMD_SUB_SUFFIX")

  def setUp(self):
    self._state = dict((name, getattr(settings, name)) for name in self.STATE)
    settings.TARGET_OS = settings.OS.UNIX
    settings.OOB_SCHEME = "http"
    settings.OOB_PORT = None
    settings.SKIP_CALC = False
    settings.BOOLEAN_PRINTED_STATE = False
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"
    self.labs = [BlindLab(profile) for profile in PROFILES]

  def tearDown(self):
    for lab in self.labs:
      lab.close()
    for name, value in self._state.items():
      setattr(settings, name, value)

  def _boolean_detected(self, lab):
    tag = "BLINDT"
    payloads = (
      bb_payloads.decision(";", tag, len(tag), holds=True),
      bb_payloads.decision(";", tag, len(tag), holds=False),
    )
    true_answer, false_answer = [lab.observe(payload) for payload in payloads]
    return true_answer.body != false_answer.body

  def _time_detected(self, lab):
    payload = tb_payloads.decision(";", "BLINDT", len("BLINDT"), 1, "GET")
    return lab.observe(payload).elapsed >= 0.8

  def _oob_detected(self, lab, transport):
    lab.clear_oob()
    token = "tok" + transport
    expression, expected, prologue = oob_payloads.proof(transport)
    payload = oob_payloads.decision(";", transport, _hostname(token), expression, prologue)
    lab.observe(payload)
    protocol = "dns" if transport == "dns" else "http"
    hits = [interaction for interaction in lab.oob_interactions()
            if interaction.protocol == protocol and token in interaction.identifier]
    return checks.oob_proof_holds(hits, expected)

  def test_the_three_labs_show_where_each_blind_channel_works(self):
    rates = {}
    for technique, detector in (
        ("boolean", self._boolean_detected),
        ("time", self._time_detected),
        ("oob-dns", lambda lab: self._oob_detected(lab, "dns")),
        ("oob-http", lambda lab: self._oob_detected(lab, "curl")),
    ):
      detected = [lab.profile for lab in self.labs if detector(lab)]
      rates[technique] = 1.0 * len(detected) / len(self.labs)
      self.assertGreaterEqual(len(detected), 1, technique + " detected nothing")
    self.assertAlmostEqual(1.0 / len(self.labs), rates["boolean"])
    self.assertAlmostEqual(1.0 / len(self.labs), rates["time"])
    self.assertAlmostEqual(1.0, rates["oob-dns"])
    self.assertAlmostEqual(1.0, rates["oob-http"])

  def test_dns_and_http_both_carry_command_output_back(self):
    lab = self.labs[-1]
    for transport in ("curl", "dns"):
      lab.clear_oob()
      token = "out" + ("http" if transport == "curl" else "dns")
      payload = oob_payloads.exfiltrate(";", transport, _hostname(token), "echo hello")
      lab.observe(payload)
      if transport == "curl":
        hits = [interaction for interaction in lab.oob_interactions()
                if interaction.protocol == "http" and token in interaction.identifier]
        bodies = [checks.oob_request_body(interaction.raw_request).strip() for interaction in hits]
        self.assertIn("hello", bodies)
      else:
        chunks = {}
        for interaction in lab.oob_interactions():
          labels = interaction.identifier.lower().split(".")
          index = next((position for position, label in enumerate(labels)
                        if label.startswith("corrtestcorrtest1234")), None)
          if index is None or index < 2:
            continue
          data = labels[:index]
          number, _, total = data[0].partition("-")
          if not number.isdigit():
            continue
          chunks[int(number)] = "".join(data[1:])
        self.assertEqual("hello", oob_payloads.decode_dns_output(chunks))


@unittest.skipUnless(os.name == "posix", "the blind labs execute a POSIX shell")
class BlindChannelsComposeWithTheScanModes(unittest.TestCase):
  """
  Every mode is the real command line against the local labs: GET and POST for the page oracle,
  GET for the delay, and additive '--oob --technique=b' over both HTTP and DNS.
  """
  @classmethod
  def setUpClass(cls):
    cls.labs = dict((profile, BlindLab(profile)) for profile in PROFILES)
    cls.server = LabServer(cls.labs)
    cls.server.__enter__()

  @classmethod
  def tearDownClass(cls):
    cls.server.__exit__(None, None, None)
    for lab in cls.labs.values():
      lab.close()

  def setUp(self):
    for lab in self.labs.values():
      lab.clear_oob()

  def _boolean_run(self, arguments):
    return _run_commix(["--technique=b", "--skip-heuristics", "--os=unix"] + arguments)

  def test_boolean_blind_runs_over_get_and_post(self):
    get_output = self._boolean_run(["-u", self.server.url("page-oracle")])
    self.assertIn("injectable via boolean-based blind command injection", get_output)
    post_output = self._boolean_run([
      "-u", self.server.base + "/lab/page-oracle",
      "--data=addr=127.0.0.1",
    ])
    self.assertIn("injectable via boolean-based blind command injection", post_output)

  def test_time_blind_runs_over_get(self):
    output = _run_commix([
      "-u", self.server.url("time-oracle"),
      "--technique=t", "--time-sec=1", "--skip-heuristics", "--os=unix",
    ], before="from src.utils import settings as _settings\n_settings.MIN_SAFE_TIMESEC = 1\n")
    self.assertIn("injectable via time-based blind command injection", output)

  def test_oob_http_follows_an_explicit_boolean_selection(self):
    lab = self.labs["oob-only"]
    output = _run_commix([
      "-u", self.server.url("oob-only"),
      "--technique=b", "--skip-heuristics", "--os=unix",
      "--oob", "--oob-transport=curl", "--oob-timeout=2", "--oob-poll=1",
    ], before=_channel_patch(lab.oob_log))
    self.assertIn("injectable via out-of-band", output)
    self.assertTrue([interaction for interaction in lab.oob_interactions()
                     if interaction.protocol == "http"])

  def test_oob_dns_runs_over_post(self):
    lab = self.labs["oob-only"]
    output = _run_commix([
      "-u", self.server.base + "/lab/oob-only",
      "--data=addr=127.0.0.1",
      "--technique=b", "--skip-heuristics", "--os=unix",
      "--oob", "--oob-transport=dns", "--oob-timeout=2", "--oob-poll=1",
    ], before=_channel_patch(lab.oob_log))
    self.assertIn("injectable via out-of-band", output)
    self.assertTrue([interaction for interaction in lab.oob_interactions()
                     if interaction.protocol == "dns"])


if __name__ == "__main__":
  unittest.main()

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

import os
import unittest
import urllib.request

from tests.testbed_server import LabHandler, LabServer
from src.utils import settings
from src.core.parse import cmdline as menu
from src.core.controller import controller, detection

def _get(url):
  response = urllib.request.urlopen(url, timeout=5)
  try:
    return response.read().decode("utf-8", "replace")
  finally:
    response.close()

class TestbedRetries(unittest.TestCase):
  """
  A target that answers a refusal before it answers the question.
  """
  @classmethod
  def setUpClass(cls):
    LabHandler.state.reset()
    cls.server = LabServer().start()

  @classmethod
  def tearDownClass(cls):
    cls.server.stop()

  def setUp(self):
    LabHandler.state.reset()

  def test_the_request_is_asked_again_until_it_is_answered(self):
    url = self.server.address + "/flaky?input=hello"
    body = detection.retry_call(lambda attempt: _get(url), attempts=3,
                                accept=lambda answer: bool(answer and "Result:" in answer))
    self.assertIsNotNone(body)
    self.assertIn("Result:", body)

@unittest.skipUnless(os.name == "posix", "the testbed executes a POSIX shell")
class TestbedHeuristicDetection(unittest.TestCase):
  """
  The three pages that matter: one that only reflects, one that runs, and one that only says so by
  waiting. The first must not become a finding, and the other two must.
  """
  STATE = ("ORIGINAL_PAGE", "ORIGINAL_PAGE_COMPARABLE", "PAGE_NOISE_RATIO", "DYNAMIC_MARKINGS",
           "REFLECTIVE_VALUE_FOUND", "PRINTER_ANSWERED", "RESULTS_BASED_STATE", "EVAL_BASED_STATE",
           "SKIP_CODE_INJECTIONS", "SKIP_COMMAND_INJECTIONS", "IDENTIFIED_TARGET_OS", "TARGET_OS",
           "OS_IDENTIFICATION_PENDING", "IDENTIFIED_COMMAND_INJECTION", "TESTABLE_VALUE",
           "WHITESPACES", "VERBOSITY_LEVEL",
           "CHECKING_PARAMETER", "BASIC_STRING", "BASIC_COMMAND_INJECTION_PAYLOADS",
           "ALTER_INTERPRETER_BASIC_COMMAND_INJECTION_PAYLOADS", "BASIC_COMMAND_INJECTION_RESULT",
           "BASIC_COMMAND_INJECTION_RESULTS", "BASIC_COMMAND_INJECTION_MARKERS",
           "BASIC_COMMAND_INJECTION_EXPECTED", "BASIC_COMMAND_INJECTION_CONTROL_EXPECTED",
           "SKIP_SUBST", "TIME_RELATED_ATTACK", "DETECTION_TIME_BLIND_DELAY",
           "FALSE_POSITIVE_RETRIES", "COMMAND_SUGGESTED", "MULTI_ENCODED_PAYLOAD",
           "TAMPER_SCRIPTS", "AUTO_TAMPER", "TESTABLE_VALUE_OPTIMIZED",
           "VALUE_SKIPPED_EARLY", "VALUE_SKIP_REFUSED", "TESTABLE_VALUE_STOOD_IN_FOR")
  OPTIONS = ("data", "cookie", "host", "referer", "agent", "header", "headers", "auth_cred",
             "interpreter", "eval_sink", "retries", "timesec", "tech", "os", "smart", "oob",
             "batch", "skip_heuristics")

  @classmethod
  def setUpClass(cls):
    LabHandler.state.reset()
    cls.server = LabServer().start()

  @classmethod
  def tearDownClass(cls):
    cls.server.stop()

  def setUp(self):
    LabHandler.state.reset()
    self.state = dict((name, getattr(settings, name)) for name in self.STATE)
    self.options = dict((name, getattr(menu.options, name)) for name in self.OPTIONS)

    settings.ORIGINAL_PAGE_COMPARABLE = ""
    settings.PAGE_NOISE_RATIO = 1.0
    settings.DYNAMIC_MARKINGS = []
    settings.REFLECTIVE_VALUE_FOUND = False
    settings.PRINTER_ANSWERED = None
    settings.RESULTS_BASED_STATE = False
    settings.EVAL_BASED_STATE = False
    settings.SKIP_CODE_INJECTIONS = False
    settings.SKIP_COMMAND_INJECTIONS = False
    settings.IDENTIFIED_TARGET_OS = False
    settings.TARGET_OS = settings.OS.UNIX
    settings.OS_IDENTIFICATION_PENDING = False
    settings.IDENTIFIED_COMMAND_INJECTION = False
    settings.TESTABLE_VALUE = "hello"
    settings.TESTABLE_VALUE_OPTIMIZED = False
    settings.VALUE_SKIPPED_EARLY = None
    settings.VALUE_SKIP_REFUSED = False
    settings.TESTABLE_VALUE_STOOD_IN_FOR = ""
    settings.WHITESPACES = [settings.SINGLE_WHITESPACE]
    settings.VERBOSITY_LEVEL = 0
    settings.CHECKING_PARAMETER = "GET parameter 'input'"
    settings.BASIC_COMMAND_INJECTION_MARKERS = []
    settings.SKIP_SUBST = False
    settings.TIME_RELATED_ATTACK = False
    settings.DETECTION_TIME_BLIND_DELAY = 1
    settings.FALSE_POSITIVE_RETRIES = 2
    settings.COMMAND_SUGGESTED = False
    settings.MULTI_ENCODED_PAYLOAD = []
    settings.TAMPER_SCRIPTS = dict(self.state["TAMPER_SCRIPTS"])
    settings.AUTO_TAMPER = []

    for name in self.OPTIONS:
      if hasattr(menu.options, name):
        setattr(menu.options, name, None)
    menu.options.retries = 2
    menu.options.timesec = 1
    menu.options.tech = "rt"
    menu.options.smart = False
    menu.options.batch = True

  def tearDown(self):
    for name, value in self.state.items():
      setattr(settings, name, value)
    for name, value in self.options.items():
      setattr(menu.options, name, value)

  def detect(self, route, smart=False):
    url = self.server.address + route + "?input=hello"
    settings.ORIGINAL_PAGE = _get(url)
    tagged = url.replace("hello", "hello" + settings.INJECT_TAG, 1)
    menu.options.smart = smart
    controller.command_injection_heuristic_basic(tagged, "GET", "input", "GET")
    return settings.IDENTIFIED_COMMAND_INJECTION

  def test_a_reflected_page_is_not_a_finding(self):
    self.assertFalse(self.detect("/safe"))

  def test_a_running_command_is_a_finding(self):
    self.assertTrue(self.detect("/exec"))

  def test_a_blind_point_is_confirmed_by_time(self):
    self.assertTrue(self.detect("/blind", smart=True))

if __name__ == "__main__":
  unittest.main()

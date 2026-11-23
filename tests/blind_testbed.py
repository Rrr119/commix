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

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

try:
  from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:  # Python 2
  from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer as ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
  sys.path.insert(0, ROOT)

from src.core.oob.provider import Interaction, OOBProvider


ORIGINAL_VALUE = "127.0.0.1"
CORRELATION_ID = "corrtestcorrtest1234"


class Observation(object):
  """
  What one lab did with one command: what it rendered, how long it took and its exit status.
  """
  def __init__(self, body, returncode, elapsed, stdout=""):
    self.body = body
    self.returncode = returncode
    self.elapsed = elapsed
    self.stdout = stdout


class BlindLab(object):
  """
  A POSIX shell sink with one blind channel available and the other channels deliberately silent.

  'page-oracle' branches on the command's exit status, but has no working delay. 'time-oracle'
  renders a constant page, while 'sleep' works. 'oob-only' renders a constant page and has no
  delay either; only a request made by the target proves execution. Every lab has the fake HTTP
  and DNS clients installed, as egress is what the out-of-band channel exercises.
  """
  PROFILES = ("page-oracle", "time-oracle", "oob-only")

  def __init__(self, profile):
    if profile not in self.PROFILES:
      raise ValueError("unknown blind lab profile: " + profile)
    self.profile = profile
    self.root = tempfile.mkdtemp(prefix="commix-blind-lab-")
    self.bin = os.path.join(self.root, "bin")
    os.mkdir(self.bin)
    self.oob_log = os.path.join(self.root, "oob.jsonl")
    open(self.oob_log, "w").close()
    self._install_tools()

  def close(self):
    shutil.rmtree(self.root, ignore_errors=True)

  def environment(self):
    environment = dict(os.environ)
    environment["PATH"] = self.bin + os.pathsep + environment.get("PATH", "/usr/bin:/bin")
    environment["COMMIX_OOB_LOG"] = self.oob_log
    return environment

  def _write_tool(self, name, body):
    path = os.path.join(self.bin, name)
    with open(path, "w") as handle:
      handle.write("#!" + sys.executable + "\n" + body)
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)

  def _write_shell_tool(self, name, body):
    path = os.path.join(self.bin, name)
    with open(path, "w") as handle:
      handle.write("#!/bin/sh\n" + body)
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)

  def _install_tools(self):
    """
    Fake clients write what reached them to a file, so neither the test nor the OOB provider
    needs a resolver, a public interactsh server or any network beyond 127.0.0.1.
    """
    self._write_tool("nslookup", (
      "import json, os, sys\n"
      "args = [part for part in sys.argv[1:] if not part.startswith('-')]\n"
      "host = args[-1] if args else ''\n"
      "if host:\n"
      "  with open(os.environ['COMMIX_OOB_LOG'], 'a') as handle:\n"
      "    handle.write(json.dumps({'protocol': 'dns', 'identifier': host, 'raw_request': ''}) + '\\n')\n"
    ))
    self._write_tool("curl", (
      "import json, os, sys\n"
      "try:\n"
      "  from urllib.parse import urlparse\n"
      "except ImportError:\n"
      "  from urlparse import urlparse\n"
      "args = sys.argv[1:]\n"
      "urls = [part for part in args if part.startswith(('http://', 'https://'))]\n"
      "url = urls[-1] if urls else ''\n"
      "parsed = urlparse(url)\n"
      "posts = any(part == '--data-binary' or part.startswith('--data-binary=') or\n"
      "            part.startswith('--data=') or part == '-d' for part in args)\n"
      "body = sys.stdin.read() if posts else ''\n"
      "method = 'POST' if posts else 'GET'\n"
      "raw = method + ' ' + (parsed.path or '/') + ' HTTP/1.1\\r\\nHost: ' + (parsed.hostname or '') + '\\r\\n\\r\\n' + body\n"
      "with open(os.environ['COMMIX_OOB_LOG'], 'a') as handle:\n"
      "  handle.write(json.dumps({'protocol': 'http', 'identifier': parsed.hostname or '', 'raw_request': raw}) + '\\n')\n"
    ))
    # The DNS lookup chain names these as fallbacks. They answer nothing, which is what a target
    # without them does; the first lookup already logged the name.
    for name in ("getent", "host", "ping"):
      self._write_shell_tool(name, "exit 1\n")
    self._write_fake_sleep()

  def _write_fake_sleep(self):
    if self.profile == "time-oracle":
      return False
    self._write_shell_tool("sleep", "exit 0\n")
    return True

  """
  Turn the injected value into the command the lab actually runs.

  The original value stands for the application's own command, which succeeded before the payload
  was chained onto it. Keeping it as 'true' makes the emulated sink behave like a real one for
  both ';' and '&&' boundaries without making the test depend on a utility being installed.
  """
  def command(self, value):
    if value.startswith(ORIGINAL_VALUE):
      return "true" + value[len(ORIGINAL_VALUE):]
    return "true" + value

  def observe(self, value):
    started = time.time()
    process = subprocess.run(
      ["/bin/sh", "-c", self.command(value)],
      env=self.environment(),
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      timeout=30,
    )
    elapsed = time.time() - started
    stdout = process.stdout.decode("utf-8", errors="replace")
    if self.profile == "page-oracle":
      body = "TRUE" if process.returncode == 0 else "FALSE"
    else:
      body = "constant"
    return Observation(body, process.returncode, elapsed, stdout)

  def clear_oob(self):
    open(self.oob_log, "w").close()

  def oob_interactions(self):
    interactions = []
    with open(self.oob_log) as handle:
      for line in handle:
        line = line.strip()
        if not line:
          continue
        try:
          record = json.loads(line)
        except ValueError:
          continue
        interactions.append(Interaction(record.get("protocol", ""),
                                        record.get("identifier", ""),
                                        record.get("raw_request", "")))
    return interactions


class LabHandler(BaseHTTPRequestHandler):
  protocol_version = "HTTP/1.0"
  labs = {}

  def log_message(self, *args):
    pass

  def do_GET(self):
    self._serve()

  def do_POST(self):
    self._serve()

  def _value(self, parsed, body):
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    form = urllib.parse.parse_qs(body.decode("latin-1"), keep_blank_values=True) if body else {}
    cookie = urllib.parse.parse_qs(self.headers.get("Cookie", ""), separator=";", keep_blank_values=True)
    if "addr" in query:
      return query["addr"][0]
    if "addr" in form:
      return form["addr"][0]
    if "addr" in cookie:
      return cookie["addr"][0]
    return self.headers.get("X-Test", "")

  def _serve(self):
    parsed = urllib.parse.urlparse(self.path)
    parts = [part for part in parsed.path.split("/") if part]
    profile = parts[1] if len(parts) > 1 and parts[0] == "lab" else ""
    lab = self.labs.get(profile)
    if lab is None:
      self.send_error(404)
      return
    length = int(self.headers.get("Content-Length") or 0)
    body = self.rfile.read(length) if length else b""
    observation = lab.observe(self._value(parsed, body))
    payload = observation.body.encode("utf-8")
    self.send_response(200)
    self.send_header("Content-Type", "text/plain")
    self.send_header("Content-Length", str(len(payload)))
    self.end_headers()
    self.wfile.write(payload)


class LabServer(object):
  """
  One HTTP endpoint per lab, each carrying the injected value in whichever place was used.
  """
  def __init__(self, labs):
    self.labs = dict(labs)
    handler = type("LabHandlerForRun", (LabHandler,), {"labs": self.labs})
    self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    self.httpd.daemon_threads = True
    self.thread = threading.Thread(target=self.httpd.serve_forever)
    self.thread.daemon = True

  @property
  def base(self):
    return "http://127.0.0.1:" + str(self.httpd.server_address[1])

  def url(self, profile):
    return self.base + "/lab/" + profile + "?addr=" + ORIGINAL_VALUE

  def __enter__(self):
    self.thread.start()
    return self

  def __exit__(self, *exc):
    self.httpd.shutdown()
    self.httpd.server_close()


class FileChannel(OOBProvider):
  """
  An interactsh-shaped channel backed by the fake clients' log rather than a remote server.

  The production controller and payloads are unchanged: registration is a no-op, and every
  interaction the fake client recorded is handed back through the same provider interface.
  """
  def __init__(self, log_path):
    OOBProvider.__init__(self)
    self.log_path = log_path
    self.correlation_id = CORRELATION_ID
    self.domain = "test.local"
    self.scheme = "http"
    self.port = None
    self._offset = 0

  def start(self):
    pass

  def stop(self):
    pass

  def server_notice(self):
    return "Using out-of-band 'test.local' interactsh server."

  def _hostname(self, token):
    return self.correlation_id + token + "." + self.domain

  def _token_of(self, interaction):
    for label in (interaction.identifier or "").lower().split("."):
      if label.startswith(self.correlation_id):
        return label[len(self.correlation_id):]
    return None

  def data_of(self, interaction):
    labels = (interaction.identifier or "").lower().split(".")
    for index, label in enumerate(labels):
      if label.startswith(self.correlation_id):
        return labels[:index]
    return []

  def _fetch(self):
    found = []
    position = self._offset
    with open(self.log_path) as handle:
      handle.seek(self._offset)
      while True:
        line = handle.readline()
        if not line:
          break
        if not line.endswith("\n"):
          break
        try:
          record = json.loads(line)
        except ValueError:
          position = handle.tell()
          continue
        position = handle.tell()
        found.append(Interaction(record.get("protocol", ""),
                                 record.get("identifier", ""),
                                 record.get("raw_request", "")))
    self._offset = position
    return found

  def poll_now(self):
    for interaction in self._fetch():
      self._record(interaction)

  def wait_for(self, token, timeout, protocol=None):
    deadline = time.time() + timeout
    while True:
      self.poll_now()
      hits = self.seen(token, protocol=protocol)
      if hits or time.time() >= deadline:
        return hits
      time.sleep(0.05)

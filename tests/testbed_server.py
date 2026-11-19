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

import html
import subprocess
import threading
import time
import urllib.parse

try:
  from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:
  from http.server import BaseHTTPRequestHandler, HTTPServer
  ThreadingHTTPServer = HTTPServer

"""
A tiny range target: a page that reflects, a page that runs, a page that runs blind, and a page
that fails its first requests. The last one is here because a detector that gives up on the first
non-answer cannot tell a flaky target from a clean one.
"""
class LabState(object):
  def __init__(self):
    self.lock = threading.Lock()
    self.requests = {}

  def count(self, path):
    with self.lock:
      self.requests[path] = self.requests.get(path, 0) + 1
      return self.requests[path]

  def reset(self):
    with self.lock:
      self.requests = {}

def _page(body):
  return ("<!doctype html><html><head><title>commix testbed</title></head>"
          "<body><p>" + body + "</p></body></html>")

def _run_shell(value, timeout=8):
  command = "echo " + value
  try:
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, universal_newlines=True)
    try:
      output, _ = process.communicate(timeout=timeout)
    except TypeError:
      output, _ = process.communicate()
    return output or ""
  except Exception as err:
    return "testbed execution error: " + str(err)

class LabHandler(BaseHTTPRequestHandler):
  state = LabState()

  def _reply(self, status, body):
    encoded = body.encode("utf-8", "replace")
    self.send_response(status)
    self.send_header("Content-Type", "text/html; charset=utf-8")
    self.send_header("Content-Length", str(len(encoded)))
    self.end_headers()
    self.wfile.write(encoded)

  def do_GET(self):
    parsed = urllib.parse.urlsplit(self.path)
    query = urllib.parse.parse_qs(parsed.query)
    value = query.get("input", [""])[0]
    count = self.state.count(parsed.path)

    if parsed.path == "/health":
      self._reply(200, _page("ready"))
      return
    if parsed.path == "/safe":
      self._reply(200, _page("Result: " + html.escape(value)))
      return
    if parsed.path == "/exec":
      self._reply(200, _page("Result: " + html.escape(_run_shell(value))))
      return
    if parsed.path == "/blind":
      _run_shell(value)
      self._reply(200, _page("Result recorded."))
      return
    if parsed.path == "/flaky":
      if count <= 2:
        self._reply(503, _page("Try again"))
        return
      self._reply(200, _page("Result: " + html.escape(_run_shell(value))))
      return
    self._reply(404, _page("Not found"))

  def log_message(self, format, *args):
    pass

class LabServer(object):
  def __init__(self, host="127.0.0.1", port=0):
    self.httpd = ThreadingHTTPServer((host, port), LabHandler)
    self.thread = None

  @property
  def address(self):
    return "http://" + self.httpd.server_address[0] + ":" + str(self.httpd.server_address[1])

  def start(self):
    self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
    self.thread.start()
    return self

  def stop(self):
    self.httpd.shutdown()
    self.httpd.server_close()
    if self.thread:
      self.thread.join(timeout=2)

# eof

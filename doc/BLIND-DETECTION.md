# Blind and out-of-band detection benchmark

The offline benchmark in `tests/test_blind_detection.py` runs the real payload builders against
three local POSIX shell labs. Each lab exposes one blind channel and deliberately silences the
others:

| Lab | What the target reveals |
|-----|-------------------------|
| `page-oracle` | A page that branches on the command's exit status. `sleep` is a no-op. |
| `time-oracle` | A constant page. A real delay is the only evidence. |
| `oob-only` | A constant page, no delay, and outbound DNS/HTTP clients. |

All three labs have the same fake `nslookup` and `curl` clients. They write the interaction to a
local file instead of contacting a resolver or interactsh server, so the benchmark is deterministic
and needs no network beyond loopback.

## Run it

```
python -m unittest tests.test_blind_detection -v
```

The benchmark test also measures that both out-of-band transports carry command output back:

- HTTP: `curl --data-binary @-` reaches the fake server and the request body is compared with the
  command's output.
- DNS: the numbered hex labels produced by the production DNS payload are reassembled with
  `decode_dns_output()`.

## Detection rates

Detection means the channel produced the evidence its production technique requires: a different
true/false page for boolean-based, the requested delay for time-based, and a fresh proof value in
the interaction for out-of-band. One run per lab and channel:

| Technique | `page-oracle` | `time-oracle` | `oob-only` | Detection rate |
|-----------|:-------------:|:-------------:|:----------:|---------------:|
| Boolean-based | yes | no | no | 1/3 (33.3%) |
| Time-based | no | yes | no | 1/3 (33.3%) |
| Out-of-band DNS | yes | yes | yes | 3/3 (100%) |
| Out-of-band HTTP | yes | yes | yes | 3/3 (100%) |

The first two rows are expected: a channel only sees the evidence it is built to read. The
out-of-band rows show why `--oob` is useful as a fallback when a target returns neither the
command's output nor a usable page difference nor a reproducible delay.

These are offline, capability-isolated lab results rather than a score for any external product or
hosted testbed. They pin the detection logic and make future changes comparable; they are not a
claim about internet-wide detection rates.

## Scan modes

The same test module runs the real CLI against these labs:

- boolean-based over a GET query and a POST body;
- time-based over GET;
- out-of-band HTTP and DNS over GET/POST, after an explicit `--technique=b` selection.

`--oob` alone still selects only out-of-band. When `--technique` or `--type` is given, the switch is
additive: the named techniques run first, and out-of-band follows as the blind fallback.

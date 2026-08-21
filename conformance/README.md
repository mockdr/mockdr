# Conformance harness

Sends one request to mockdr and to the real product, and reports where they
disagree.

This exists because of a defect it would have caught. mockdr 2.0.2 accepted a
Splunk HEC token as `?token=` unconditionally. Real splunkd reads the
parameter but refuses it with `400 code 16` unless `allowQueryStringAuth` is
set, which is off by default — so a client validated against mockdr would have
been rejected by a stock indexer. The documentation does not say this. Only
running the real thing did.

## What it can and cannot cover

Two of the eight mocked platforms can be run at all:

| Platform | Real instance |
|---|---|
| Splunk | ✅ `splunk/splunk`, free trial licence |
| Elasticsearch / Kibana | ✅ Elastic Basic |
| SentinelOne, CrowdStrike, Defender for Endpoint, Microsoft Graph, Sentinel, Cortex XDR | ❌ SaaS only, no self-hostable edition |

There is no OSS stand-in for the other six. Wazuh, Velociraptor and Graylog
are different products with different APIs, not substitutes. Fidelity for
those six rests on published schemas and vendor SDK source, as before.

That is less of a loss than it looks: Splunk and Elastic carry by far the most
API surface mockdr implements — the SPL engine, ES query DSL, aggregations,
and the Kibana Security Solution.

## Running it

```bash
docker compose up -d elasticsearch
# Kibana's service account needs a password before Kibana will start:
curl -u elastic:'Probe-Passw0rd!' -X POST \
  http://localhost:19200/_security/user/kibana_system/_password \
  -H 'Content-Type: application/json' -d '{"password":"Probe-Passw0rd!"}'
docker compose up -d kibana mockdr

python -m harness.runner probes/elastic.yaml \
  --real-auth 'elastic:Probe-Passw0rd!' --mock-auth 'elastic:mock-elastic-password'
```

Exit status is `0` for no findings, `1` for findings, and `2` when a target
could not be reached — because "nothing differed" and "nothing ran" must not
look the same.

### Splunk on arm64

Splunk publishes amd64 images only. Under qemu three things break, in order:

1. `sudo` loses its setuid bit, so the provisioning playbook dies at
   *Gathering Facts*. The compose file runs the container as `root`.
2. `splunk start` then trips over root-owned `var` directories. Run
   `chown -R splunk:splunk /opt/splunk` and start splunkd by hand.
3. `/opt/splunk/etc` ships empty and only the playbook populates it, so
   splunkd cannot be started before the playbook has run.

Expect a five-minute boot. On amd64 none of this applies.

`http-event-collector create` ignores a requested token value and mints its
own; the harness reads the actual one back at bootstrap, which is what
`${hec_token}` resolves to.

## How a difference is judged

Two responses to the same request always differ — ids, timestamps, counts,
versions. Comparing raw bodies would bury one real finding under a hundred
meaningless ones, and a report nobody reads finds nothing.

So the comparison is over a **skeleton**: the status, the significant headers,
the type at each JSON path, and the *values* of the few keys that carry
meaning (`code` and `text` for Splunk, `statusCode` and `error` for Kibana).
Volatile values collapse to markers rather than being dropped, so a gap in the
rules shows up as `<uuid>` where a real value was expected instead of
disappearing.

Four rules keep the noise down, each for a reason:

- **Volatile values are masked.** A UUID differing from a UUID is not news.
- **Array elements collapse onto one `[*]` path.** A seeded mock returns
  twenty rules where a fresh install returns none; the *shape* of a rule is
  the question, not how many there are.
- **An empty array suppresses its element shape entirely.** If one side has no
  elements, the shapes were never compared, and reporting every field as
  missing would be true and useless. Probes needing both sides populated
  declare `needs_seed`.
- **The mount prefix is stripped.** mockdr serves Elasticsearch under
  `/elastic` and echoes that back in error messages. That is an artefact of
  hosting eight products on one port, not a disagreement.

Security headers are deliberately not compared: mockdr sets
`X-Content-Type-Options` where a stock Elasticsearch does not, and that is
mockdr being stricter than the thing it mocks — not a defect to be fixed by
removing the header.

## Findings, ranked

`status` and `value` first, because they are what a client branches on.
`missing_key` outranks `extra_key`: a field the real product returns and
mockdr does not is one a client may read and find absent in production, while
the reverse is merely generous.

## Writing a probe

```yaml
- id: hec-valid-token-query
  endpoint: hec
  why: >
    A valid token by query string is 400 code 16 unless inputs.conf enables
    allowQueryStringAuth.
  request:
    method: POST
    path: /services/collector
    query: {token: "${hec_token}"}
    json: {event: conformance-probe}
```

`why` is read by whoever looks at a finding, so it should say what the request
is trying to provoke rather than restate the path. Probes are weighted towards
**refusals**: a success is usually easy to get approximately right, while
rejections encode the real contract and are where mockdr has been wrong.

Prefer a volatility rule in `normalize.py` over an `ignore_paths` entry. An
ignore that really means "this value is a timestamp" belongs where it applies
everywhere.

## Tests

```bash
python -m pytest tests/ -q
```

These cover the comparison logic and need no running service. The harness
makes claims about mockdr, so its own reasoning is tested: a differ that
under-reports hides defects, and one that over-reports buries them.

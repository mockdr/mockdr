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

## Shapes, and then meanings

Most probes compare the *shape* of a reply: which keys, of which types, under
which status. That works against an empty real install, and it is what finds
a flattened error envelope or a missing `paging` block.

It cannot find a wrong *answer*. A search that matches nothing agrees with
every other search that matches nothing, so semantics stay invisible — which
is how `tail` came to return its rows the wrong way round here, `stats ... by`
to leave its groups unsorted, and `_time` to render as an epoch where splunkd
renders ISO-8601. Each of those passed every structural probe.

`--seeded` closes that. The bootstrap puts the same five events into both
targets' HEC, under a sourcetype unique to the run, and creates
`conformance-seeded` on both Elasticsearch targets with the same six
documents. The probes marked

```yaml
    needs_seed: true
    compare: values
```

then run the same search against both and compare the rows themselves rather
than their skeletons. The fields that belong to the instance rather than to
the API — bucket ids, index times, the server's own name — are listed under
`volatile_fields` in the probe file and dropped before the comparison.

A `compare: values` probe against a body that is *not* JSON — Splunk's CSV —
compares the text as it arrived. `ignore_leading_lines` drops a preamble that
is not an answer; one case needs it, and says so on the probe.

A seeded probe has to establish its own row order: the order splunkd returns
raw events in is a property of how they landed in buckets, not something it
documents. `| sort <field>` before the command under test is enough.

Elasticsearch's seeded probes anchor their windows to the documents rather
than to the clock — `2026-08-03T09:00:00.000Z||/d` resolves to the same
instant on every run, where `now-30d` would stop being true. Two of them use
a `now` bound wide enough to stay true regardless, so the resolver itself is
still exercised.

Two differences are left in place deliberately, both measured and both
recorded in `backend/tests/unit/splunk/test_spl_against_splunk.py`: splunkd's
lazy field extraction, which depends on sourcetype configuration this mock
does not model, and the raw event order above.

## Running it

CI runs the whole harness on an amd64 runner — weekly, on demand
(`workflow_dispatch`), and on pushes that touch the harness or the Splunk
and Elastic mocks (`.github/workflows/conformance.yml`). Locally:

Kibana needs encryption keys or its Cases and Alerting APIs answer every
request with a 500 — "Encrypted Saved Objects plugin is missing encryption
key". `compose.yml` sets them. The first Kibana run without them made every
cases probe a measurement of a broken fixture, which is the failure this
harness exists to prevent on the other side.

Kibana's service account also needs a password, which Elasticsearch does not
set for it: without one Kibana never leaves `unavailable`, and every Kibana
probe then compares the mock against a product that is not running. That was
a manual step here, and it survived unnoticed for as long as a data volume
did — the first `docker compose down -v` took the password with it. The
`kibana-credentials` service sets it now, and the harness refuses to run at
all if Kibana still reports itself unavailable.

```bash
docker compose up -d

python -m harness.runner probes/elastic.yaml
```

Credentials live in each probe file, not on the command line — see
[Credentials](#credentials) for why.

Exit status is `0` for no findings, `1` for findings, and `2` when any probe
could not be run — a target unreachable, or a bootstrap that failed to supply
a placeholder the probe needed. "Nothing differed" and "nothing ran" must not
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

The bootstrap makes one write to the real instance: if the HEC token has no
index allow-list, it sets one (`index=main`, `indexes=main`). Without it the
`hec-incorrect-index` probe compares different fixtures, not different
software — an unrestricted HEC accepts any index name, even one that does
not exist, with `200`, while mockdr's seeded token is restricted. A token
that is already restricted is left alone.

## Credentials

Each probe file declares the user every target recognises:

```yaml
credentials:
  mock: {user: elastic, password: mock-elastic-password}
  real: {user: elastic, password: "${env:ELASTIC_PASSWORD:-Probe-Passw0rd!}"}
```

They are per platform because they are a property of the platform: the user
Elasticsearch recognises is not the one splunkd does. An earlier version took
a single global default on the command line, and running both specs at once
authenticated Elastic with Splunk's user. Both sides then answered 401 —
which compares as *agreement*, and three real findings vanished from the
report. The harness was doing to itself exactly what it exists to catch.

`${env:NAME:-default}` reads the environment at load time, so a spec shares
one password with `compose.yml` without either file copying the other's
literal. A reference with no value and no default is an error at load, not a
401 at runtime.

The mock-side values are mockdr's seeded ones. A test reads the backend's
seeder and auth module as text and fails if they ever diverge, so the harness
stays a separate project while still being held to what mockdr actually
seeds.

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

Choose `significant_keys` for what a client *branches on*, not for what looks
important. Splunk's `type` — `ERROR`, `WARN`, `FATAL` — was left out at first
because it looked like a label; comparing it as "a string" let every
`FATAL`-versus-`ERROR` disagreement through until it was added.

Four rules keep the noise down, each for a reason:

- **Volatile values are masked.** A UUID differing from a UUID is not news.
- **Array elements collapse onto one `[*]` path.** A seeded mock returns
  twenty rules where a fresh install returns none; the *shape* of a rule is
  the question, not how many there are.
- **An empty collection suppresses its element shape entirely.** If one side
  has no elements — an empty array, or `null` where the other side has a
  list — the shapes were never compared, and reporting every field as
  missing would be true and useless. The `null`-versus-array difference at
  the path itself is still reported. Probes needing both sides populated
  declare `needs_seed`.
- **Array elements merge their types.** A path seen as `null` in one element
  and `string` in another reads `null|string`. With a plain overwrite the
  last element won, and a hit that was malformed on one side compared as
  fine.
- **The mount prefix is stripped.** mockdr serves Elasticsearch under
  `/elastic` and echoes that back in error messages. That is an artefact of
  hosting eight products on one port, not a disagreement.

Security headers are deliberately not compared: mockdr sets
`X-Content-Type-Options` where a stock Elasticsearch does not, and that is
mockdr being stricter than the thing it mocks — not a defect to be fixed by
removing the header.

## Measuring against a live product

Ad-hoc measurement against the real containers is how most of this repo's
findings were found, and it is not free of consequence: these are real
products with real state.

**Before sending any request that could write, establish that the refusal you
are measuring precedes the action.** For an unknown query parameter,
Elasticsearch and Kibana and splunkd all refuse before doing anything —
provable in one request:

```bash
curl -u … -XDELETE "$ES/an-index/_doc/an-id?zzzqqq=1"   # 400, unrecognized parameter
curl -u … "$ES/an-index/_doc/an-id"                     # 200, the document is still there
```

That check is cheap and it is not optional. Skipping it once emptied
splunkd's user database: `DELETE /services/authorization/roles/admin` is not
a refusal to measure, it is a deletion to perform, and afterwards every
request to that container answered `No users exist. Please set up a user.`
Recovery is a `user-seed.conf` in `/opt/splunk/etc/system/local` and a
restart, and everything the container had learned since it was built is gone.

Rules that follow from it:

- Aim destructive probing at a throwaway object you create and drop yourself,
  never at the seeded index, the admin user, or anything the harness needs.
  `scripts/es_param_audit.py` makes and drops `mockdr-param-probe` for this.
- A sweep that fills path parameters with a name nothing has is safe only for
  the paths that *have* a parameter. A verb aimed at a collection endpoint
  names nothing to miss, and the product does it: a verb sweep that guarded
  `PUT` and `POST` this way but not `DELETE` sent
  `DELETE /api/detection_engine/index` to the running Kibana, which answered
  200. (It removes the legacy `.siem-signals` index, absent on 8.15, so
  nothing was lost — the guard was still wrong.) Skip every destructive verb
  at a path with no parameter, and count what you skipped in the report, so
  "not asked" cannot read as "agreed".
- Order a sweep so anything destructive runs last. A sweep that deletes the
  index it is iterating over reports every later route as missing — which
  reads as a mock defect and is not one.
- Clean up after a sweep that creates: a HEC token, a saved search, an index.
- Identity and authorisation endpoints are not probing surface at all.
- **One suite at a time against a given target.** Two runs overlapping on the
  same Elasticsearch reported 17 differences that a single run does not have:
  each re-seeds at the start and writes to the seeded index as it goes, so the
  second reads what the first is still changing. The findings look exactly
  like mock defects. If a run is still going, wait for it.
- **The seeded index is not seeded any more once the suite has run.** Two
  dozen probes write to it — `_update`, `_update_by_query`,
  `_delete_by_query`, a stale-`seq_no` write — so afterwards the real side
  holds documents the seed never described. Comparing by hand against that
  state and reading the difference as a defect is easy and wrong: it cost an
  afternoon's conclusion here, which a clean index disproved in one request.
  Make your own index for a hand comparison, or re-run the seeder first.

  The suite's own comparison is unaffected: both targets run the same probes
  in the same order and mutate alike. What it does mean is that one
  *diverging* write shows up again in every probe after it, so findings are
  read in file order and the first one is the one to fix.

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

These cover the comparison logic and need no running service.

## What the numbers mean

Findings are ranked: `status`, `value` and `type` are what a client branches
on; `missing_key` and `extra_key` are shape. Both Splunk (72 probes) and
Elastic/Kibana (57 probes) are at zero of the first kind. The hundreds of
`missing_key` that remain are list endpoints whose real entries carry thirty
to sixty content keys where mockdr's carry a dozen — a gap a client notices
as a `KeyError`, not as a wrong answer. Read a run with that in mind. The harness
makes claims about mockdr, so its own reasoning is tested: a differ that
under-reports hides defects, and one that over-reports buries them.

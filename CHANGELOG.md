# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

The response *shapes* are now measured rather than typed from memory. Every
Splunk, Elasticsearch and Kibana list endpoint is compared key-for-key
against the real product in the conformance harness, and every Sentinel and
Graph resource against the vendor's published specification, fetched from
the internet: the Azure REST API specs (`securityinsights` 2024-03-01 stable,
plus the 2025-10-01 preview for the codeless connector kind) and the official
Microsoft Graph v1.0 OpenAPI metadata. Measured before and after this
release: Splunk 897 missing keys → 0 across 72 probes; Sentinel 276 drift
findings → 0 across 19 routes; Graph 35 → 0 across 49 routes; Elastic and
Kibana 0 across 57 probes.

### Fixed

**Splunk — an entry carried a tenth of the keys a real one does.** A real
saved search has 217 content keys, an index 113, a finished job 67 (with its
`performance` and `searchTelemetry` trees), a role 43, a user 23, the
current context 24, a KV collection 10; the mock had 11, 12, 36, 5, 7, 7 and
3. Each collection is now completed against a fixture captured from
Splunk 10.4.2 (`backend/infrastructure/fixtures/splunk/`), the mock's own
values winning. A client reading any field a real entry has now finds it.
Also measured and fixed: the link relations per collection (a job's nine
sub-resource links including `search_telemetry.json`, a saved search's ten,
an index's five); the ACL members (saved searches and KV collections carry
the four `can_share_*` capabilities, a job's ACL has a string `ttl` and no
`can_list`); `published` on job entries; `paging` absent from `server/status`
and `messages` absent from the job list; top-level links per collection
(`_acl` on saved searches and KV config, none on jobs, current context or
fired alerts); `server/status` itself, which is a collection of seven
sub-resources, not one invented `{"health": "green"}` document; KV
collection config as splunkd's flat `field.<name>` / `accelerated_fields.<name>`
keys, and listable under `/services/` across apps; a wrong password answers
with `code: incorrect_username_or_password` (a missing one does not); the
parser names the field of `dc(host)`/`count(x)` and `timechart` carries its
`seriesfilter: "sum IN top10"`. The job telemetry's timestamps are anchored on
the job's own start, not the capture run's.

**Kibana — `GET /api/features` returned 8 of 33 features.** All 33 of
8.15, captured from the real Kibana.

**Sentinel — every resource now has the shape the spec declares.** Fixtures
are generated from the Azure spec (`scripts/gen_arm_fixtures.py`), one per
resource and per `kind`, and deep-merged under the mock's values, so every
declared property is present with a type-correct default. Measured drift that
this fixed: `systemData` missing everywhere; `kind` inside the property bag
instead of top-level on alert rules and data connectors; alert rule
templates an empty list (now three Scheduled templates with a single-item
route); incident labels as strings instead of `{labelName, labelType}`;
`watchlistItemsCount` and `additionalData.techniques`, which 2024-03-01 does
not declare; no `etag` on a single watchlist item; data connectors in one
invented shape for every kind (now `tenantId` + the kind's own `dataTypes`
tree for the eight stable kinds, and the codeless `connectorUiConfig` for
`GenericUI` as the preview spec declares it); threat-intelligence indicators
without their `kind: indicator` discriminator.

**Graph — five properties v1.0 does not declare, and untyped members.**
`alert_ids` (storage leaking out of `security/incidents`), `isActive` on
service health, `publisherName` on service principals,
`deploymentProfileAssignmentStatus` on Autopilot identities and `result` on
threat assessment requests are gone. `groups/{id}/members` and
`directoryRoles/{id}/members` return each member as its concrete type with
`@odata.type: #microsoft.graph.user` and the user's full default property
set, not an `{id, displayName}` stub.

### Added

- `scripts/schema_drift.py`: compares every mounted Sentinel/Graph route
  against the vendored spec, resolving cross-file `$ref`s (the ARM
  common types), `kind` discriminators scoped to the route's base type,
  `@odata.type` derived types, preview-only definitions, free-form objects
  and empty arrays (neither is drift), and walking parents to find a nested
  collection that is not empty.
- `data/vendor-specs/` is versioned: the reference the comparator and the
  fixture generator run against.
- Two harness probes declare data-dependent paths (a job's `performance`
  profile and the sourcetypes it touched; a KV collection's own field
  schema) as such, with the reason on the line.

**The four EDR platforms, against public references after all.** The
vendor sites gate their specs, but the references exist in the open:
CrowdStrike's `gofalcon` SDK is generated from the swagger and versions
every operation, 200 payload and model (`scripts/gofalcon_spec.py`);
Microsoft's Defender docs are Markdown in `MicrosoftDocs/defender-docs`
with request blocks, property tables and response examples
(`scripts/mde_docs_spec.py`); Cortex XDR has no spec anywhere, but the
XSOAR content pack ships responses recorded from the real product
(`data/vendor-specs/xsoar-samples/`, MIT); SentinelOne's 2.1 swagger, which
`scripts/fetch_swagger.sh` already fetched, is generated from the product's
own response schemas. Each reference is used for what it can prove: an
`omitempty` SDK model only for surplus fields, a recording or a docs
example only for absent ones, the SentinelOne swagger for both. Measured
before → after: SentinelOne 342 → 0 on 31 routes; CrowdStrike 61 → 0 on 23;
Defender for Endpoint 642 → 0 on 30; Cortex XDR 277 → 0 on 20.

- *SentinelOne*: every list and single resource is completed to — and
  restricted to — the swagger's fields (`backend/infrastructure/fixtures/sentinelone/`,
  one per response definition): a user has 33 fields, not 11; `system/info`
  answers `build/patch/release/version`, not an invented
  `serverVersion/buildTime`; agent processes carry `processName`,
  `executablePath`, `cpuUsage`, `memoryUsage`, `startTime` and no
  `pagination`; exclusion scopes are `{tenant, accountIds, siteIds, groupIds}`;
  `activities/types` has its `descriptionTemplate`; a hash verdict is a
  verdict, without an invented `confidence`; cloud-detection alerts lose a
  `agentRealtimeInfo` the schema never had. Twelve routes the 2.1 API does
  not have (`/agents/{id}`, `/threats/{id}`, `/webhooks`, …) are listed by the
  comparator as mock-only.
- *CrowdStrike*: an alert (v2) carried the legacy detection's `behaviors`,
  `hostinfo`, `max_severity`… — gone; users lose `customer`/`roles`; devices
  the retired `slow_changing_modified_timestamp`; PATCHes answer meta-only as
  `MsaReplyMetaOnly` does; the current `/cases/queries/cases/v1`,
  `/cases/entities/case-tags/v1` and `POST …/quarantined-files/GET/v1` paths
  are served. Sixteen routes the current API no longer has (legacy
  `/indicators/*/iocs`, `/incidents/*`, `/alerts/*/cases`) are still served
  and listed as such.
- *Defender for Endpoint*: machines, alerts, vulnerabilities, machine
  actions, software, investigations, indicators and logon users are
  completed from the docs (`fixtures/mde/`): an alert has its `evidence`
  items with 20 fields each, a machine `deviceValue`, `osArchitecture`,
  `version`; `groupName`, `loggedOnUsers` and `agentVersion` were not
  documented machine fields; file statistics carry the global view; domain
  and IP statistics say `organizationPrevalence`, not `orgPrevalence`.
- *Cortex XDR*: replies are completed to the recorded shape
  (`fixtures/xdr/`, one per route): an alert has its `alert_fields`, an
  incident its `hosts`/`users`/`incident_sources`; `quarantine/status` is a
  bare list, not a paged envelope; `insert_cef_alerts` takes CEF *lines* as
  the product does — a string used to crash it with `AttributeError`.

**No more mock-only SentinelOne routes — the UI runs on the real API.** The
mock served twelve routes the 2.1 API does not have (`/agents/{id}`,
`/agents/{id}/passphrase|processes|applications`, `/threats/{id}`,
`/threats/{id}/fetch-file`, `/cloud-detection/alerts/{id}`,
`/hashes/{hash}/reputation`, `/policies`, `/webhooks`) and its own frontend
depended on them, which proved nothing. They are gone: the UI reads single
entities as the product does (`/agents?ids=`, `/threats?ids=`,
`/cloud-detection/alerts?ids=`, `/agents/passphrases|processes|applications?ids=`),
policies through their scopes (`/sites/{id}/policy`, `/groups/{id}/policy`,
`/accounts/{id}/policy`, `/tenant/policy`), the fetched file through
`/threats/{id}/download-from-cloud`; and the outbound webhooks — a mockdr
feature, not a SentinelOne API — live under `/_dev/webhooks` with the rest
of the control surface. Every mounted SentinelOne route now has a spec path
(35 compared, 0 drift).

**Shaking the internet for the rest.** Graph `/beta/` routes are now
judged by the beta metadata (`data/vendor-specs/graph_beta_reduced.json`,
from `microsoftgraph/msgraph-metadata`'s beta OpenAPI). Every Defender
route has a documented reference once the docs' own spelling is honoured
(`/api/Software`, `CreateAlertByReference`, `Delete https://…`, pages without
a `## HTTP request` heading): five routes the docs do not know
(`GET /api/domains/{domain}`, `GET /api/ips/{ip}`, `GET`/`PATCH
/api/indicators/{id}`, `POST /api/investigations/{id}/collect`) are gone,
and the batch delete is served at its documented path
`POST /api/indicators/BatchDelete` with `IndicatorIds`. Cortex XDR gains
three more references, each used for presence only: the endpoint-by-endpoint
OpenAPI transcriptions of the official reference (124 routes, read from a
local clone — the repository carries no licence, so only the derived key
paths are kept), the shared `CoreIRApiModule` recordings of the XSOAR pack
(`rbac/get_users`, `get_user_group`, `alerts_exclusion/*`, …), and reply
shapes read from MIT-licensed connector code, one cited source per route
(`xdr_connector_reduced.json`). Against them: `rbac/*` and
`alerts_exclusion/` answer a bare list in `reply`, not an invented paged
envelope; `alerts_exclusion/add` answers `{rule_id}` and `delete`
`{rule_id: [...]}`; `healthcheck` answers `{status}` without a `reply`
envelope; roles, groups and users carry their recorded fields.

### Known limits

Six Cortex XDR routes have no public evidence of their reply shape at all
(`alerts/update_alerts`, `hash_exceptions/allowlist|blocklist/get`,
`indicators/enable_iocs|disable_iocs`, and the members of `endpoints/delete`);
they stay listed as unjudged. A recording or a transcription proves what a
real reply carries, never what it does not. The CrowdStrike cases model
changed shape in the current API (`OperationsGetCasesByIDsResponseVM`); the
mock still models the legacy shape and does not alias the new create and
update paths.

## [2.0.5] - 2026-08-22

A thoroughness pass before 2.0.5, run with every discovery tool that had
found bugs *after* a release now running *before* one: the full local CI
mirror including e2e and the Docker smoke test, the conformance harness with
four times the probes, hostile-body probing of all 462 routes, parser
fuzzing, and an adversarial review of everything since 2.0.3.

### Fixed

**Crashes — 31 routes answered 500 to a malformed body, now 0.** Every one
was an explicit `null` or `{}` defeating a dict default: one SentinelOne
route, six CrowdStrike, twenty Cortex XDR, and one each for Splunk KV Store,
Sentinel and Graph. Each now refuses in its vendor's 400 envelope. Found by
hostile-body probing; the same pass had found twelve in 2.0.1. Two more
from parser fuzzing: a bare `|` crashed the KQL parser with `IndexError`,
and JSON nested ~20,000 deep escaped HEC's parser as `RecursionError`.

**Splunk — the JSON types were an inference, and it was wrong.** 2.0.1
stringified every job value — `"1"`/`"0"` for booleans, `"5"` for counts —
reasoning from splunklib's `content["isDone"] == "1"`. That comparison is
right for the Atom XML splunklib actually requests, where everything is
text. Measured on Splunk 10.4.2, `output_mode=json` carries real booleans
and integers, on the job list and the single job alike, and
`doneProgress` is the integer `1` once done. Index counts are integers too
— except `currentDBSizeMB`, which is a string. All of it is now as measured.

**Splunk — eight more disagreements measured away.** `/services` does not
exist on splunkd (404; mockdr had invented a catalogue). A verb a collection
does not take is `400 Cannot perform action "DELETE" without a target name
to act on.`, not 405 — the same wording as creating anything without a name.
A missing login password is `400`, not `401`. KV Store refusals are Atom
XML like every other splunkd error, even though its data is JSON-only. The
parser classifies `sort` and `tail` as `events`/`SP_EVENTS` and `dedup` as
`stateful` — three of the guesses 2.0.4 shipped were wrong — carries
`top`/`rare`/`timechart` arguments in their own measured shapes, accepts
`makeresults` and `inputlookup` as generating commands with no phantom
`search` stage, and no longer splits on a `|` inside a quoted string.
`search/jobs/export` accepts POST, which is what splunklib sends. Unknown
saved searches, indexes and users are `Could not find object id=x`; an
unknown fired alert is `Could not find alert savedsearch_id="admin;search;x"`.

**HEC.** `invalid-event-number` is reported as the event is parsed, so a
blank event at position 0 is reported before broken JSON at position 1 —
splunkd streams, and a parse-everything-first mock reported the wrong one.
A top-level JSON array is a batch, not a rejection. A non-numeric `time` is
code 15, `Error in handling indexed fields`, not code 6. An ack query on a
token without acknowledgement is code 14, `ACK is disabled`, before any
channel check. `GET` on the collector is HTTP 405 carrying a body that says
404 — reproduced as measured.

**Elasticsearch — three missing root routes and six wrong exception
types.** `POST /_count`, `/_mget` and `/_bulk` without an index did not
exist. `_mget` on a missing index answered a plain-text 500 where
Elasticsearch answers 200 with the error per document. A negative `size` is
`illegal_argument_exception`, a non-numeric one `number_format_exception`,
a result window past 10,000 a `search_phase_execution_exception` wrapping
it with `failed_shards`, an array body `parsing_exception: Expected
[START_OBJECT] but found [START_ARRAY]`, an unknown top-level key
`parsing_exception: Unknown key for a START_OBJECT in [x].`, an unknown
aggregation type the same `parsing_exception` with `caused_by` that an
unknown query gets. `GET _search?source=` is honoured. A single unknown
path segment is an index name — `400 invalid_index_name_exception` if it
starts with `_`, `404 index_not_found_exception` otherwise — and an unknown
`_cat` verb is a 405 whose `error` is a bare string. The 401 names the user
it refused.

**Kibana — what it refuses, in its words.** A rule with an unknown `type`
is `400 [request body]: type: Invalid discriminator value. Expected 'eql' |
'query' | …`; a rule lookup with neither `id` nor `rule_id` is a 400 whose
`message` is a *list*; deleting by `rule_id` works and an unknown one is
`404 rule_id: "x" not found`. A case, or an exception list, missing
required fields is refused with io-ts's `Invalid value "undefined"
supplied to "field"` per field, in schema order, in the Boom envelope —
mockdr created a case from `{"a":{"b":1}}` with an empty title. An unknown
case status is `Invalid value "x" supplied to "status"`; a patch without
`version` names `"cases,version"`. An endpoint action without
`endpoint_ids` is `[request body.endpoint_ids]: expected value of type
[array] but got [undefined]`. `signals/search` with an empty body is
`"value" must have at least 1 children`. `per_page=0` is accepted.
`/api/features` carries every key Kibana's do — `order`, `catalogue`,
`management`, `alerting`, `subFeatures`, and `privileges` with `api`,
`ui` and `savedObject` — and one feature reports `privileges: null`, as
two of Kibana's do.

**Harness.** `compose.yml` sets Kibana's encryption keys; without them the
real Cases and Alerting APIs answered every request with a 500 and the
harness was measuring a broken fixture. The Splunk bootstrap restricts the
real HEC token's indexes so `hec-incorrect-index` compares like with like.
Probes: Splunk 25 → 72, Elastic/Kibana 11 → 57; `type` is significant for
Splunk messages. The local CI mirror fails when its smoke container cannot
start, on its own port, rather than passing against whatever else held
5001.

### Known gap, quantified

With zero status, value or type disagreements left across 129 probes, the
harness still reports 800 (Splunk) and 97 (Elastic) key-level differences,
almost all `missing_key` on list endpoints: a real saved search, index,
role or job carries thirty to sixty content keys; mockdr's carry a dozen. A
client reading one of the missing keys gets a `KeyError`, not a wrong
value. That is the remaining fidelity work, and it is a different kind.

## [2.0.4] - 2026-08-22

### Fixed

The conformance harness sent sixteen requests to mockdr and to a real Splunk
10.4.2 and reported 135 disagreements. As with Elasticsearch below, every
item quotes what splunkd actually sends.

- **`/services/search/parse` does not exist.** mockdr served it since 2.0.2;
  splunkd has no such endpoint, and `splunklib`'s `Service.parse()` posts to
  `search/parser` (and `search/v2/parser`). Both are served now, POST-only —
  GET is `405` with `Allow: POST`, as on splunkd — and they answer what
  splunkd answers: a **flat object**, not an Atom envelope. `commands` carries
  one entry per stage with its `pipeline` and `streamType`, which is what a
  client reads to decide whether a query can be streamed; `eventsSearch` and
  `reportsSearch` split at the first reporting command. Errors are `FATAL`:
  `Unknown search command 'boguscmd'.` and `Invalid query.`, with splunkd's
  quoting and full stop.
- **`GET /services/server/info` was open to anyone.** The docstring said "no
  auth required for health checks". splunkd answers an anonymous caller
  `401`; its unauthenticated health endpoint is HEC's
  `/services/collector/health`. Thirty-five of the keys splunkd reports were
  also missing — `kvStoreStatus`, `health_info`, `host_fqdn`,
  `numberOfCores`, `physicalMemoryMB`, `startup_time`, `manager_uri` among
  them — and the entry carried `fields` and `edit`/`remove` links that
  splunkd's does not.
- **One 401 envelope where splunkd has two.** A missing or wrong *password*
  is `ERROR "Unauthorized"` with `WWW-Authenticate: Basic realm="/splunk"`;
  a session or Bearer *token* splunkd does not recognise is `WARN "call not
  properly authenticated"` and no challenge. mockdr sent the second shape for
  every failure, so a client that retries on a challenge never saw one.
- **App entries lacked what an app carries.** `can_change_perms` and the
  three `can_share_*` ACL members, `_reload` and `package` links, and seven
  content keys (`configured`, `core`, `show_in_nav`, …). The list does not
  carry `fields`; a single app does. `name` no longer appears inside
  `content` — it is the entry. An unknown app is `Could not find object
  id=x`.
- **Four refusal texts were paraphrases.** An unknown endpoint is `Not
  Found`; an unknown job is `Unknown sid.`; a dispatch with no query is the
  full `The required 'search' parameter for the Splunk platform REST API
  search/jobs endpoint is not specified. …`. A client that string-matches
  the refusal needs splunkd's words.
- **Event-level HEC rejections now carry `invalid-event-number`.** It is the
  zero-based position of the first failing event in the batch — measured:
  `[ok, ok, bad]` reports `2`. Codes 6, 12 and 13 carry it; the auth codes
  do not, because there was no event to point at. Code 7 (`Incorrect
  index`) carries it too, and reports one *higher* than the others for the
  same position — a splunkd quirk a client written against it has adapted
  to, so mockdr reproduces it rather than correcting it.
- **`output_mode` in a form body was ignored.** splunkd honours it in the
  query string or the POST body; splunklib puts every parameter, including
  this one, in the body. mockdr read only the query string, so every SDK
  POST without a query parameter was answered in Atom XML. The harness
  found it the moment a probe sent the parameter the way splunklib does.
- **Message types are not interchangeable.** The search dispatcher answers
  `FATAL` — for an unknown path under `/services/search/`
  (`Unknown endpoint.`), an unknown job (`Unknown sid.`), the parser's
  refusals, and a dispatch with no query — where the rest of splunkd
  answers `ERROR` (`Not Found`). mockdr said `ERROR` for all of them, and
  the harness compared the type as "a string" until it was told the value
  matters.
- **The parser reports what a reporting command will do.** `stats` carries a
  structured `args` — `stat-specifiers` with function and output name, and
  `groupby-fields` — and every report-stage command carries
  `isStreamingOpRequired` and the `preStreamingOp` splunkd runs ahead of it
  (`prestats count by host`, `prehead limit=5 null=false keeplast=false`).

The conformance harness in `conformance/` sent eleven requests to mockdr and
to a real Elasticsearch 8.15.0 and Kibana 8.15.0, and reported 55 ways the
answers differed. After these fixes it reports none. Each item below quotes
what the real product sends, because that — not the documentation — is what
the fix was measured against.

- **`POST /_search` with no index answered 404.** The route did not exist,
  so a search across all indices fell through to the not-found handler — and
  a malformed query body never reached the parser at all, answering
  `resource_not_found_exception` where Elasticsearch answers
  `parsing_exception`. Both routes exist now.
- **`parsing_exception` lacked `caused_by`, `line` and `col`.** Elasticsearch
  reports where in the body the parser stood when it failed — the first
  character of the unknown clause's *value*, not its key — and wraps the
  cause as `named_object_not_found_exception`. The position is found in the
  bytes the client actually sent, so a pretty-printed body reports its own
  layout. The wording is also Elasticsearch 8's `unknown query [x]`; `no
  [query] registered for [x]` was 6.x.
- **`index_not_found_exception` lacked `resource.type` and `resource.id`.**
  They are literal dotted keys, not a nested object, and a client reading
  `error["resource.id"]` to name the missing index found nothing.
- **`WWW-Authenticate` advertised `Bearer` first.** Elasticsearch 8.15 with
  default security sends `Basic realm="security", charset="UTF-8"` then
  `ApiKey`, and no `Bearer` — the token service only advertises itself when
  enabled, which on a stock install without TLS it is not.
- **A missing `kbn-xsrf` header was refused in the wrong envelope.** The
  check is a platform pre-handler that fires before routing, so Kibana
  answers in Boom — `{statusCode, error, message}` — on every route. mockdr
  picked the envelope by path and sent `{status_code}` on detection-engine
  routes.
- **The default space carried fields Kibana omits.** `color: null`,
  `initials` and `imageUrl` are gone; Kibana sends `color: "#00bfb3"` and
  nothing it has no value for.
- **`/api/status` served the full document to anyone.** Kibana answers an
  anonymous caller with only `{"status":{"overall":{"level":...}}}` and
  reserves name, uuid, version and metrics for a known user. `build_flavor`
  is also `traditional` now, which is what a self-managed Kibana 8 reports.

## [2.0.3] - 2026-08-21

### Changed

- **HEC no longer honours `?token=` by default, because splunkd does not.**
  2.0.2 added query-string authentication and accepted it unconditionally.
  Probing a real Splunk 10.4.2 showed that is wrong in a way that matters:
  splunkd reads the parameter, but refuses it with
  `400 {"text": "Query string authorization is not enabled", "code": 16}`
  unless `inputs.conf` sets `allowQueryStringAuth` — which is off by default.
  A client that authenticated this way against mockdr would have been rejected
  by a stock indexer, which is the direction of error a mock must never take.
  `MOCKDR_SPLUNK_HEC_QUERY_STRING_AUTH=true` mirrors the setting.

  The probes also settled an ordering that is not the obvious one: the token
  is validated *before* the channel is checked, so an invalid token sent by
  query string is a `403 code 4`, and only a *valid* one ever reaches the
  `400 code 16`. mockdr now reproduces all eight measured cases exactly.

- **Credential-bearing query parameters are masked in the request audit log.**
  The `Authorization` header was already reduced to its last four characters,
  but Splunk HEC accepts its token as `?token=` — so the very credential that
  masking protects was kept verbatim one field over, and `/_dev/requests`
  served it back. Parameter names stay readable, since what was sent still has
  to be diagnosable from the log; only the values are reduced. This is
  hardening, not a fix: `/_dev` is admin-gated and publishes tokens through
  `/_dev/tokens` by design, so nothing was reachable here that was not already
  reachable more directly.

### Fixed

A code review of the 2.0.2 work found eight routes answering `200` with
something untrue. Every one is the failure mode this project exists to expose
rather than manufacture, so every one now has a test that fails loudly if it
returns.

- **`_import` never read the request body.** It reported
  `success: true, success_count: 0` for any input, so a client could export
  its rules, import them into a fresh instance, be told it had worked, and
  find nothing there — the export/import round trip a migration check exists
  to prove was confirming a success it had not performed. It now parses the
  NDJSON (raw or multipart, since Kibana's UI posts a file and scripted
  clients post the body), creates each rule, reports a `409` per conflicting
  `rule_id` unless `overwrite=true`, and skips `_export`'s trailing summary
  line rather than counting it as a rule.
- **A finalized search job went on reporting `QUEUED`.** `dispatchState` was
  derived from elapsed time on every read, which overwrote whatever a control
  action had just set, so with a dispatch window configured `finalize` and
  `cancel` appeared to do nothing. A job whose state a control action fixed
  now reports that state.
- **`touch` sent a running job backwards.** It reset the same timestamp the
  lifecycle clock reads, so touching a job rewound it from `RUNNING` to
  `QUEUED`. Real Splunk's `touch` extends the TTL and leaves the search alone;
  the TTL countdown now has its own field.
- **A paused job kept running, and reported itself done.** Its clock now stops
  while it is held and resumes where it stopped, and it reports `isDone: 0` —
  a paused job has not finished.
- **`/api/detection_engine/privileges` named the wrong user.** It read
  `username` from an auth context that spells it `user`, so every caller was
  reported as the built-in `elastic` superuser regardless of who authenticated
  — including a `viewer`, whose actual privileges the same response then
  correctly reported as read-only.
- **`_bulk_create` rejected `risk_score: 0`.** A falsiness check reported a
  supplied `0` as `Invalid value "undefined"`, so a rule the client did send
  read as one it had omitted. Required fields are now checked for presence.
- **`/api/spaces/space/{id}` returned the default space for any id.** An
  unknown space read as success, so a typo or a deleted space sent the client
  on to write into the wrong one. Unknown ids are now `404`.
- **`action_status` filed every pending action under `isolate`.** A pending
  `kill-process` was reported as a pending isolation. Counts are now per
  action, as Kibana reports them.
- **`action_log` documented newest-first and served oldest-first.** It handed
  back repository insertion order, so page 1 held the stalest entry — the
  reverse of what an operator checking "what just happened" needs.
- **`/api/exception_lists/summary` answered without a `list_id`.** All-zero
  counts with a `200` were indistinguishable from a list that genuinely has
  no items; a request with nothing to summarise is now a `400`.

## [2.0.2] - 2026-08-20

### Added

- **22 endpoints that had no route at all.** These sit around the ones mockdr
  already served: a client reads the tag vocabulary before offering it as a
  filter, checks privileges before showing a create button, pulls a case's
  audit trail, lists the actions run against an endpoint. Each returned 404,
  so the surrounding workflow could not be exercised even though its central
  endpoint worked.
  - *Splunk:* `/services`, `/services/apps/local`, `/services/messages` and
    `/services/search/parse` — the last is what `splunklib`'s `Service.parse()`
    uses to validate a query without dispatching it, so it reports an
    unrunnable query as an error rather than accepting it. Plus KV Store
    `batch_find`, and HEC now accepts its token as `?token=` for clients that
    cannot set headers.
  - *Kibana platform:* `/api/status`, `/api/features`, `/api/spaces/space` and
    `/api/fleet/agents`, the last derived from the same endpoints the metadata
    API serves so the two inventories agree.
  - *Detection engine:* tags, privileges, index, `rules/_bulk_create` (which
    reports per rule rather than failing the batch), `rules/preview`,
    `_export` and `_import`.
  - *Cases:* status counts, reporters, `_bulk_get` (which separates hits from
    misses), and `{id}/user_actions`.
  - *Endpoint:* `action_log/{id}`, `action_status`, `policy_response`,
    `suggestions` — and the four response actions are now also served at
    `/api/endpoint/{action}`, which is where Kibana serves them; the mock had
    them only under `/api/endpoint/action/{action}`, the listing path.
- **`MOCKDR_SPLUNK_DISPATCH_SECONDS` makes a search job's dispatch states
  observable.** The search runs synchronously, so a job reported `DONE` on the
  first poll and `QUEUED`, `PARSING`, `RUNNING` and `FINALIZING` were
  unreachable — a client's `isDone` polling loop was never exercised, only
  short-circuited. Setting a window walks the job through those states over
  that many seconds. The default of `0` keeps the immediate, deterministic
  behaviour, and `exec_mode=blocking` still returns done, as real Splunk does.
  Results are readable at any state, since the search has in fact already run.

### Changed

- **Dependency majors taken deliberately rather than one Dependabot PR at a
  time:** mypy 1.19 → 2.3, Vite 7 → 8, ESLint 10.0 → 10.8, vue-tsc 3.0 → 3.3,
  Playwright 1.58 → 1.62, uvicorn 0.41 → 0.52, ruff 0.16.2 → 0.16.4,
  pip-audit 2.10.0 → 2.10.1, pytest-asyncio 1.3 → 1.4, @vue/tsconfig 0.9.0 →
  0.9.1. Both new majors were clean: mypy 2.3 reports no issues across 781
  files under `--strict`, and all 9 end-to-end flows pass on Vite 8.

### Fixed

- `_export` returned a `str` while it was being written, so FastAPI
  serialised the NDJSON as one escaped JSON string that `_import` could not
  read. Both endpoints are new in this release; the round trip works.
- The endpoint metadata list took only `per_page` where Kibana sends
  `pageSize`. Both spellings are accepted now.
- The Splunk end-to-end check read `E2E_BASE_URL` — which points at the
  *frontend* — to reach the backend, so overriding the frontend URL sent the
  request to the dev server, which answers every unknown path with the SPA's
  index.html. The backend now has its own `E2E_API_URL`.

## [2.0.1] - 2026-08-20

Eight audits of every mocked platform against first-party sources — vendor
docs, published OpenAPI/Swagger, and in most cases the vendor's own SDK and
server source — produced roughly 200 findings. This release closes the
substantial majority.

Almost none were crashes. They were `200`s carrying the wrong thing, which is
the failure mode a mock exists to expose rather than manufacture: a client
cannot tell it is being lied to, so the bug surfaces later, against production.

**Read the Changed section before upgrading.** Several responses now use the
field names the real vendors use. A client written against mockdr's previous
output will need updating; a client written against the real API will start
working.

### Security

- **`GET /users/{id}/api-token-details` no longer returns the token itself.**
  Any authenticated caller could read the administrator's credential and act
  as them. S1's own `ApiTokenDetailSchema` declares exactly `createdAt` and
  `expiresAt`.
- **Graph write routes enforce the writer role.** `require_graph_write` existed
  and was correct but was attached to nothing, so the documented "reader is
  read-only" was never implemented — a reader could send mail and post to
  Teams.
- **Tenant scoping applies on every list endpoint.** The middleware appended
  `accountIds=<caller's account>` and each endpoint declared a matching filter,
  but six of seven routes never declared the parameter, so it was dropped
  before the handler saw it and a confined caller was served the whole store.
- **A role change takes effect immediately.** Authorisation reads the role from
  the token record, which was written once at token creation and never
  revisited, so a demoted user kept every privilege of their old role.
- **A quadratic regular expression in the Graph `$filter` lambda parser is
  bounded.** A 32 KB filter took 2.8 s to reject; it now takes 0.6 ms.
- Agent actions are scoped to their filter. A body scoped by `groupIds` matched
  nothing and fell through to *every* agent, reporting success.

### Changed

- **Elastic Security alert documents are ECS.** `host.name`, `@timestamp`,
  `process.pid`, `file.hash.sha256`, with rule metadata under
  `kibana.alert.rule.*` or `signal.rule.*` by index. The previous flat
  snake_case names exist in no cluster, so a query written against a real one
  matched nothing — and the two index families returned byte-identical
  documents despite different schemas.
- **Defender resources are addressed by `id`.** `machineId`, `alertId`,
  `actionId`, `investigationId` and `indicatorId` were the primary keys where
  every real resource uses `id`. Foreign keys are unchanged: an alert still
  carries `machineId`.
- **Kibana list envelopes differ per API, as they do in Kibana.**
  `rules/_find` returns `perPage` (the *request* parameter remains `per_page`),
  `cases/_find` names its collection `cases` and carries per-status counts,
  case objects declare `totalComment`/`totalAlerts`, and `endpoint/metadata`
  returns `pageSize` with entries wrapped in `metadata`/`host_status`/
  `policy_info`.
- **Splunk renders values as splunkd does.** Search results are strings — or
  lists of strings — and job status fields are `"1"`/`"0"`. `splunklib`'s
  `Job.is_done()` compares `content["isDone"] == "1"`, so the SDK's documented
  polling loop previously never terminated.
- **Case updates go through `PATCH /api/cases`** with `{"cases": [{id,
  version, …}]}`, the endpoint Kibana actually exposes. `PATCH
  /api/cases/{id}`, which exists in no Kibana, is gone. `version` is required
  and a stale one is a `409`.
- `GET /agents/count` returns `data.total`, as S1's `AgentsCountSchema_200`
  declares, rather than `data.count`.
- Cortex XDR reports scripts as `script_uid`; CrowdStrike alert updates read
  `action_parameters`.
- Creating a Splunk index or saved search returns `201`, and a duplicate name
  is `409` instead of silently overwriting.
- Seed data is reproducible. Ids came from `secrets.randbelow` and `uuid4()`,
  neither of which can be seeded, so every id changed on each restart despite
  the seeder documenting determinism.

### Added

- **A working SPL pipeline.** Commands run in the order written, with one
  expression grammar behind `search`/`where`/`eval` supporting AND/OR/NOT,
  parentheses, real comparison operators and wildcards, plus `stats`, `dedup`,
  `top`, `rare`, `fields`, `timechart`, `rex`, `regex`, `fillnull` and `sort`.
  Unrecognised commands are reported in the job's `messages`.
- **Advanced Hunting evaluates KQL** over five tables projected from the same
  seeded data the REST endpoints serve, so a hunting result cannot contradict
  `/api/machines`.
- **Elasticsearch aggregations** — terms, date_histogram, histogram, range,
  filter, filters, cardinality, value_count, min/max/sum/avg/stats and
  top_hits, with sub-aggregations — plus `_count`, `_mget`, `_cat/indices`,
  `_cat/health`, `_cluster/health`, `_security/_authenticate`, `GET _search`,
  and `PUT`/`DELETE` on `_doc`.
- **The Splunk job API is served under both v1 and v2**, and
  `/servicesNS/{owner}/{app}/` reaches every endpoint — `splunklib` rewrites
  every path to that form as soon as a namespace is set.
- KV Store `query`, `fields`, `sort`, `limit` and `skip`; S1 `sortBy`,
  `sortOrder` and `skip`; Kibana `cases/_find` `severity`, `search`,
  `reporters`, `sortField` and `sortOrder`. All were documented and all were
  dropped before the handler ran.

### Fixed

- **A snapshot written by a different schema version no longer destroys the
  store.** Affected records were silently dropped and the next mutation
  overwrote the good file; 60 agents became 0, unrecoverably. Lossy snapshots
  are quarantined instead. A snapshot whose top level was not a JSON object
  crashed startup outright.
- Six composite-keyed Graph collections restored under bare ids, so
  `GET /users/{id}/messages/{id}` returned `404` after a restart while row
  counts looked unchanged. Collected-file bytes were mangled by the JSON
  encoder and skipped on import. Nine collections — OAuth tokens, Splunk
  sessions, in-flight search jobs — were registered nowhere and vanished on
  restart, leaving clients holding credentials the server had never issued.
- Elasticsearch `_id` was a fresh UUID per response, so search → get-by-id
  could never round-trip, and `POST _doc` acknowledged a write it never
  performed.
- A keyset cursor on a non-unique column never advanced, so paging the
  firewall rules looped forever on the same page.
- `$filter` and `$orderby` on Sentinel read the whole expression: only the
  first clause was matched, so `and`/`or` were ignored, and `properties/x`
  ordering silently did nothing.
- Twelve request bodies and query shapes that returned a plain-text `500` —
  indistinguishable from the service falling over — now answer their vendor's
  `400`. Probing every route with hostile input finds no `5xx` at all.
- Seeded records reference data that exists: STAR rules, CrowdStrike
  `detect_ids`, `exposedMachines` against `machineReferences`, managed-device
  users, Graph licence seat counts, and 34 records whose "updated" timestamp
  preceded their own creation.
- The EDR→SIEM bridge subscribed to ten event types and three were published;
  agent activity, Defender machine changes and XDR alert inserts now reach the
  SIEMs.
- Four call sites iterated the store's live dictionaries outside its lock, so a
  read racing a concurrent write raised `RuntimeError`.

## [2.0.0] - 2026-08-14

First tagged release since the project was opened up; `v1.0.4` pointed at the
initial commit. The major bump reflects two behaviour changes rather than a
rewrite: an unparseable OData `$filter` is now refused instead of quietly
returning the wrong rows, and the UI moved to Tailwind CSS v4.

### Security

- Dependency advisories published since the last refresh are cleared:
  `python-multipart` 0.0.22 → 0.0.32 (PYSEC-2026-3036/3037/3038/3039/3040) and
  `pytest` 9.0.2 → 9.0.3 (PYSEC-2026-1845), plus transitive frontend bumps of
  `form-data`, `nanoid`, `picomatch`, `postcss` and `yaml`. `pip-audit` and
  `npm audit` both report zero vulnerabilities.
- Splunk index creation, HEC token management and KV Store collection
  management now require an administrator role. `require_splunk_admin` existed
  but was never applied, so the seeded `viewer` could create indexes and mint
  HEC tokens. `sc_admin` counts as an administrator, as it does in Splunk Cloud.

### Added

- OData `$filter` supports `endswith(field,'value')`, which real Graph serves
  and mockdr previously rejected.
- Unquoted `true`, `false`, `null`, `Edm.Guid` and ISO-8601 date/time literals
  are recognised in `$filter`, as OData v4 writes them.
- EDR→SIEM bridging is live (ADR-009): the Splunk and Sentinel bridges are
  registered at startup and EDR mutations publish to the event bus, so a
  Defender alert or a triggered scenario now appears in the SIEMs. Both bridges
  and the bus were previously unreachable code.
- MDE list endpoints support `$count=true`, returning `@odata.count`.

### Changed

- **An unparseable or unsupported OData `$filter` returns `400` instead of
  being partly ignored.** Input the parser could not read used to be skipped,
  which *widened* the filter — `$filter=@@@` returned every record with a
  `200`, and a stray paren silently dropped the rest of the expression.
  Unsupported-but-valid syntax (`not`, `in`, nested functions) previously
  raised and surfaced as `500`. Both now answer `400` in the vendor's error
  envelope, matching Defender and Graph. No filter that worked before stops
  working.
- **The UI is built with Tailwind CSS v4.** Tailwind's default palette moved to
  OKLCH, so built-in colours (`text-green-400` and friends) render slightly
  more vivid; a 13-page screenshot comparison found 12 pages byte-identical and
  the custom `s1-*` palette unchanged.
- The version is defined once per workspace — `config.APP_VERSION`,
  `pyproject.toml` and `package.json` — and the sidebar footer reads it at
  build time instead of hardcoding a string. The five sources previously
  disagreed. A unit test now fails if they drift apart.
- Dependencies refreshed: FastAPI 0.141.1, faker 40.36.0, ruff 0.16.2,
  pytest-cov 7.1.0, pre-commit 4.6.2, vue-router 5.2.0, lucide-vue-next 1.0.0,
  jsdom 30.0.1 and `@types/node` 26.2.0.
- The Graph, MDE and Sentinel token endpoints return OAuth 2.0 errors —
  `{"error": "...", "error_description": "AADSTS...", "error_codes": [...]}` —
  instead of the OData envelope of the API they sit in front of. MSAL and other
  OAuth clients read those keys.
- `GET /graph/v1.0/me` returns `400 Request_BadRequest` under app-only
  authentication, as real Graph does, instead of returning the first seeded user.
- Splunk endpoints now answer in Atom XML unless `output_mode=json` is
  requested, as splunkd does. HEC still always answers JSON.
- Sentinel management-plane requests now require `?api-version=`, as Azure
  Resource Manager does. The Log Analytics query endpoint is unaffected.
- Graph `$count=true` now requires `ConsistencyLevel: eventual` instead of being
  answered regardless.

### Fixed

- `contains()` and `startswith()` in an OData `$filter` returned `500` on every
  call, on both MDE and Graph — the tokeniser consumed the opening paren as
  part of the function token and the parser then demanded it again. These are
  the forms the XSOAR MDE integration and Microsoft's Graph documentation lead
  with. Graph imports the parser from MDE, so one defect reached both.
- `and` bound *looser* than `or` in an OData `$filter`, inverting the
  precedence OData specifies: `a and b or c` evaluated as `a and (b or c)`, so
  records matching only the `or` arm were dropped. The parser builds a tree
  rather than a flat clause list, and parentheses nest correctly.
- `accountEnabled eq true` matched nothing and `ne true` matched everything —
  unquoted keywords were compared as strings against `str(True)`, i.e. `"True"`.
- Unquoted timestamps were truncated to their year, so `createdDateTime ge
  2026-08-08T00:00:00Z` compared against `2026` and answered far more coarsely
  than asked. Unquoted GUIDs were shredded the same way.
- A doubled quote — OData's escape for a literal one — ended the string, so
  `startswith(displayName,'O''Brien')` matched every name starting with `O`.
- Deeply nested parentheses raised `RecursionError` and surfaced as `500`,
  reachable from a short query string. Nesting is capped.
- Every in-repo caller of the Sentinel operations endpoint omitted the
  `api-version` parameter that ARM enforcement had just made mandatory,
  including the UI's health check, which returned `400` at runtime. The test
  fixture supplied the parameter automatically, hiding it from the suite.
- `apply_graph_filter` leaked its synthetic `_lambda_*` keys into the caller's
  records when a filter failed to parse; cleanup now runs unconditionally.
- Cortex XDR advanced authentication now uses the documented scheme —
  `SHA256(key + nonce + timestamp)` over the plain concatenation — instead of an
  HMAC over `nonce:timestamp`, which rejected every client built to Palo Alto's
  specification. Standard authentication (the API key in `Authorization`) is
  supported as well.
- Request-validation failures are returned in the mocked vendor's error envelope
  with the status that vendor uses, instead of FastAPI's `422 {"detail": [...]}`,
  which no mocked API emits.
- `POST /mde/api/indicators` now rejects a body missing `indicatorValue`,
  `indicatorType`, `action` or `title` with `400 BadRequest` instead of creating
  an indicator with empty fields.
- Authorization scheme names are matched case-insensitively for Sentinel and
  Splunk, per RFC 7235.
- Splunk accepts a session key in its own `Authorization: Splunk <key>` scheme,
  not only as `Bearer`.
- Graph reports a missing resource with the code its sub-API uses:
  `Request_ResourceNotFound` for directory objects, `ErrorItemNotFound` for
  Outlook mail, `itemNotFound` for drive items and `notFound` for the security
  API.
- A state snapshot now covers every seeded collection. Graph, Sentinel, Splunk
  and hash exceptions were absent from the registry, and because loading a
  snapshot skips seeding, restarting with `MOCKDR_PERSIST` left those vendors
  permanently empty. A coverage test now fails if a new collection is missed.
- Sentinel rejects a `$skipToken` it did not issue with `400 InvalidSkipToken`
  instead of raising `ValueError` and returning a 500, and `nextLink` is now the
  absolute, followable URL ARM returns rather than a bare `?$skipToken=`.
- `POST /iocs/bulk` accepts a single indicator sent as an object instead of
  silently discarding it and reporting success.
- Activity records evicted from the bounded order deque are deleted with it, so
  `count()` and `list_activities()` no longer diverge past 10,000 activities.
- The Webhooks UI reads `eventTypes` and `createdAt`, the field names the API
  actually returns; it previously read snake_case and threw while rendering.
- `frontend/.env` is created from `.env.example` by `start.sh` and the Docker
  build. Vite inlines `VITE_*` at build time, so without it every vendor client
  in the UI authenticated as `undefined`.
- `xdr_api_key_repo.get_by_key_id` is a single dict lookup instead of rebuilding
  an index on every call, matching what its docstring already claimed.

- Graph, MDE and Sentinel token endpoints now accept the tenant-scoped URL real
  Entra ID uses (`/{tenant}/oauth2/v2.0/token`) in addition to the bare path, so
  clients that mirror the Microsoft authority shape no longer fall through to
  the SPA catch-all and get a misleading `405 Method Not Allowed` ([#22]).
  Like Entra, the segment accepts the tenant GUID or a verified domain name; a
  tenant that matches neither is rejected with `400 invalid_request`
  (AADSTS90002). Set `MOCKDR_STRICT_TENANT=false` to accept any tenant.

[#22]: https://github.com/mockdr/mockdr/issues/22


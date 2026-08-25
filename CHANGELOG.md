# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

**Refusals a client of that vendor could not parse.**
The hostile probe asks whether a route crashes. `scripts/error_envelope_audit.py`
asks the quieter question beside it: when a route *refuses*, does it refuse
in the vendor's own envelope? A client parses errors with one parser —
`errors[0].message` for Falcon, `error.code` for Graph, `reply.err_msg` for
Cortex, `messages[0].text` for splunkd — and a refusal in some other shape
looks fine in a browser while breaking every integration that inspects it.
2 083 refusals swept across every route.

* **A summary of an exception list that does not exist was a plain-text
  500.** The list route answers 404 for the same id; the summary route let
  the not-found straight out. The hostile probe had never seen it, because
  it sends *malformed* values and this needs a well-formed id that resolves
  to nothing — which is the commonest thing a client sends.
* **Deleting a document that is not there answered three of the seven
  members Elasticsearch sends.** A delete that finds nothing is answered
  with the *document* envelope and a 404, not an error object — `_version`,
  `_shards`, `_seq_no` and `_primary_term` beside `result: "not_found"`
  (measured on 8.15). A client doing optimistic concurrency reads exactly
  those, and found them missing on the one path where it matters.

Three shapes the audit had to be taught, each already pinned by a test or
measured here: HEC refuses in its own shape rather than splunkd's,
Elasticsearch's 405 carries a bare string where every other status carries
the nested object, and a delete's 404 is not an error envelope at all.

**Filters that travel in a body, and the two that could only ever answer nothing.**
`scripts/filter_effect.py` asks of every body-side filter what
`param_effect.py` asks of every query parameter: does it do anything? That
blind spot is not small — Cortex XDR is a POST-only API whose every list
route filters through `request_data.filters`, and Elasticsearch's whole
query language is a body. It cost nine of Cortex's thirteen endpoint filter
fields, found earlier in this release by writing and reading back rather
than by asking directly.

Each filter is exercised in **both** directions, because one is not enough:
a value nothing can match must answer empty, and a value a record holds must
not — a filter that refuses everything passes the first test while being
just as broken. A field mapped onto a record key nothing holds has no value
to test with, and is reported for exactly that: it can only ever answer
nothing.

Which is what `dist_name` and `public_ip_list` were doing. Cortex serves
`installation_package` and `public_ip` on every endpoint and filters on
both; mockdr had them as fixture defaults only, never on the record, so the
two filters accepted a value and answered nothing. Both are now on the
endpoint and seeded.

62 filters across the two dialects, and the tool was checked against a
deliberately broken filter before its clean run was believed.

**Where each Splunk entry lives.**
An entry's `id` says which app owns it and under which user, and splunkd
spells that in the id itself: `/servicesNS/{owner}/{app}/{collection}/{name}`
for anything that lives in an app, `/services/{collection}/{name}` for what
the instance owns. mockdr rendered every id in the plain form. Both are
reachable — the namespace middleware rewrites one to the other — so a client
that *follows* the link worked either way; one that parses owner and app out
of it, as splunklib's `Entity.path` does and as any tool deciding where to
write a change back must, found neither.

Measured by reading one entry from each of the 28 collections mockdr serves,
which is what the note left in `probes/splunk.yaml` at 2.3.0 was waiting
for. The rule turned out to be simple: **the id is namespaced exactly when
the entry's own ACL names an app** — and it comes from the ACL, not from the
request path, so asking for an index under `/servicesNS/nobody/search/…`
still answers `/servicesNS/nobody/system/…`, because that is where the index
lives. `search/jobs` is the one measured exception: a job's ACL names the
user and app it ran in, and its id is still plain.

Deriving the id from the ACL meant the ACLs had to be right, and eleven
collections' were not: users, roles, capabilities, the server's own
description and the KV store status all claimed to live in the `search` app
under `nobody`, where splunkd reports them owned by `system` with no app at
all. Knowledge objects — macros, saved searches, event types, source types,
lookups, HEC tokens — carry four more ACL members saying who may re-share
them, and now do; a configuration object such as an index carries none of
the four, and no longer does either. Six probes compare it against the real
product.

One correction to the `f` filter added earlier in this release: splunkd's
job endpoint has a handler of its own and ignores `f` outright, answering
all 65 content keys whatever is asked for. The middleware now leaves it
alone rather than narrowing where the product does not.

**And the mistake in the other direction: writes nobody checked the caller for.**
`scripts/authz_audit.py` asks all 247 write routes whether a credential
without the right to them is answered 2xx — with no credential at all, and
with the read-only one each vendor issues. A mock that permits what the
product refuses is as misleading as one that loses data: a playbook tested
against it learns nothing about the 403 waiting in production.

Two Splunk routes took a write from anyone who could log in. Measured on
10.4.2: a `power` account posting to `receivers/simple` is answered 200 and
a plain `user` account 403, with a `WARN` message that names no capability —
not the management refusal, which names `admin_all_objects`. So the plain
user role now reads and does not ingest, and the same guard covers
`notable_update`, which Enterprise Security gates on `edit_notable_events`.

Two routes the audit flagged are deliberately open, and it now says so:
starting an XQL query runs a search, which Cortex's viewer role may do, and
`/_dev/webhook-sink` is mockdr's own — the sink a delivered webhook is
posted *to*, whose sender is a webhook and not a client with a credential.

**What Splunk and Kibana actually answer to a write, measured.**
The round-trip audit reached the two products `conformance/` can run, so
the answers were compared rather than reasoned about.

* **Creating a Splunk index kept the name and dropped every setting beside
  it.** An index made with `maxTotalDataSizeMB=12345` read back as the
  default 500000. It now keeps what it was given, typed as splunkd types it
  (a number here, a string for `maxHotBuckets`), derives `homePath`,
  `coldPath` and `thawedPath` from the name, and **refuses an argument it
  does not know** — `Argument "x" is not supported by this handler.` — from
  the 89 the handler accepts, recorded from `data/indexes/_new`. There was
  also no way to *edit* an index: `POST` to a member's own URL, which is how
  splunkd edits anything, answered 405. Deleting one answers with the
  collection as it now stands, as splunkd does, not with a message.
* **Every index looked the same, whether splunkd owned it or a client made
  it.** `main` and the `_`-prefixed indexes are `system`-owned and not
  removable, and splunkd offers no `remove` link for them; one created
  through the API is app-level and removable. The mock reported all of them
  as removable, and offered a link splunkd would refuse. The entry's
  `fields` block was three empty lists, where splunkd lists the 80 settings
  the index takes.
* **`f`, the parameter that narrows an entry to the fields you asked for,
  did nothing on any Splunk route.** It is the REST framework's, not one
  collection's: repeatable, wildcarded (`f=max*` selects the eighteen
  `max…` settings of an index), and a name matching nothing leaves `eai:acl`
  alone. A new middleware applies it wherever the paging middleware applies
  `count` — which is what made comparing an index's *values* across two
  installs possible at all.
* **Kibana answers a case-comment write with the case, not the comment.**
  The mock answered with the comment, so a client reading the answer as a
  case found none of its fields. Deleting a comment is 204 with no body, and
  answered 200 with the JSON literal `null`. `GET /api/cases/{id}` fills
  `comments`, which the mock always left empty even for a case it had just
  had a comment added to — while `_find` leaves it empty and reports
  `totalComment`, which is the distinction the mock had collapsed.
* **Every case and comment claimed to have been edited the moment it was
  made.** `updated_at` and `updated_by` are null until something changes
  them. The user object is `{email, full_name, username}`, all three
  present; the mock wrote an invented `"Elastic Admin"` into `full_name` and
  left `email` out.

The harness now seeds a case with a comment on both targets, so a comment
write is comparable at all: three probes on the elastic side, five on the
Splunk side, and one difference deliberately left standing and documented
in `probes/splunk.yaml` — splunkd renders entry ids in the namespaced
`/servicesNS/{owner}/{app}/…` form, and imitating that means measuring the
owner and app of some thirty collections.

**Writing something, and asking for it back.**
`scripts/roundtrip_audit.py` is the first audit here that writes. Every
other one reads, and a mock that only ever answers reads can look right in
each single answer while forgetting what it was told: a create that drops
half the body and returns defaults, an update that answers 200 and changes
nothing, a delete that answers 200 and leaves the record in the listing.
All three are 200s, and a client that never re-reads never sees them.
Twenty-five cycles now write, read back, list, change, delete and check the
record is gone — across all nine mounts.

What it found, and what was fixed:

* **CrowdStrike read two write bodies one level flatter than Falcon
  documents them.** `HostGroupsCreateGroupsReqV1` is a *collection* —
  `{"resources": [{name, group_type, …}]}` — and the route read the group
  from the top level, so the documented body created a group named `""` and
  answered 200. The same for the update. Both now take the collection,
  create or change every member of it, and refuse a body without
  `resources` or a member without its required fields. The evidence is now
  in the repository: `scripts/gofalcon_spec.py` records what each write
  route *accepts* (`request`, `request_paths`, `request_required`), which no
  comparator here held before — `param_drift` covers query parameters and
  nothing covered bodies.
* **`iocs/entities/indicators/v1` updated only the first indicator** of the
  list it was sent, and answered 200 for all of them.
* **`GET /devices/queries/host-groups/v1` and
  `/devices/queries/host-group-members/v1` were missing.** The query
  function for the first already existed; only the route to it did not.
* **Graph's `tiIndicator` carried two properties Microsoft has never had.**
  The observable was stored as `indicatorValue`/`indicatorType`, so a client
  sending the documented `domainName` got a 201 and lost it, and one reading
  `fileHashValue` found nothing. The type now carries the 58 properties
  Graph declares. The reference took some finding: Microsoft retired
  `tiIndicator` from v1.0 and removed the type from the v1.0 metadata with
  it, while the route stays reachable and playbooks written against it keep
  calling — so `scripts/graph_csdl_spec.py` reduces the beta CSDL, and takes
  a root set so that vendoring one type does not vendor six thousand.
* **Cortex XDR ignored nine of the thirteen endpoint filter fields it
  publishes.** `endpoint_id_list`, `group_name`, `alias`, `username`,
  `dist_name`, `public_ip_list`, `isolate`, `first_seen` and `last_seen` all
  fell through a hand-written loop, so a client narrowing to one endpoint
  was handed the whole estate — the quietest failure a mock has. Endpoints
  now use the same filter engine as alerts and incidents, which refuses a
  field it does not know rather than ignoring it.
* **Three Cortex writes named their target with a key the API does not
  have.** `update_agent_name` read `endpoint_id` where Cortex sends
  `filters`, and answered 500 to every documented request. The tag routes
  read `endpoint_ids` where Cortex sends `context.lcaas_id`, tagged nothing,
  and answered with two members Cortex's own reply does not carry; the tag
  now lands on the endpoint and reads back in `endpointTags`.
  `update_incident` dropped `manual_severity` and `resolve_comment` —
  the analyst's overrides — while answering `true`.
* **`hash_exceptions` read `hash_list` as a list of objects.** It is a flat
  list of SHA256 strings with `comment` beside it, so the documented body
  reached `"…".get("hash")` and became a plain-text 500. A malformed value
  is now the 400 it should be.
* **Sentinel's watchlist item write handed back its own bookkeeping key.**
  A client that sent two columns got three, `_key` among them.

**A paging audit, and the two collections that could not be walked.**
`scripts/paging_audit.py` walks every collection a page at a time and asks
whether the whole of it came back exactly once — no duplicate, no gap, a
total that agrees with the pages, and paging that terminates. A mock that
pages wrongly looks right in every single answer; only a client that reads
to the end sees the difference.

* **`installed-applications` reported the page's own length as the total and
  never handed back a cursor**, though the swagger declares both. A client
  read one page of 707 applications and was told that was all of them.
* **Kibana's endpoint list echoed the page after the one it was asked for**,
  and left out the `sortField` and `sortDirection` it had applied — so a
  client paging by the echoed number skipped every other page. The sort is
  now applied as well as echoed, over the nine fields Kibana's schema
  allows; a probe covers the successful listing, which none did before.

The audit also learned what *cannot* be walked: SentinelOne publishes its
per-agent applications and processes with `data` and nothing else, by its
own swagger, so those two are reported as a fact rather than a finding.

**Twelve parameters the routes declared and ignored.** A new audit —
`scripts/param_effect.py` — asks every route, for every parameter it
declares, whether the answer changes when the parameter cannot match: a
limiter set to 1 must not answer with two, a filter nothing can match must
answer with none, `$select=id` must not answer with every field. It needs no
running vendor, which is the point: the six platforms that cannot be started
locally had never been checked for behaviour at all, only for shape.

What it found, all now fixed and pinned by tests:

* **Graph took `$select` on eleven routes and did nothing with it** —
  alerts, incidents, detected apps, conditional access policies, the
  registration report, a managed device, a group, a user and a user's
  memberships. A client asking for two fields got the whole resource.
* **`$filter` was dropped on three routes** (detected apps, conditional
  access policies, memberships) and **`$orderby` on two** (alerts,
  incidents), so "newest first" answered in insertion order.
* **SentinelOne declared two filters it never applied**:
  `installed-applications?ids=` and `device-control?accountIds=`.
* **Sentinel's threat-intelligence query read three of the eight documented
  criteria.** The threat types, the confidence bounds, the ids, the sort
  order and the page size were all taken and dropped, so a hunt narrowed to
  two indicators came back as the whole feed.
* **Falcon ignored a filter that is not FQL at all.** `filter=zzz` returned
  every record where the API answers 400; a client that mistyped its filter
  read the whole collection as its matches.

**Kibana: the rest of the platform surface, and the console proxy.** What a
client calls *around* the work, all of it 404 before: `saved_objects/_find`
(whose `type` is required, in the words its config schema uses),
`data_views`, Fleet's `agent_policies` and `agents/setup`, the Security
Solution's `timelines`, `timeline` and `note`, `cases/configure` and
`osquery/packs`.

And **`/api/console/proxy`** — how a client that only reaches Kibana talks
to Elasticsearch. The request is forwarded to this instance's own
Elasticsearch API and the answer relayed as it came, pretty-printed the way
the console shows it. Note what the *proxy* answers: 200, whatever
Elasticsearch said, with the error in the body (measured).

**Splunk: the catalogues beside the data.** Eleven more endpoints the sweep
found answering 404: the health tree a monitor polls, the extended index
list an app reads sizes from, the licence a client checks before offering a
feature, the capabilities a role may hand on, and the knowledge objects a
content pack enumerates — macros (`notable` among them, which mockdr's own
SPL understands), source types, event types, lookups, lookup files,
monitored files and field extractions.

Where mockdr has the thing it serves it: an entry per index, an entry per
source type its events actually carry. Where it has none it serves an
*empty collection* — the difference between "this deployment has none" and
"this endpoint does not exist". Each entry's content is filled out from a
recording of the real collection, because a client reads deep into these: an
extended index carries a hundred and nineteen settings, a source type
forty-two. A knowledge object also carries four more acl members than a
system entry does, because it can be shared, and its collection offers
`_acl`, `_reload` and `create` where a system one offers nothing.

**Splunk: the endpoints a client checks first, and `/export` in every mode.**
An endpoint sweep against splunkd 10.4.2 found each of these answering 404
here: the **simple receiver** (`/services/receivers/simple`) — the pre-HEC
way in, still in every ad-hoc script, which now writes a searchable event
and reports what it stamped — the **time parser** a dashboard shows its
window with, the **typeahead** a search bar completes from, and the **KV
store status** a client checks before trusting it with anything. Each
refusal is splunkd's own: an index that is not there is a WARN naming it,
an empty body is "empty body", a time it cannot read is "Invalid time."

`/export` answered its json stream whatever was asked for, because it read
`output_mode` from the query string and splunklib puts it in the form body.
It serves `json_rows`, `csv` and `xml` now, and its json stream marks the
last row and answers an empty search with the single line that says the
stream ended rather than broke.

**`json_rows` and `json_cols`.** Two output modes splunkd knows and mockdr
called invalid. A job's results and events answer them; the job itself and
the collection call them an *invalid* output mode — a third wording for the
same kind of refusal — and everywhere else they are unsupported, refused in
JSON because they are JSON modes, where `atom` and `raw` are refused in XML.

**Kibana: alerting, actions, and the identity behind them.** An endpoint
sweep against a running Kibana 8.15 found these answering 404 here and 200
there: the alerting framework's health and rule catalogue
(`/api/alerting/_health`, `/rule_types`, `/rules/_find`), the connectors a
rule can act through (`/api/actions/connectors`, `/connector_types`), the
value lists an exception can point at (`/api/lists/_find`), and the three
calls a client makes to find out who and what it is talking to —
`/internal/security/me`, `/api/licensing/info` and the task manager's
health.

The rule-type catalogue, the licence and the task manager's health are
captured from a running instance rather than written out: a client reads
deep into each — action groups, authorized consumers, the alerts-as-data
mapping, drift percentiles, which features a licence allows — and a
hand-written version had arrays where Kibana has percentile objects and
offered features a Basic licence refuses. The mapping block a rule type
carries repeats across the forty-four of them, so the fixture stores each
distinct one once and the loader puts it back.

**Elasticsearch: aliases, multi-search, and the rest of the surface a client
touches.** An endpoint sweep against the real cluster found these missing —
every one of them a 404 here and an answer there:

* **Aliases.** `PUT/DELETE /{index}/_alias/{name}`, `POST /_aliases`,
  `GET /_alias/{name}`, and — the point of them — a search *through* an
  alias, which now reads the indices behind it. An alias nothing carries
  answers `{"error": "alias [x] missing"}`: a plain string, where every
  other Elasticsearch error is an object.
* **`_msearch`**, which is what Kibana sends for almost every panel. Each
  answer carries its own `status`, and a *shard* failure belongs to its own
  search while a body that will not **parse** fails the whole request — with
  the line and column counted inside the search that failed, not inside the
  payload.
* **`_settings`** (get and put), **`_analyze`** (with the `<ALPHANUM>`/`<NUM>`
  token types and a keyword field's whole-value token), **`_validate/query`**
  (whose invalid answer is `{"valid": false}` and nothing else),
  **`_terms_enum`** for an autocomplete, and **`_resolve/index`**.
* **Scroll and point-in-time**, the two ways to read more than a page. A
  scrolled search hands back the `_scroll_id` it never used to, `POST
  /_search/scroll` pages with it, and a cleared scroll is a
  `search_context_missing_exception`. A point-in-time search names its
  `pit_id` back and adds the `_shard_doc` tiebreaker to every hit's sort —
  without which a `search_after` carrying it back is one value too long for
  the sort, and the next page is refused.

An index's `number_of_replicas` now defaults to 1, which is a cluster's own
default even on a single node.

**Elasticsearch: the writes a client makes around a search.** `_update`,
`_update_by_query`, `_delete_by_query`, `GET _source` and the maintenance
calls (`_refresh`, `_flush`, `_forcemerge`, `_cache/clear`) were not served
at all, so closing a signal, stamping a field or refreshing after an ingest
got a 404 from the mock and a write from the cluster. 28 calls measured
against 8.15, down to the `noop` a change-free update reports (with no shard
doing any work), the `[id]: document missing` a 404 carries, and which of
`updated`/`deleted` each by-query body has — `_update_by_query` reports
both, `_delete_by_query` only its own.

mockdr does not run Painless, and says so rather than guessing: it reads the
shape a SIEM actually sends — `ctx._source.signal.status = 'closed'`,
`ctx._source['kibana.alert.workflow_status'] = params.status`,
`ctx._source.count += 1`, `remove()`, a write to `ctx.op` — and refuses
anything else. A wrong answer to a status update is worse than a refusal,
because the client believes the alert was closed.

A by-query write reaches mockdr's own alerts where it can: a status
assignment goes through the repository that owns them, and a write it cannot
make is reported in `failures[]` with the reason rather than counted as
written.

**Elasticsearch: the index mapping a client sends, and what it is for.**
mockdr took the `mappings` on `PUT /{index}` and threw them away, so
`GET /{index}` answered `"mappings": {}` where a cluster echoes back what it
was given, and `_field_caps` — what every Kibana data view asks for before
it can draw anything — was not served at all. Both are there now, along with
`PUT /{index}/_mapping` (which takes new fields and refuses a type change,
because the documents are already indexed under the type they have) and
`GET /{index}/_mapping/field/{field}`.

A cluster also *adds* to the mapping as documents arrive, and the types it
picks are not obvious: a string becomes `text` with a `.keyword` subfield
capped at 256 characters, a string that parses as a date becomes `date`, a
whole number `long` and a fractional one `float`, an array takes its
element's type, an object becomes nested `properties`, and an empty array or
a null maps to nothing at all. Measured field by field against 8.15.

The mapping earns its keep immediately: **a `terms` aggregation over a text
field is refused**, the way a cluster refuses it — fielddata is off, so
there is nothing to group by. The mock grouped by the whole sentence and
answered buckets no cluster would produce, which is the shape of a client's
broken query looking fine against the mock and failing in production.

**Elasticsearch: the query clauses a SIEM client sends.** `prefix`,
`regexp`, `fuzzy`, `ids`, `multi_match`, `simple_query_string`,
`match_phrase_prefix`, `match_bool_prefix`, `terms_set`, `constant_score`,
`dis_max` and `boosting` were all "unknown query" here, so a detection rule
or a Kibana search bar using one got a 400 from the mock and hits from the
cluster. A `terms` *lookup* — the values named by another document — was
worse: it matched nothing at all, silently, and a missing lookup index was
not the 404 a cluster answers with. 63 searches measured against
Elasticsearch 8.15.

With them, four rules the mock had wrong:

* **`minimum_should_match` was ignored**, so `match` was an OR whatever the
  client asked for — three hits where the cluster returns one. A number, a
  percentage rounded down, and the negative form ("how many may be missing")
  all read now.
* **`wildcard` was case-insensitive.** Lucene is not: `SRV-*` matches
  nothing on a keyword field where `srv-*` matches three.
* **A field holding an empty array `exists`ed.** Nothing is indexed for it,
  so a real cluster leaves the document out.
* **`term` on an `ip` field would not take a network.** `10.0.0.0/24` is
  every address inside it, not a string that never matches.

A term-level query has to know whether a field is analysed, and mockdr does
not hold the mapping while it filters; whitespace decides, which is what
makes `regexp: {host: "srv"}` miss `srv-1` — Lucene anchors the pattern —
while `regexp: {message: "login"}` matches a word inside a sentence.

`simple_query_string` follows the grammar rather than a guess at it: `-`
negates its own clause rather than excluding the document, so under the
default `or` operator `login -alice` matches every document that either says
login or does not say alice; `+` is and, `|` is or, `~N` is an edit
distance.

**Six commands SOAR content uses, which the mock refused outright.**
`eventstats`, `mvexpand`, `filldown`, `spath`, `convert` and `bin`/`bucket`
were unknown commands here, so any search containing one came back as a
refusal — including the JSON parsing (`spath`) and the time bucketing
(`| bin _time span=1h | stats count by _time`) that SIEM content is built
on. 62 searches measured against Splunk 10.4.2, down to the wording of each
refusal: `mvexpand` says "Invalid argument: 'g'" for a second field name and
"A field name is expected" for none, `bin` says "You must specify a field to
discretize", `convert` names the conversion type it does not have, and a
`limit` that is not a non-negative integer is refused by the search
processor rather than by the command.

`bin` writes a numeric span as a range (`0-2`, `1.0-1.5` — the span decides
the decimals) and a time span as the bucket's start on its own; `bins=` and
`minspan=` round the span they work out up to a power of ten.

**`| streamstats`, and what `stats` writes when it cannot compute.** Two
findings from the same measurement run, 62 searches against Splunk 10.4.2:

* An aggregation with nothing to compute writes **no field**. `sum` over a
  text field, `avg` over a field the rows do not have, `values` over the
  same — splunkd leaves the column out of the row, and returns no row at all
  when there is no `by` and nothing could be computed. The mock wrote `0`
  and `""`, so a client reading `sum(bytes)` got a number here and no field
  in production. `count` over an empty result set is still a row saying `0`,
  and `min`/`max` fall back to text ordering when the field holds no
  numbers, with a number winning over text in the same field.
* `median` is not `perc50`. With an even number of values splunkd averages
  the middle pair and rounds an exact half *up*: the median of 1 and 2 is 2,
  of 1 and 4 is 3, of 1.2 and 1.4 is 1.3.

`streamstats` itself — stats over the rows seen so far, added to each row as
it passes — is what every "count since" and "compare with the previous row"
search is built on, and the mock refused it as unknown. `window`,
`current`, `by`, `reset_on_change`, `reset_before`, `reset_after` and
`time_window`, each measured.

Both commands now refuse an argument they cannot read — `stats nosuchfunc(n)`
and `stats count nosucharg=1` are errors there, and the second was silently
ignored here, so the command ran with a different meaning than the one asked
for.

**Fifty-three more `eval` functions, and the strictness around them.** The
mock had nineteen; it has seventy-two. A search using `split`, `cidrmatch`,
`strftime`, `spath`, `json_extract`, `printf`, `md5` or any of the multivalue
family got a FATAL here and a value in production. Each was measured one
expression at a time against Splunk 10.4.2, and in three runs against the
real engine — 92, 45 and 141 expressions — the two now agree on every one.
Among them `mvfilter` and `mvmap`, which evaluate their expression once per
value of the field they bind.

Three kinds of strictness came with them, each measured, each a difference a
client can see:

* **Argument types.** `len(123)`, `upper(1)` and `md5(1)` are "The arguments
  to the '<name>' function are invalid" there, and were answers here.
* **Static type checking.** splunkd checks the types it can see before it
  reads a row: `"1"+1` and `"a"-"b"` are refused, in four distinct messages.
  A *field* is typed when the row arrives instead — `field+1` adds if the
  value is a number and yields null if it is not — and with a string on
  either side the same `+` concatenates.
* **A typed null is not a missing field.** `null()` is a literal of type
  Invalid: `upper(null())` is an argument error, where `upper(nosuchfield)`
  is null and simply leaves the field unassigned. The mock treated both as an
  error, so an ordinary search over events missing an optional field failed
  here and answered there.

Also measured and now matched: a field cannot be assigned a boolean
(`eval v=1==1` is refused with splunkd's own suggestion to use `if()`), an
undefined result such as `sqrt(-1)` or `1/0` leaves the field unassigned
rather than failing, and `min`/`max` order by where a value came from — a
quoted literal is text even when it reads as a number, so `min("10", "9")` is
`"10"`, while a field holding `10` is that number.

**`| makeresults`.** The command every Splunk example and every hand-written
test starts with, which the mock did not know — so it refused the whole
search, and the standard way to try an expression could not be tried against
the mock at all. `count`, `annotate`, and inline data through `format=csv|json`
with `data=`, with the option checking measured down to the wording: a count
that is not a non-negative integer and a word that is not a boolean are
refused by the search processor, an option given twice is refused by name,
inline data allows no other argument, and a generating command that is not
first is refused by the command itself. splunkd words those under three
different subjects, and one of them carries no subject at all.

**`output_mode=csv`, where splunkd serves it.** 2.3.0 refused it everywhere,
in splunkd's own words for a mode a handler will not serve — right for most
endpoints and wrong for the four that do serve it: a job's `results` and
`events`, the job itself, and the job collection. The quoting is splunkd's,
not RFC 4180's: a token is written bare only when it is purely alphanumeric,
so `ok` and `42` are bare while `1.5`, `a-b`, `a b` and `a:b` are quoted, and
a multivalue field becomes one quoted cell whose members are separated by
newlines. A field a row has no value for is empty rather than `""`. Measured
against Splunk 10.4.2, and four seeded probes compare the bytes.

### Fixed

**A conformance job that failed on the weather.**
`es-count` reported eight differences in CI and none locally: a shard still
allocating when the search reached it puts a whole `_shards.failures`
subtree in a real Elasticsearch's reply that a mock has no equivalent for.
That is what happened during *that run*, not what either product answers, so
a spec may now name paths no probe compares — the counterpart of
`volatile_fields`, which suppresses values and never applied to shape.

**The KV store's delete ignored its query and emptied the collection.**
`DELETE …/storage/collections/data/{name}?query={…}` cleared every record
whatever it was asked, and answered 200 — so a client deleting the three
records it had selected lost the lot and was told the delete succeeded. It
now deletes what the query selects, using the same engine the read path
filters with, and was verified against Splunk 10.4.2.

**`_cat` answered JSON.** Every `_cat` endpoint answers a *table* unless the
caller asks for `format=json` — that is what `_cat` is for — and mockdr
answered a JSON document regardless, so a script reading columns got one
long line of braces. `v` adds the header row and `h` picks the columns, both
measured.

**The XML results document had no fields at all.** splunkd names them once
in a `<meta><fieldOrder>` block, numbers each result with the offset a
client pages by, repeats `<value>` for a multivalue field, and quotes its
attributes with single quotes — mockdr wrote none of that, so a reader
built on the real document found nothing in it.

**A generating search matched every event in the index.** `| makeresults`
reads no index at all, but the job recorded the whole event store as what
it matched, so `/events` answered with documents the search never touched —
and `/results` was used as a fallback when a job legitimately matched
nothing.

**A boolean in a CSV was `1`.** splunkd writes `true`, which is what
`typeahead`'s `operator` column shows.

**An exception-item search against a list that does not exist answered
`200`** with an empty page, where Kibana answers `404` with
`{"message": "exception list id: \"x\" does not exist", "status_code": 404}`.
A client searching the wrong list was told the list exists and holds
nothing.

**`GET /{index}/_source` answered a plain-text 500** for an index that is
not there — found by the hostile probe on the day it was added: the index
check raised out of the handler instead of being turned into the 404 every
other route answers with.

**Sorting is judged by the mapping too.** A `text` field cannot be sorted
on, for the same reason it cannot be aggregated, and a field the mapping
does not have at all is refused by the shard that would have sorted it —
unless the client says what type to assume with `unmapped_type`, which now
also decides what a missing value *sorts as*: the edge of a long for a
numeric type, `null` for a keyword. Only an index mockdr holds a full
mapping for is judged this way; for its own collections the mapping is a
summary, and refusing a sort on a field it does not happen to list would be
inventing a failure.

A shard failure also names the index it happened on rather than saying
"mockdr" every time, and a `query_shard_exception` carries the index and its
uuid the way a real shard's does.

**`top_hits` invented its ids.** It derived one from the contents instead of
reporting the id each document was indexed with, so a client could not fetch
back what it found; it also ignored `sort`, `from` and `_source`. And the
`missing` aggregation — the other half of a `terms` aggregation — was not
implemented.

Three differences are left in place and named in the tests, each depending
on something mockdr does not model: a `nested` query (no nested mappings), a
`script` query (no Painless), and a `terms` aggregation over a text field,
which a cluster refuses because fielddata is off.

**`| table *` selected a field called `*`.** Neither `table` nor `fields`
read a wildcard, so `| table *` and `| fields host*` — ordinary SPL — quietly
returned nothing. Both expand patterns now, in name order, which is the
order splunkd reads an expansion in while keeping the order given for
explicit names.

**The response's field block was in the wrong order.** splunkd lists the
columns *by name* unless a command in the pipeline built the row — `table`,
`fields`, `stats`, `timechart`, `top`, `rare` — in which case the order is
that command's. mockdr always used the row's own key order, so a search
ending in `eval z=1, a=2` declared `z` before `a`. It also declared only
what the *first* row carried, dropping a column that appears later, and left
out a column `stats` named but could not compute — which splunkd lists
anyway.

**A probe that could not fail.** `compare: values` parsed both bodies as
JSON, so two CSV documents both became `None` and every csv probe agreed with
itself — coverage that measured nothing. It compares the text when the body
is not JSON, and `ignore_leading_lines` accounts for the one preamble splunkd
writes non-deterministically (empty on one run, a single space on the next).
Verified by breaking the quoting rule on purpose and watching the probes
catch it.

## [2.3.0] - 2026-08-24

### Fixed

**Every time filter matched nothing.** An Elasticsearch range bound written
as date math — `now-30d`, `now/d`, `2026-01-01||+1M/M` — was compared as a
*string*, and `"2026-08-06T16:16:51.000Z" >= "now-30d"` is false for every
document. The one filter that appears in every Kibana time picker, every
detection rule and every SIEM dashboard answered `200` with an empty result
set. `utils/es_datemath.py` implements the grammar, and the rounding is the
measured one: `gte: now/d` means since midnight, `lte: now/d` through the end
of today, operators apply left to right, months clamp the day, weeks begin on
Monday.

**Splunk snapped its windows on a multiple of seconds.** `@` rounding was
modulo arithmetic, which is right by accident below a day and wrong above it:
the epoch fell on a Thursday, so `@w` snapped to a Thursday rather than the
preceding Sunday, `@mon` to a multiple of 30 days, `@y` to 365. `earliest=-1mon@mon`
— "since the start of last month", the most common dashboard window there is
— landed up to a fortnight off. Worse, a modifier the grammar could not read
resolved to "no bound": `earliest=-30x` returned every event here and none in
production. splunkd dispatches the job, returns nothing, and says why; so
does this now, in splunkd's own words, with the job marked FAILED.

**A parenthesised search answered 500.** `search index=main (host=a OR host=b)`
raised "unknown function 'main'" out of the handler: the expression parser
treated any word before a bracket as a function call, in the search clause as
well as in `eval`, and SPL has no functions in the search clause.

**`date_histogram` left out the quiet days.** Every interval no document
landed in was omitted, so a series plotted from the response skipped them
instead of drawing them at zero, and a calendar interval was a fixed span of
seconds — `1M` meant 30 days and `1w` a week beginning on a Thursday, the
same bug as Splunk's `@w`. Numeric metrics came back as ints where
Elasticsearch sends doubles, and `key_as_string` as `+00:00` where it writes
`.000Z`.

**An index you created did not exist.** `PUT /{index}` was not a route at all,
so the mock answered 404 to a create and then 404 to every search of the index
that create was supposed to make. A document written with `PUT /{index}/_doc/{id}`
was stored and readable by id but invisible to every search — an ingest that
looks like it worked and a dashboard that stays empty. And `HEAD /{index}`,
how every client library asks whether an index exists, answered 405. The whole
lifecycle is measured against 8.15 now, down to `forced_refresh` and the 201
that separates a create from a replacement.

**Kibana's requests were read past.** `severity=nonsens` came back as `200`
with no cases, which a client reads as "there are none" rather than as the
typo it is; `sortField=nope` came back sorted by something else; a case was
created with a severity outside the enum and a `status` no client may set; an
exception list was created with a `type` a real Kibana refuses; a response
action with an unreadable body came back as a 404 about an endpoint rather
than a 400 about the request.

Kibana speaks **four** validation dialects, and they differ in wording,
precedence and envelope: io-ts on the Cases API, io-ts *with* a `[request
query]` prefix on the exception lists, zod on the Detection Rules, and
`@kbn/config-schema` on the Endpoint routes — which stops at the first
failure where the others join every complaint, and counts pages from 0 where
the others count from 1. What a route raises after its schema is satisfied
comes back in a different envelope again: `{message, status_code}` rather
than Boom's. All four are now measured, message for message.

`DELETE /api/cases` took its ids in the body and answered 204 whatever
happened; Kibana takes them in the query string and answers 404 naming the
saved object when one is missing. The Endpoint metadata route declared four
filters Kibana does not have and spelled the page size its own way — a client
written against the mock sent a query the real one refuses, so those are gone
and the UI now sends what a real client sends.

**splunkd checks its query three ways; mockdr checked none of them.** The
output mode, the sort direction and every argument name are validated against
the handler's own list, and each has its own wording: a mode splunkd does not
know is `Invalid output mode specified (x).`, one it knows but the handler
will not serve is a WARN naming it, a sort direction outside asc/desc is
`Unknown sort order "x".`, and an argument a collection does not declare is
refused by name. The job collection is the exception on two counts, both
measured rather than assumed: it sorts on several keys at once, so it pairs
each `sort_key` with a `sort_dir` and refuses a mismatch, and it takes any
argument because it has a dispatcher of its own.

**Smaller ones, all measured the same way.** SPL: `tail` reverses its rows,
`stats ... by` sorts its groups and drops a row missing a by-field, `top`
carries `_tc` and six decimals of percentage, `table` drops a field a row does
not have, `_time` renders as ISO-8601 rather than as the epoch the pipeline
sorts on, a single-valued field is a string rather than a one-element array,
`stdev`/`var`/`perc<N>`/`mode`/`earliest`/`latest` exist, and `round(10, 2)`
is `10.00`. Elasticsearch: hits carry the `sort` values `search_after` needs,
a document without the sort field goes last whichever way the sort runs,
`track_total_hits` caps at 10 000 with `relation: gte`, a written document
keeps the id it was given, Lucene's `[a TO b]` works and `@timestamp:x` names
a field, and four malformed `range` shapes are refused by name — one of which
the fuzzer reached as a 500. Kibana: a case carries `comments`,
`customFields`, `category`, `duration` and `external_service`, and no longer
carries mockdr's own `alert_ids`.


**The guard that was too strict.** The shard-allocation wait added above
refused to probe until `unassigned_shards` reached zero — which on a
single-node Elasticsearch never happens, because every replica is
permanently unassigned and yellow is its healthy state (the probe file says
so itself, three lines away). It waits for *movement* to end now: nothing
initializing, nothing relocating.

**The navigation guard fired an import it never waited for.** It called
`import('../stores/auth').then(…)` and moved on, so the promise outlived the
navigation — in the test environment it resolved after teardown, which is
what the frontend job caught — and it called `login()` without catching,
which became an unhandled rejection the moment a failed login started
throwing. It is awaited now, it hydrates the *user* (the store reads the
token from `localStorage` when it is created, so the old condition never
fired), and a token the backend refuses ends at `/login` rather than on an
empty dashboard. `src/router/__tests__/guard.spec.ts` covers all four paths;
the guard had no test at all.

**Sentinel resources completed what they already had.** The ARM completion
helper built a default for every declared property and then overwrote most of
them — 14 000 discarded objects per incident page. It builds only what the
resource lacks, as the other four platforms' helpers already did. Incident
list 6.0 → 3.9 ms.

**Every icon was its own download.** Rollup gave each `lucide-vue-next` icon
its own ~200-byte chunk, so opening a view fetched 42–46 JavaScript files for
about 8 kB of icons. They are one chunk now (20 kB, cached once): a view costs
15–18 JS requests instead of 42–46, and 21–24 requests in total instead of
44–52. Nothing else is grouped — naming a chunk pins it into the static graph,
and both obvious groupings made the login screen worse (a `charts` chunk put
250 kB of Chart.js on it, an `app-core` chunk put every vendor client there).
The login page still loads 9 requests and no Chart.js.

**The filters a real integration actually sends.** The XSOAR SentinelOne V2
integration — the connector most mockdr users point at it — sends 27
documented query parameters; six of them this mock ignored, so the
integration's own filtered queries came back unfiltered: `osType` and
`ruleName__contains` on alerts, `status` on STAR rules, `updatedAt` on
accounts and sites, `userEmails` on activities (resolved through the users,
because an activity stores only the id), plus the account and site filters
beside them. Seeded STAR rules now carry the swagger's spread of statuses
instead of `Active` twenty times over — a filter no seed can exercise is a
filter nobody can trust.

**`tenant` was dropped on seven routes.** SentinelOne declares it wherever a
request can be widened from the caller's own scope to the whole tenant;
FastAPI dropped it, so it never reached the mock's OpenAPI either. It is
declared now. mockdr seeds one tenant and a non-admin token stays scoped, so
the answer is the same set — the point is that a declared parameter is no
longer silently discarded.

**A documented filter that filtered nothing.** SentinelOne's swagger declares
`incidentStatus`, `analystVerdict`, `severity` (alerts), `type`, `source`,
`uuids` (IOCs) and `id` (groups); this mock declared only its own plurals
(`incidentStatuses`, `types`, `ids`, …). A client written against the vendor's
documentation sent the documented name, FastAPI dropped it, and the route
answered `200` with the entire collection — the silent wrongness this project
exists to prevent, in the one place `field_drift.py` cannot see, because it
compares response fields and a filter is a request. The documented names are
taken now, beside the plurals this mock has always had. SentinelOne also
spells a filter value one way and answers another —
`incidentStatus=UNRESOLVED` returns alerts whose `incidentStatus` reads
`Unresolved` — so a filter over a declared set matches both forms
(`FilterSpec(..., enum=True)`).

`scripts/param_drift.py` measures the rest and states it: of 89 routes both
sides describe, **1 066 documented parameters this mock does not take** (the
vendor declares dozens of `__contains`/`__gt` variants per route) and **20 it
takes that the swagger does not declare**. Numbers, not surprises.

**Two Splunk-only middlewares taxed all 561 routes.** `SplunkOutputModeMiddleware`
and `SplunkPagingMiddleware` were `BaseHTTPMiddleware`, which wraps every
request in an anyio task group and a memory object stream whether or not the
middleware touches the response. Both are pure ASGI now and share one
body-rewriter (`api/middleware/json_rewrite.py`): a request outside `/splunk`
is passed straight through, and a body is collected only when it is actually
going to be rewritten. The middleware floor — what any response costs before
its route runs — halves, from 0.79 ms to 0.39 ms. Verified against real
splunkd: 72 conformance probes, 0 findings.

**An unknown path cost fifteen times a served one.** The fallback that turns a
typo into a vendor-shaped 404 probed all seven verbs against the whole route
table, every time: 7.66 ms for a path nothing owns, on a mock whose floor is
0.4 ms — and `hostile_probe.py` sends 16 000 of them. Starlette already
distinguishes the two cases (a path that exists under another verb reports
`PARTIAL`), so one pass answers most of it, and the route table is fixed once
the app is built, so the answer is cached per path. Unknown path 7.66 → 1.10 ms,
wrong verb 7.31 → 1.49 ms, with the same status, body and `Allow` header.

**Serialisation was the request.** The weekly load test — new to CI, and the
first run of it since 2.1.0 — failed on the runner: read p99 812 ms against
a 500 ms gate. Three causes, all in the path every response takes:

- `dataclasses.asdict` deep-copies every leaf it walks, and every query
  called it per record: 11 700 `_asdict_inner` calls for one `GET /threats`.
  `utils/serde.record_dict` rebuilds mutable containers and shares scalars —
  same isolation from the store, same output, none of the copying.
- `deep_complete` built a default for every declared key and then threw
  away the ones the record supplied. It builds only what is missing now.
- `SecurityHeadersMiddleware` was a `BaseHTTPMiddleware`, which wraps every
  one of the 561 routes in an anyio task group; it is pure ASGI now.

Together with the middleware and fallback work above: `GET /threats`
7.1 → 3.4 ms, Defender alerts −23 %, Elasticsearch `_search` −18 %, a Splunk
oneshot search −17 % (medians of an interleaved A/B, three rounds). The load
test passes with room (read p99 449 ms
pinned to two cores, 186 ms at the concurrency CI uses). No response shape
changes: 199 routes compared across six platforms, 0 drift.

**The harness measured a moment, not a product, twice more.** After the shard
wait, two probes still read Kibana's own lifecycle: `_cat/indices` listed the
system indices it creates and rolls over (stats not yet available), and
`_search` across `_all` caught a shard mid-allocation (an extra `caused_by`
chain). Both now address an index the bootstrap guarantees on each target —
creating `conformance-probe` on a cluster that has none of its own — so the
row shape and the window rule are what they measure.

**The harness measured a moment, not a product.** A conformance run on a
cluster that was still allocating shards reported eight findings: the real
Elasticsearch answered a search with `_shards.failures`
(`no_shard_available_action_exception`), which the mock has no way to
produce. `bootstrap_elastic` now waits for every shard to be allocated
before the first probe and says so if it never happens — "nothing differed"
and "nothing ran" stay distinguishable.

**The scripts were the only Python nothing linted.** `scripts/` has a ruff
config of its own (the backend's rules, with the allowances a script earns)
and is checked in CI and by `ci.sh`; the 34 findings that had accumulated
are fixed, including a probe that bound to `0.0.0.0` to talk to itself.

### Added

**The harness compares answers, not only shapes.** Every probe until now
compared the *shape* of a reply against an empty real install — which cannot
see a wrong answer, because a search that matches nothing agrees with every
other search that matches nothing. That blind spot is where the time filters,
the snapping, the bucketing and the sort order above all survived.
`--seeded` puts the same five events into both Splunk targets' HEC and the
same six documents into both Elasticsearch targets, and 56 probes then run
the same query against both and compare the rows themselves
(`needs_seed: true` + `compare: values`, with the fields that name the
instance rather than the API dropped first). CI runs both probe files seeded.

### Changed

- `scripts/load_test.py` takes `--concurrency`: the CI job scales the
  scenarios to a 2-vCPU runner, where a 50-deep queue measures the runner's
  cores rather than the mock's work. Release runs keep the full counts.

- `ci.sh` runs the hostile-inputs step CI runs; the weekly workflow also
  runs `scripts/load_test.py`; the release checklist ends with the GitHub
  Release (2.1.0 and 2.2.0 had tags but no Release page — created).

## [2.2.0] - 2026-08-23

The TEAMS.md review of 2.1.0 (86 perspectives over the code) converged on
three things; this is them.

### Fixed

**Bridge events are dated by their records, not by November 2023.** The
Splunk bridge seeder and the Sentinel incident seeder stamped every event
with a fixed epoch (`1700000000`, 2023-11-14) while the records they carried
said 2026 — `search index=msdefender earliest=-24h` found nothing, nor did
the seeded ES saved searches (`-24h@h`), nor a Sentinel client filtering
`createdTimeUtc`. An add-on indexes an object at its own time, so a bridge
event's `_time` is now the record's timestamp (`utils/event_time.py`:
`createdAt`, `alertCreationTime`, `creation_time`, `detection_timestamp`,
…). The seeder's second pass over SentinelOne activities is gone — the
repository already bridges every activity live, so twenty were indexed
twice. Tests: every bridge event's `_time` equals its record's timestamp;
`earliest=-90d` finds events in every vendor index.

**Traffic cannot grow the process until it dies.** Collections written per
request are capped with oldest-first eviction (`CAPS` in `store.py`):
Splunk events 100 000, notables 20 000, search jobs and sessions 5 000,
Elasticsearch documents 100 000, agent uploads 200, and every OAuth token
collection 5 000 — a client that fetched a token per request used to keep
all of them forever. Request bodies have a ceiling (`MOCKDR_MAX_BODY_BYTES`,
16 MiB; `413` before any byte is read). `/_dev/fault-injection` delays are
bounded at 60 s. `/metrics` labels requests by the matched route's template
(`/web/api/v2.1/groups/{group_id}`), so probing unknown paths no longer
adds a label set per path.

**A webhook receiver's answer counts.** Delivery recorded any HTTP response
as `success`, a 500 included. A 5xx is now retried like a connection error
and a 4xx is recorded as a rejection without retry; only 2xx/3xx is a
delivery. The `/_dev/webhook-sink` (public by design, it receives what the
mock sends) no longer stores `Authorization`, `Cookie` or API-key headers
for admins to read back.

**The map matches the territory.** ADR-001 said reads take no lock (they
do); SECURITY.md promised `X-XSS-Protection: 1; mode=block` (the code sends
`0`, as OWASP recommends); ADR-009 was titled ADR-010; the FastAPI title and
the console's login and breadcrumb still said "SentinelOne Mock API" /
"Mock S1" / "Hypervisor" and the sidebar "7 platforms"; the coverage gate
was 55 % in CI and 85 % in the docs (it is 85 % everywhere now — measured
89 %); `CORS_ORIGINS` defaulted to a port nothing listens on; the README
did not know `ES_*_PASSWORD`, `SPLUNK_SESSION_TTL_SECONDS` or the new
`MOCKDR_MAX_BODY_BYTES`; the Vite dev proxy forwarded only `/web/api` and
`/_dev`, so the 61 vendor views got `index.html` as JSON on port 3000; the
Bruno and Postman collections still carried two removed Cortex routes and a
Defender path without `/stats`; `data/vendor-specs/crowdstrike_swagger.json`
was a CloudFront error page; `get_threat` bypassed the shared
`public_threat` serializer.

**Cortex XDR `get_alerts_multi_events` has a reference, a route and the
bridge uses it.** Elastic's `panw_cortex_xdr` integration reads the same
API and carries a transcription of its replies (v1: the alert with its
`events` list; v2: flattened) as its test mock; reduced to key paths under
the Elastic License (`scripts/cortex_alerts_spec.py`,
`data/vendor-specs/xdr_alerts_multi_events_reduced.json`). The mock now
serves `POST /public_api/v1/alerts/get_alerts_multi_events/` (same filters
and paging as `get_alerts_by_filter_data`) completed to that shape, and
the Splunk bridge's `pan:xdr:alert` events are that route's alert — the
2.1.0 known limit is closed. Cortex XDR: 34 routes compared, 0 drift.

**Completion without deepcopy.** Every completed list item deep-copied its
whole default template — 200 000 `copy.deepcopy` calls for twenty threat
pages. Scalars are immutable and are shared now; only nested objects are
rebuilt. `GET /threats` 66 → 14 ms, and the load test's read scenario (50
workers) p99 1030 → 349 ms, back under its 500 ms gate.

**The SentinelOne agents channel has a reference too.** Splunk's own
`SA-SentinelOneDevices` reads `sentinelone:channel:agents` for Enterprise
Security assets and names the 39 fields it expects — the `GET /agents`
object's (`uuid`, `agentVersion`, `lastActiveDate`,
`networkInterfaces{}.physical`, …). Reduced to field names
(`scripts/s1_channel_fields_spec.py`); a test keeps every bridge event
carrying all of them.

**What the same review listed below its top three — done.** Seed data
names nobody real: documentation IP ranges (RFC 5737) and reserved
`.example`/`.test` domains replace Faker's routable addresses and
surname domains, and no seeded mail rule forwards to `gmail.com`. Cortex
XDR exclusions, violations and agent reports no longer carry a fixed 2023
timestamp. The persistence snapshot records the version that wrote it.
Webhook deliveries run on eight daemon workers instead of a sleeping
thread per subscription per event. The Docker image owns `/app` as
`appuser`. ARCHITECTURE.md describes the eight platforms, the
measured-fidelity method and the verification tooling (it had stood still
since March); `scripts/README.md` maps every script to when it runs and
holds the release checklist.

**The console fails honestly and can be used without a mouse.** A login
that cannot reach the backend fails with a message instead of "succeeding"
on preset metadata and landing on an empty dashboard. Every API client
reports a failed request to a notifications store rendered as toasts in a
polite `aria-live` region, so the 39 views that swallow errors in a bare
`catch {}` no longer fail silently; identical messages collapse. Rows that
navigate on click are focusable and open on Enter; every `<th>` carries
`scope="col"`; selection checkboxes and filter selects have accessible
names; icon-only buttons have labels; the two dashboard charts describe
themselves; a skip link precedes the sidebar; focus is visible;
`prefers-reduced-motion` stops the infinite animations; the muted text,
primary-as-text, danger badge and the Splunk search button meet WCAG AA
contrast; checkboxes are 24 px targets. An axe-core Playwright suite
(`e2e/accessibility.spec.ts`) fails on any serious or critical WCAG 2.2 AA
violation on the login, dashboard, endpoints, threats and Splunk search
pages. The Vite dev proxy now forwards every vendor root.

### Added

- `frontend/e2e/accessibility.spec.ts` (axe-core), `src/stores/notifications.ts`, `Toasts.vue`.
- `data/vendor-specs/NOTICE.md`: every vendored reference with its source,
  licence and what of it is kept (key paths only for the Elastic-licensed
  Event Streams recordings and the unlicensed Cortex transcription).
- CI job `hostile-inputs`: `scripts/fuzz_parsers.py` and
  `scripts/hostile_probe.py` run on every push — they found their bugs
  after a release until 2.0.5 made them a release step.

## [2.1.0] - 2026-08-23

Response *shapes* are now measured, not typed from memory. Every mounted
route of every platform is compared against a public reference, each used
for what it can prove: Splunk, Elasticsearch and Kibana against the real
products in the conformance harness; Sentinel and Graph against the
published specs (Azure REST API specs 2024-03-01 stable + 2025-10-01
preview, Microsoft Graph v1.0 and beta OpenAPI metadata); SentinelOne
against its 2.1 swagger (generated from the product's schemas — absence
and surplus both count); CrowdStrike against the `gofalcon` SDK (generated
from the swagger; `omitempty` models, so only surplus counts); Defender for
Endpoint against `MicrosoftDocs/defender-docs` and Cortex XDR against
recorded responses, transcriptions and connector code (presence only).

Before → after: Splunk 897 missing keys → 0 (72 probes); Elastic and Kibana
0 (57 probes); Sentinel 276 → 0 (20 routes); Graph 35 → 0 (51 routes, beta
included); SentinelOne 342 → 0 (35); CrowdStrike 61 → 0 (23); Defender
642 → 0 (36); Cortex XDR 277 → 0 (33). No mounted route is without a
reference, except Defender's two Azure AD token endpoints.

### Changed

**Splunk — an entry carried a tenth of the keys a real one does.** A real
saved search has 217 content keys, an index 113, a finished job 67 (with its
`performance` and `searchTelemetry` trees), a role 43, a user 23, the
current context 24, a KV collection 10; the mock had 11, 12, 36, 5, 7, 7 and
3. Each collection is completed against a fixture captured from Splunk 10.4.2
(`backend/infrastructure/fixtures/splunk/`), the mock's own values winning.
Also measured and fixed: the link relations per collection (a job's nine
sub-resource links including `search_telemetry.json`, a saved search's ten,
an index's five); the ACL members (saved searches and KV collections carry
the four `can_share_*` capabilities, a job's ACL has a string `ttl` and no
`can_list`); `published` on job entries; `paging` absent from `server/status`
and `messages` absent from the job list; top-level links per collection
(`_acl` on saved searches and KV config, none on jobs, current context or
fired alerts); `server/status` as the collection of seven sub-resources it
is, not an invented `{"health": "green"}` document; KV collection config as
splunkd's flat `field.<name>` / `accelerated_fields.<name>` keys, listable
under `/services/` across apps; a wrong password answers with
`code: incorrect_username_or_password` (a missing one does not); the parser
names the field of `dc(host)`/`count(x)` and `timechart` carries its
`seriesfilter: "sum IN top10"`. Job telemetry timestamps are anchored on the
job's own start, not the capture run's.

**Kibana** — `GET /api/features` returned 8 of 33 features; all 33 of 8.15
now, captured from the real Kibana.

**Sentinel** — every resource has the shape the spec declares: fixtures are
generated from the Azure spec (`scripts/gen_arm_fixtures.py`), one per
resource and per `kind`, and deep-merged under the mock's values. Fixed on
the way: `systemData` missing everywhere; `kind` inside the property bag on
alert rules and data connectors; alert rule templates an empty list (three
Scheduled templates now, with a single-item route); incident labels as
strings instead of `{labelName, labelType}`; `watchlistItemsCount` and
`additionalData.techniques`, which 2024-03-01 does not declare; no `etag` on
a single watchlist item; data connectors in one invented shape for every
kind (now `tenantId` + the kind's own `dataTypes` tree for the eight stable
kinds, and the codeless `connectorUiConfig` for `GenericUI` as the preview
spec declares it); threat-intelligence indicators without `kind: indicator`.

**Graph** — five properties v1.0 does not declare are gone (`alert_ids`
leaking out of `security/incidents`, `isActive` on service health,
`publisherName` on service principals, `deploymentProfileAssignmentStatus`
on Autopilot identities, `result` on threat assessment requests);
`groups/{id}/members` and `directoryRoles/{id}/members` return each member
as its concrete type with `@odata.type` and the user's full default
property set; `/beta/` routes are judged by the beta metadata.

**SentinelOne** — every list and single resource is completed to, and
restricted to, the swagger's fields (`fixtures/sentinelone/`, one per
response definition; `null` where the swagger says `x-nullable`, the
vendor's own `example` otherwise): a user has 33 fields, not 11;
`system/info` answers `build/patch/release/version`, not an invented
`serverVersion/buildTime`; agent processes carry `processName`,
`executablePath`, `cpuUsage`, `memoryUsage`, `startTime` and no
`pagination`; exclusion scopes are `{tenant, accountIds, siteIds, groupIds}`;
`activities/types` has its `descriptionTemplate`; a hash verdict is a
verdict without an invented `confidence`; cloud-detection alerts lose an
`agentRealtimeInfo` the schema never had; policies are served by scope
(`/sites/{id}/policy`, `/groups/{id}/policy`, `/accounts/{id}/policy`,
`/tenant/policy`) in `EnrichedPolicySchema` shape. `/agents/passphrases`
honoured no `ids` filter and answered every agent's passphrase.

**CrowdStrike** — an alert (v2) carried the legacy detection's `behaviors`,
`hostinfo`, `max_severity`… and lacked `severity`/`severity_name`; users
lose `customer`/`roles`, devices the retired
`slow_changing_modified_timestamp`; PATCHes answer meta-only as
`MsaReplyMetaOnly` does; the current `/cases/queries/cases/v1`,
`/cases/entities/case-tags/v1` and `POST …/quarantined-files/GET/v1` paths
are served.

**Defender for Endpoint** — machines, alerts, vulnerabilities, machine
actions, software, investigations, indicators and logon users are completed
from the docs (`fixtures/mde/`, honouring the docs' own spelling:
`/api/Software`, `CreateAlertByReference`, `Delete https://…`): an alert has
its `evidence` items with 20 fields each, a machine `deviceValue`,
`osArchitecture`, `version`; `groupName`, `loggedOnUsers` and `agentVersion`
were not documented machine fields; live-response actions carry the
documented `commands` fields; file statistics carry the global view; domain
and IP statistics say `organizationPrevalence`, not `orgPrevalence`; the
batch delete lives at its documented `POST /api/indicators/BatchDelete`
with `IndicatorIds`.

**Cortex XDR** — replies are completed to the recorded shape (`fixtures/xdr/`,
one per route, list replies item by item): an alert has its `alert_fields`,
an incident its `hosts`/`users`/`incident_sources`; `rbac/*` and
`alerts_exclusion/` answer a bare list in `reply`, not an invented paged
envelope; `alerts_exclusion/add` answers `{rule_id}` and `delete`
`{rule_id: [...]}`; `quarantine/status` is a bare list; `healthcheck`
answers `{status}` without a `reply` envelope; `tim_insert_jsons` answers
`{validation_errors}`; `insert_cef_alerts` takes CEF *lines* as the product
does — a string used to crash it with `AttributeError`.

**Splunk EDR bridge — CrowdStrike events in the shape Event Streams emits.**
The bridge wrote a `DetectionSummaryEvent` with a hand-picked subset and an
`IncidentSummaryEvent` that was the mock's whole incident model. Measured
against events recorded from the Falcon Event Streams API
(`data/vendor-specs/cs_event_streams_reduced.json`, key paths from Elastic's
`crowdstrike/falcon` pipeline test data): detections are now the current
`EppDetectionSummaryEvent` with its recorded fields (agent, aggregate and
composite ids, file, hashes, parent, disposition flags, tactic/technique,
source product), and an incident carries exactly its nine fields
(`IncidentID`, `HostID`, `IncidentStartTime`/`EndTime`, `FineScore`, `State`,
`IncidentType`, `LateralMovement`, `FalconHostLink`). A test keeps every
bridge event within the recorded key set.
The live bridge (events on mutation) now builds the same shapes as the
seeder; it had kept the legacy `DetectionSummaryEvent`.

**Splunk EDR bridge — the other vendors' events as their add-ons index
them.** The SentinelOne App for Splunk, the Splunk Add-on for Microsoft
Security and the Splunk Add-on for Palo Alto Networks each write the
product's API object as one event. The bridge wrote the mock's internal
records instead — a Defender alert lacked 30 documented keys (`id`,
`computerDnsName`, `aadTenantId`, the evidence fields, …) and carried
`alertId`; a Cortex incident lacked `xdr_url`, `notes`, `host_count`. Bridge
events are now the serialization the list route answers, key for key
(`application/splunk/edr_shapes.py`, shared by seeder and live bridge), and
the sourcetypes are the add-ons': `ms:defender:atp:alerts`,
`ms:defender:machines` (were `ms:defender:endpoint:alerts|machines`),
`pan:xdr:incident`, `pan:xdr:alert`, `pan:xdr:endpoint` (were plural).
Defender events are checked against add-on events recorded in
`splunk/attack_data` (`data/vendor-specs/splunk_ta_samples_reduced.json`,
`scripts/splunk_ta_samples_spec.py`). (The PAN add-on's `get_alerts_multi_events` shape was unknown when this
was written; the entry above closes it.)

### Removed

No evidence, no route: a mock that serves a path nobody can document
invents the product, and a UI that leans on such a path proves nothing.

- *SentinelOne*: twelve routes the 2.1 API does not have (`/agents/{id}`,
  `/agents/{id}/passphrase|processes|applications`, `/threats/{id}`,
  `/threats/{id}/fetch-file`, `/cloud-detection/alerts/{id}`,
  `/hashes/{hash}/reputation`, `/policies`, `/webhooks`). The UI reads
  single entities as the product does (`?ids=` lists), policies by scope,
  the fetched file via `/threats/{id}/download-from-cloud`; the outbound
  webhooks — a mockdr feature, not a SentinelOne API — live under
  `/_dev/webhooks` with the rest of the control surface.
- *Defender for Endpoint*: `GET /api/domains/{domain}`, `GET /api/ips/{ip}`,
  `GET`/`PATCH /api/indicators/{id}`, `POST /api/investigations/{id}/collect`
  — none documented.
- *CrowdStrike*: the sixteen routes the current API no longer has — the
  legacy Incidents API (`/incidents/*`), the legacy IOC API
  (`/indicators/*/iocs/v1`), the cases shape under `/alerts/*/cases`, the GET
  variants of `…/GET/v1` POSTs — with the incidents and cases views and the
  dashboard's incident widget.
- *Cortex XDR*: `alerts/update_alerts`, `hash_exceptions/allowlist|blocklist/get`,
  `indicators/enable_iocs|disable_iocs` — no public evidence of their reply
  shape — with the hash-exceptions view (add/remove stay).
- The Postman collection follows: 15 requests moved to the documented
  routes, 13 dropped.

### Added

- `scripts/schema_drift.py`: compares every mounted route of a platform
  against its reference — swagger/OpenAPI (cross-file `$ref`s, `kind` and
  `@odata.type` polymorphism, preview-only definitions, free-form objects
  and empty arrays as not-drift, exact or suffix path matching) or a
  route → key-path map with request bodies and id resolution; lists the
  routes the reference does not describe.
- Reference reducers: `gofalcon_spec.py` (CrowdStrike), `mde_docs_spec.py`
  (Defender docs tree), `xsoar_samples_spec.py` (recorded responses from the
  XSOAR packs, MIT), `cortex_openapi_spec.py` (per-endpoint transcriptions
  of the Cortex reference; unlicensed, so only derived key paths are kept),
  and a Graph beta extraction.
- Fixture generators: `gen_arm_fixtures.py` (Sentinel), `gen_s1_fixtures.py`,
  `gen_mde_fixtures.py`, `gen_xdr_fixtures.py`; fixtures under
  `backend/infrastructure/fixtures/{splunk,sentinel,sentinelone,mde,xdr}`
  and `kibana_features.json`.
- `data/vendor-specs/` is versioned (Azure specs, Graph metadata, the
  reduced references, `xsoar-samples/` with provenance, and
  `xdr_connector_reduced.json` with one cited source per route).
- Two harness probes declare data-dependent paths (a job's `performance`
  profile and the sourcetypes it touched; a KV collection's own field
  schema) as such, with the reason on the line.

### Known limits

A recording, a docs example or a transcription proves what a real reply
carries, never what it does not: for Cortex XDR and Defender, surplus
fields are listed as undocumented, not counted as drift. Fields a fixture
adds carry type-correct defaults or the vendor's documented example, not
real data. The current CrowdStrike cases model
(`OperationsGetCasesByIDsResponseVM`) is not modelled; only the documented
query and tag routes are served. Defender's two OAuth token endpoints are
Azure AD, not the product API, and are not compared. The Splunk bridge's
Cortex XDR alert events use the alert object recorded under
`get_incident_extra_data`; the add-on's own `get_alerts_multi_events`
reply has no public recording. Removed routes and renamed bridge
sourcetypes make this a minor, not a patch, release.

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


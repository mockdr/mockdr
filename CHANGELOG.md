# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

**`scripts/write_effect.py` — the members a write route accepts must do
something.** `body_audit.py` asks whether a route *reads* its body, by
refusing `{}` and a member it does not declare. Whether the members it
accepts are *applied* is a different question, and the gap between the two
held every write defect fixed above: `PUT /tenant/policy` refused both of
those bodies and then ignored 43 of the 51 members the swagger documents.
Each route is now sent every member of its documented body, typed from the
swagger's own schema, and the answer is compared member by member. Server-
owned members (`id`, `createdAt`, who last acted) and write-only ones (a
password, a one-time code) are listed in the script with the reason rather
than guessed at, as is the one body whose two members contradict each other
by design — `reactivate`'s `unlimited` and `expiration`. It runs in CI after
the spec is fetched, and reports 0.

Only SentinelOne is covered, by measurement rather than choice: it is the
one vendor whose vendored reference gives body schemas with types. The
CrowdStrike and Cortex references name their members and not their types, so
a generated body would be a guess, and a guess that answers 400 measures the
guess.

### Removed

**Seven functions nothing could reach, and the blind spot that hid them.**
`unreachable_code.py` counted identifiers in one bag, by name, across every
file — so a function was "reached" if *any* module anywhere named something
spelled the same. `application/cs_cases/commands.py` has a `create_case`
that no route calls and it read as reached on every run, because
`application/es_cases/commands.py` has one that a route does. Six more sat
behind the same collision.

It attributes a mention now: a file counts only if it is the defining module
or imports it by its whole dotted path. Matching on path *parts* was the
first attempt and no better — every file importing any `commands` module
vouched for every other. And a helper its own module calls is reached, which
the attempt before that got wrong, flagging four `deep_complete`s.

Gone with it: `create_case` and `update_case` on CrowdStrike cases, whose
routes are read-only and tag-only; a `get_alert` in `alerts` and another in
`es_alerts`; `scan_endpoint` in `es_endpoints`; `get_tags` in `es_rules`,
where the route that serves tags computes them inline; and `get_indicator`
in `mde_indicators`. 100 lines, and every one of them verified by hand
before deletion — each caller named a same-spelled function of another
module.

### Changed

**Coverage runs through `sys.monitoring`, and CI gets nine minutes back.**
One job was 29 of CI's 31 minutes while every other finished inside three,
so it was the wall clock — and most of what it spent went on the `settrace`
tracer rather than on the tests. Python 3.12 added `sys.monitoring` and
coverage.py uses it when asked. Measured over the whole suite here: 197s
with the default tracer against 139s with this, for byte-identical numbers —
27 956 statements, 2 284 missed, 92 % either way.

**The seed-ordering test tries twelve draws, not four.**
It exists because a timestamp defect can hide in the one seed a suite
happens to use, and it has now been beaten twice by exactly that: the
Elasticsearch rule seeder the first time, the agent seeder the second, and
neither of the four draws it tried had hit the overlap. Twelve draws cost
five seconds; forty were swept by hand when the agent defect was fixed, and
all forty are clean.

### Added

**The Graph console has tests.** It had none — 24 views, its store and its
API client — and all three defects the strengthened end-to-end sweep found
were in it. Every other vendor section of this console is covered; that one
never was, and its `0 | 0 | 0 | 0` line had been sitting in the coverage
report all along.

The fixtures are not written by hand. `scripts/gen_graph_fixtures.py` asks
the mock exactly what the console asks it — 30 paths, 526 records — and
writes the answers down, because a hand-written fixture is a guess at what
the backend answers and one of them guessed wrong: `AlertsView`'s gave
`agentRealtimeInfo` an object where the product answers `null`, so the view
read a property off null, rendered nothing, and 2 103 unit tests passed over
a blank page. `scripts/frontend_fixture_drift.py` re-asks the mock the same
questions and reports a key that appeared, a key that vanished, and a key
that turned null in *either* direction — the last one being the shape of the
defect that started this. It runs in CI.

Each of the 21 views is held to two things: it renders its heading, and it
puts a value from the captured answer on the page. The second is what an
empty state, a crashed setup and a refused request all fail. Both were
checked by breaking them — an empty answer fails three cases, a
wrong-shaped one fails a fourth.

`src/api/__tests__/graph.spec.ts` covers the token call itself, since that
is where the defect lived: it asserts the grant carries the `scope` Entra
requires, and fails if the line is removed again.

### Removed

**`src/stores/graph.ts`, which nothing imported.** 143 lines, `0 %` covered,
holding the only `TODO` in the tree — and `useGraphStore` appeared in no
file but its own, where every other store is used by three to eight. The
Graph dashboard computes the one figure it needed locally. Writing tests for
code nothing calls would have added debt rather than removed it.

Frontend coverage is 91.2 % of statements, from 81.0 %: `stores` 70.3 % →
98.5 % (the dead file was most of the gap), `views/graph` 0 % → 74.2 %. 2 144
unit tests, from 2 103.

### Changed

**The ReDoS guard measures a ratio, not the clock.**
It asserted that a 32KB hostile `$filter` is rejected inside one second,
chosen as "well under the old cost (~2.8s) and far above the fixed one
(~1ms)". It failed anyway, once, under twenty parallel workers — a
wall-clock budget measures the machine as much as the code — and raising it
is no answer either: the broken version took 2.8s, so any budget loose
enough to survive load would let the regression through. It compares the
hostile filter against an ordinary one measured in the same conditions
instead. A hostile filter costs 1x an ordinary one today; the limit is 50x
and the quadratic version was roughly 2 800x.

It was the only test in this suite asserting on elapsed time. The other
fourteen files that read the clock use it for timestamps.

### Fixed

**No documented filter points at an empty field any more — 0 of 344, from 59.**
The rest of them, after the indicators, the device rules, the agents and the
threats: an account carries the licence document and SKUs its answer
declares and an expiry date; an exclusion is written at all four scopes
rather than two, and names the application where it is written against one;
a blocklist entry likewise; a firewall rule names the tags it is scoped by; a
group has a rank; a STAR rule the id of the scope it belongs to; and an
activity that reports a threat says which threat — types 25 to 27 are
"Threat detected", "mitigated" and "resolved", and all three left it unset,
so a client following an activity to what it reports found nothing to
follow.

The scopes are round-robin, not drawn: a scope that appears only on some
seeds gives a filter that passes only on some runs, which is the flakiness
this seed keeps being cleaned of.

Two tests had been passing on the uniformity that has now gone. The schema
test caught `skus[].type` written lowercase where the swagger's enum is
`Core`, `Control`, `Complete`. And `test_documented_sorting` asserted a page
was ordered by `scope` — an object, whose ordering is the mock's rendering
of a dict rather than a contract any product keeps. It read as passing only
while every record's scope was the same shape; object- and list-valued
fields are skipped now, with the reason written down.

**32 tests that used to skip themselves now run**: 4 796 pass where 4 764
did, and 150 skips where there were 182.

**59 documented filters sat over a field nothing ever filled.**
17 % of the filters this mock derives from the swagger pointed at a member
that was empty in every seeded record — so each one could only ever answer
with nothing, and 91 tests skipped themselves with "no scalar value to
filter by" rather than exercise them. Three records were half-written:

* an **indicator** kept almost none of the intelligence it arrives with —
  no severity, category, labels, campaign, malware or actor names, no
  batch, creator or external id, and no upload time. All eleven are filled
  now, the actor and its type drawn together so a record's two members
  agree, and `uploadTime` derived from `creationTime` rather than drawn
  beside it;
* a **device-control rule** described its device by class alone. It carries
  the vendor, product and device ids, the manufacturer, name, uid and
  version now — and a Bluetooth rule its minor classes and services, since
  which members a rule fills follows the interface it is written against;
* an **agent** had no external id, cloud provider, storage type, proxy
  method, missing permissions or user actions. The last two come from the
  swagger's own enums, so `enum_drift.py` holds them to it.

13 remain, over five routes — and four of the twenty-two this first
reported were the probe's own doing, not the seeder's: it did not descend
into a list, so `scopeRoles.roleId`, `locations.id` and two others read as
empty where the value was there all along.

A threat carries the rest: the cloud provider of the endpoint it was found
on, so the two describe the same machine; a ticket id where it has been
raised with a ticketing system, both members having been fixed at "no
ticket, ever"; and the publisher that signed the file, most detections being
unsigned. The schema test caught the first attempt at
`cloudProviders`, which put the provider's name in a member of its own where
the swagger keys the object by provider — a good catch, and the reason the
shape is right now. 27 tests that used to skip themselves now run: 4 791 pass where 4 764
did, from 182 skips down to 155.

**A test looked for a substring nothing had.**
`test_filter_contains_function` asked Defender for machines whose name
contains `WS` and asserted at least one came back. `WKSTN` does not contain
it — the letters are not adjacent — so it had been passing on whichever
generated name happened to, and a seeder change that shifted the draw ended
that. It takes its needle from a name the install actually has.

**`date-time` is a format, not a type.** Advertising the declared kind of
each documented filter — right in itself — wrote `"type": "date-time"` into
85 parameter schemas of this mock's own `/openapi.json`, and JSON Schema
knows seven types of which that is not one. A client generating code from
the document would have choked on every dated filter. They read
`{"type": "string", "format": "date-time"}` now, and a test walks every
parameter schema in the document for a type JSON Schema does not know.

**The console's route sweep proved a page had rendered, not that it worked.**
75 of the 92 end-to-end cases visited a route and ran axe over it. axe
reports what is wrong with the markup a page rendered and finds nothing
wrong with markup a page never rendered — so a blank shell, a view whose
data call was refused, and a page whose script threw all passed. The sweep
now also requires the page to show its own heading (or, on a detail page,
some content: those eight views carry no `h1`) and refuses to pass a page
that asked the backend for something it was told no to.

It failed on 33 of 92 the first time it ran, and every finding was the
console's, not the mock's:

* **Graph, Sentinel and Defender could not authenticate at all.** All three
  omitted `scope` from their client-credentials grant, which Entra requires
  and answers `AADSTS900144` without. Every page in those three sections
  showed its empty state — "No users found" over a store holding users,
  "0 of 0 incidents" over fifty.
* **`/alerts` was a blank page.** The view read
  `alert.agentRealtimeInfo.agentComputerName`, and the swagger declares
  `agentRealtimeInfo` on a cloud-detection alert as a *null schema* — the
  endpoint is in `agentDetectionInfo`. It threw, Vue rendered nothing, and
  the old sweep passed it because there was no markup to find fault with.
  The unit test that covered this view fed it a fixture with the shape the
  product does not answer, so it passed too, and its name said
  "renders endpoint names from agentRealtimeInfo". The `Alert` type says
  `agentRealtimeInfo: null` now, which is what found the same read in the
  top bar's alert dropdown.
* **Two Kibana calls used the wrong spelling.** The Cases API takes
  `perPage` on the way in and answers `per_page` on the way out — an
  asymmetry Kibana really has, and the detection engine and exception lists
  beside it take `per_page`. The console sent `per_page` and the snake_case
  `sortField=created_at`. Kibana 8.15 refuses both, in the same words this
  mock does: `invalid keys "per_page"` and
  `Invalid value "created_at" supplied to "sortField"`.
* **The Defender dashboard counted a page and called it a total.** Its cards
  read "Total Machines" over 50 of 60, and its two doughnuts were drawn from
  the same 50. The indicators card asked for `$top: 0` and then counted the
  rows it got back — zero by construction — and was refused outright, since
  that API takes `$top` from 1.
* **Two Graph pages asked for routes Graph does not have.** Autopilot
  deployment profiles are a beta resource, requested under `/v1.0`; the
  file list asked for `drive/items/root/children` where the reference
  records `drive/root/children`. Both answered 404 and both pages showed
  their empty state.

The mock was right in every one of them, which is the outcome its own rule
asks for: a client that would break against the product breaks against this.

**Two Defender records named their machine and reported no name for it.**
The docs' own property tables record `computerDnsName` beside `machineId`
on an alert, an investigation and a machine action. The investigation had
carried it from the first commit, seeded from the machine; the alert and the
machine action did not, and both answered an empty string while
`/api/machines` had the name all along. A client reading an alert to find
the affected host found nothing, and one correlating alerts to machines by
name matched nothing at all. `rbacGroupName` on an alert was the same: the
group belongs to the machine and the alert reported none. Both carry the
name now, seeded and on a fresh action alike, which is what the
investigation beside them had been doing all along.

(The commit that made this change says "none of the three". Two: the
investigation was already right, and it is the precedent the other two
should have followed.)

A machine action also drew `creationDateTimeUtc` and
`lastUpdateDateTimeUtc` independently, so it could report having been
updated before it was requested. That pair — and `dateJoined`/`lastLogin` —
are in the ordering test's list now; neither was.

**Measured and already right: what a threat says about its agent.**
Ten denormalised members on a SentinelOne threat — the computer name, the
OS, the agent version, the uuid, the site and account — agree with the agent
record on all thirty threats, as do the alerts. Referential integrity holds
across twenty seeds as well: no alert, threat, agent, group, exclusion, rule
or tag names a record the install does not have.

**A site's active licences were a random number between 50 and 200.**
"Number of active licenses for the site", and the licence surface each site
answers beside it is named `Total Agents` with a count equal to
`totalLicenses` — so the unit is an agent and an active licence is an agent
using one. The seeder drew a random number instead, and a site holding 18
agents answered 76, a figure no other answer of this mock agreed with and
that never moved when an agent did. It is the agent count now, and
`allSites.activeLicenses` adds up to the sixty agents that exist.

Stored rather than counted on the way out, and that distinction cost a
round: computing it in the query left `?activeLicenses=18` and
`?sortBy=activeLicenses` reading the record while the answer said something
else — which is the exact defect this release spent the day removing, one
field over. Agents are seeded after their sites, so the count is written
once both exist.

**An agent could report having been updated before it existed.**
`createdAt` was drawn as "some point in the last 200 days" and `updatedAt`
as "some point in the last day", independently, so an agent registered
within the last day could carry the later date first. `rand_after` was
written for exactly this and the agent seeder had never been converted;
`groupUpdatedAt` and `lastActiveDate` had the same shape. Ten consecutive
runs of `test_seed_referential_integrity` pass where the eighth had failed.

It surfaced by accident: removing the random draw above shifted every
subsequent draw, and a different sequence hit it. A test that only fails on
some seeds had been passing on the seeds it was given.

**An account's licence total did not follow its sites.**
`totalLicenses` is "the total number of licenses on all Surfaces for all
Bundles" and nothing kept it: adding a fourth site of ten licences left the
account answering the 1500 the first three hold, and raising that site to 90
changed nothing either. `numberOfSites` beside it was kept by an increment
and a decrement, which is one missed call site away from the same drift.
Both are counted from the sites now — on a create, an update and a delete —
so the account and its sites cannot come apart.

**Measured and already right: `activeAgents` is every agent.**
The name reads like a subset and the answer says 60 where 48 agents are
active, which looked wrong until the swagger's own description settled it:
"Total Agents in the Account". `numberOfAgents` and `numberOfUsers` are
absent from the answer for the same kind of reason — the account's response
schema does not declare either.

**Measured and already right: an API token is shown once.**
A user's `apiToken` comes back from the create and is `null` in the list and
in a fetch by id, which is what the code's own comment claims and what the
critical test holds it to.

**A user scoped to one site saw every site.**
`scope` is declared with the enum `["tenant", "account", "site"]`, and this
mock answered `scope: "site"` and the site roles that go with it while
showing that caller all sixty agents across all three sites. It was
answering a boundary it did not have, so a client testing least privilege
against it got a pass it would not get from the product.

`TenantScopeMiddleware` already enforced the account axis, and its own
comment records why: "the scoping was inert and every caller saw the whole
store". That is this sentence one axis over. A caller whose user is
`scope: "site"` is now confined to the sites their roles name — 18 agents
for one site, 39 for two — and asking for a site they do not hold returns
their own rather than the one they asked for, which is how the account
branch beside it already guarded its axis. The user record is read rather
than the token, so a scope changed after a token was issued takes effect on
the next request rather than the next token.

Nothing seeded changes: all three seeded users are `scope: "tenant"` with no
site roles, and the account axis stays invisible because this mock seeds one
account, so confining to it removes nothing. Three sites is what made the
site axis measurable at all.

**Measured and already right: an action route's `filter` selects.**
136 SentinelOne write bodies document a `filter`, and 8 of those routes
answer with a count this can be read from. Given an id nothing has, each
affects 0; given a real one, each affects 1 — in both directions, which is
the pair `filter_effect.py` established for body filters. Three of them
looked wrong at first and were not: the probe had been sending a *threat* id
to the two alert routes and to `/users/delete-users`.

**Measured and already right: a delete removes the record.**
Six delete routes were exercised — take a record, delete it, re-read the
listing — and none of them left it there. Three answer `200` to a second
delete rather than `404`, and that is not a defect either: `DELETE
/users/{id}` is documented with `200`, `401` and `403` and no `404` at all,
`/exclusions/{id}` is one of the nine routes `param_drift.py` already counts
as unpublished, and `/_dev/` is mockdr's own surface, which imitates
nothing.

**Seven more members a write accepted and dropped.** `billingMode` and
`usageType` on `POST /accounts`; `externalId`, `salesforceId`,
`unlimitedExpiration` and `makeSocDefaultUi` on the account create and
update, all four declared in the account's own answer schema and held by
nothing; and `templateRuleId` on a STAR rule, so a rule made from a template
answered without the template it came from.

A rule created through the API also named its author differently from every
rule this mock seeds: `creator` carried the user's *id* where the swagger
reads "the full name of the user that created the rule". It carries the name
now, and the rule gets the same `scope`, `siteId`, `accountId` and counters a
seeded one has, so the two are the same kind of document.

**The updates dropped what the creates had just been taught to keep.**
Each update command lists the members it applies, and the lists were shorter
than the bodies the swagger documents: `rank` and `isDefault` on a group,
`allowRemoteShell` and the scoped roles on a user, `billingMode` and
`usageType` on an account. Every one was answered `200` and discarded, and
read back as the value it had before.

**`PUT /sites/{id}/reactivate` cleared the expiration it was given.**
The swagger documents two members on that body — `unlimited`, whose
description reads "if false an expiration should be supplied", and
`expiration`, "new expiration date for the site". The route took no body at
all and always set the expiration to null, which is the opposite of what
the two members are for: a client reactivating a site for another year was
handed one with no expiry and told it had worked. It reads them now, and a
bodyless call still works, because the swagger marks `data` required only
*within* a body that is sent and every client here has always called it
without one.

Teaching the route a body made mockdr's own documented-body guard refuse
that bodyless call with a `400` — an absent body is not an unrecognised
body, and four of this repo's own tests said so. The guard judges only a
body that was actually sent; a route whose reference marks the body required
is refused by its own model before the guard runs.

**`PUT /tenant/policy` answered 200 and changed nothing.**
The swagger documents 51 members on that body and the policy record carried
8, and `update_policy` sets what the record has and drops the rest — so a
client turning on anti-tampering, enabling snapshots, setting a
decommission window or any of 43 other settings was told it had worked, and
read back the value it had before. Not even a careful client that re-reads
could see it: the answer came from the fixture completion, which never
changes. The record carries all 43 now, with the defaults it was already
answering, so nothing a client reads is different — what changed is that a
write to them sticks. The nested settings stay one line each: an empty
object is completed from the fixture on the way out, exactly as `engines`
already was.

Four members of that same body belong to the server and now refuse it:
`createdAt`, `updatedAt`, `userId` and `userFullName`. Sending the whole
document back would otherwise have let a client rewrite its own audit trail.
`createdAt` also answered `2018-02-27T04:49:26.257525Z` — the swagger's
example, on every policy in an estate seeded around today — and `userId` the
example account id, which names no user this mock serves. Both are seeded
now, and an update records who made it.

**Three creates dropped eight documented members between them.**
`inject`, `pathExclusionType` and `actions` on an exclusion; `rank` and
`isDefault` on a group; `allowRemoteShell`, `siteRoles` and `tenantRoles` on
a user. Every one of them is documented on the create body, every record
already had a place for it, and each create listed the members it read with
these left out — so they were answered `200`, discarded, and read back as
the defaults.

`body_audit.py` could not see any of this and still cannot: it asks whether
a route *reads* its body, by refusing `{}` and an undeclared member, and
every route here refuses both. Whether the members it accepts are *applied*
is a different question, and `tests/integration/api/test_write_takes_effect.py`
is where it is now asked.

**Every Elastic case was filed by a user no Elastic install has.**
`elastic` is Elasticsearch's reserved superuser and carries no profile: the
cluster answers `GET /_security/user/elastic` with `"full_name": null,
"email": null, "metadata": {"_reserved": true}`, and Kibana repeats that
wherever it names a user. `utils.es_case_serde` already held the shape,
measured against 8.15 — and the case seeder wrote an invented
`"Elastic Admin" <elastic-admin@acmecorp.internal>` beside it, so every
case's `created_by`, `updated_by` and `closed_by` carried a name and an
address that exist nowhere, and `/api/cases/reporters` published them to the
filter drop-down. Two copies of one measured fact is how they came apart;
the seeder uses the constant now, and a test asserts they are the same
object. `GET /api/cases/reporters` is byte-identical to Kibana 8.15's answer
again, and the Elastic conformance suite is back to 0 findings from 2.

**Four Defender resources answered one property under two spellings.**
Microsoft's property tables are camelCase almost everywhere and not quite —
the `machine` table lists `onboardingstatus`, `software` lists `Vendor` and
`Weaknesses`, `investigation` lists `ID` and `State` — and the completion
matched those keys exactly, so the record's spelling and the table's both
reached the answer. A machine carried `onboardingStatus: "Onboarded"` *and*
`onboardingstatus: ""`, and a client whose JSON mapper ignores case (the
default in .NET, and common elsewhere) could bind the empty one and read the
machine as never onboarded. `software` did it twice and `investigations`
once. The completion matches case-insensitively now and keeps the spelling
the record carries — the one every neighbouring name in the same table
shares, and the one the products answer.

**`$filter` refused properties the same route answers.**
The OData property table was built from each route's *recorded sample*,
which is a subset of the entity's: the `machines` sample records 18 names
where the docs' own `machine` table lists 21. So
`$filter=deviceValue eq 'Normal'` came back `400 Could not find a property
named 'deviceValue'` from a route that answers `deviceValue` on every
record, and `ipAddresses` and `osArchitecture` were refused the same way.
The entity's table joins the route's now, matched case-insensitively for the
same reason as above. A name that exists in no spelling is still refused.

**Measured and stated: five machine properties nothing documents.**
`osVersion`, `sensorHealthState`, `managedBy`, `managedByStatus` and
`vmMetadata` come from this mock's own domain model and appear in no
vendored Defender reference — `scripts/schema_drift.py mde` has been listing
them as undocumented all along, and `$filter` on them is refused because
nothing speaks for them. Left as they are: removing a field is the kind of
scope decision that has always been made deliberately here, not in passing.

**Every STAR rule said it had never fired.**
Nothing set `generatedAlerts`, `lastAlertTime`, `creatorId` or `updaterId`,
so all four came from the swagger's examples: all twenty rules answered
`generatedAlerts: 0` and `lastAlertTime: "2018-02-27T04:49:26.257525Z"` —
one 2018 timestamp, in an estate seeded around today — while each of them
had an alert seeded within the last few weeks. Both id fields carried the
swagger's example user id, which resolves to no user this mock serves, so a
client following a rule to its author found nobody. The counters come from
the alert the rule actually generated now, and the author is the `Admin
User` record in the store. `updater` itself is declared as a null schema in
the swagger, so the answer carries `null` there whatever is stored, and
nothing is.

**Measured and not built: `editable` is `false` on every rule.**
The swagger reads "true if the rule can be modified at this scope level",
and this mock serves `GET`, `POST` and `DELETE` for these rules but no
update — so `false` is the honest answer for as long as that is true. It
becomes wrong the day an update route is added.

**Two probe artifacts, recorded so they are not rediscovered as defects.**
`installed-applications` looked like it answered `agentNetworkStatus:
"connected"` for every row; over the whole 707-row collection it is 501
connected, 146 disconnected and 60 disconnecting, and only the first hundred
rows happen to belong to connected agents. And `/sites` looked like its
`state`, `siteType` and `suite` filters returned everything for an
undeclared value; that route answers a nested envelope, and the probe was
counting the envelope's keys rather than its records.

**A filter could not match a value the answer carries.**
Eighteen documented filters, given a value taken straight out of a record the
same route had just returned, answered `200` with nothing. Three causes, all
of them the same failure from a client's side — it reads a value, filters by
it, and is told there is no such record:

* `str(value or "")` read `False` and `0` as the empty string, so no `eq` or
  `in` filter could ever match either. `?activeThreats=0` found none of the
  agents carrying `"activeThreats": 0`, and eleven boolean fields did the
  same for `false`. Absent is still the empty string; present-and-falsy is
  not absent, and a boolean now matches in any spelling the `bool` operator
  already took (`false`, `FALSE`, `0`, `no`).
* The account record carried no `billingMode`, `usageType` or
  `totalLicenses`, so the answer showed the swagger's example values for all
  three and nothing could filter by them. They are seeded now, and
  `totalLicenses` is the sum it is documented to be — 1500 across three sites
  of 500 — where it answered `0`.
* A STAR rule stored `accountIds`, `siteIds` and `scopeLevel`, none of which
  the swagger declares, while the swagger declares the singular `accountId`,
  `siteId` and `scope`, which nothing set. Every one of the twenty rules
  therefore answered with the same example id, and the documented
  `accountIds`, `siteIds` and `scopes` filters matched nothing. The declared
  fields are seeded from the agent the rule was made for.

`test_generated_filters.py` walked all 344 derived filters and could not see
any of this: it asserted only that a filter does not *widen* the result, and
an empty answer passes that. It now requires a value the route itself
published to find at least one record — the rule `filter_effect.py` already
applied to body filters, reaching the query filters it cannot see.

**`nextCursor` carried a percent-encoded padding character.**
The code claimed "S1 URL-encodes the base64 padding character" and nothing
supported it: 66 response definitions in the swagger give `nextCursor` as
`YWdlbnRfaWQ6NTgwMjkzODE=`, with a literal `=`, and the offset encoder a few
lines below never encoded it either — the two disagreed with each other. A
body is not a URL, and a client that correctly escapes this value for the
query string it goes back into was escaping an escape. Cursors are raw
base64 now; the percent-encoded spelling, and the doubly-encoded one a
careful client made of it, are still read, so anything holding an older
cursor still pages.

**Measured and not built: a cursor this mock never issued returns page one.**
`garbage`, an empty value, base64 of something else, a real cursor with four
characters cut off, and forty nines all answer `200` with the first page —
so a client whose cursor is corrupted in a log, a database column or a retry
pages forever without learning anything is wrong. Both decoders do this
deliberately (`returns 0 on any error`, `yields {}`), and they at least
agree with each other. Left alone because nothing measured says what
SentinelOne answers here: the swagger documents `cursor` as a string and
declares no error for it, and inventing a `400` is the same rule violation
as inventing a route. A real measurement would settle it in one request.

**A timestamp filter no longer answers 200 to a value it cannot read.**
Of the 99 dated filters this mock takes, 47 answered with the whole
collection and 50 with none, for the same unreadable value — `gte_dt` and
`lte_dt` skipped the filter outright, telling a client that had asked to
narrow that nothing narrowed it, while the ordered comparisons fell through
to text, where `"2026-07-21T08:22:15.000Z" > "not-a-date"` is false for
every record ever written. Two more returned an accident of alphabetical
order. All 99 refuse now, in the validation envelope `?limit=abc` already
used. Which parameters are dated is decided on evidence, not on their
spelling: the swagger declares `format: date-time` on 20 of them, and for
the rest the mock's own answer decides — a field whose sampled values are
ISO-8601 is compared as a timestamp. Only ordering operators are affected;
`eq` and `contains` on a dated field are left alone.

Being stricter had to not mean refusing what the product takes, so
`_parse_dt` now reads every ISO-8601 spelling — an explicit `+00:00` offset,
a space separator, seconds without fractions — where it knew three formats
before. All of those filter; only what no ISO spelling and no epoch reading
can parse is refused.

**`installedAt__between` filtered nothing, whatever it was sent.**
It was read here as `START,END` — a spelling nothing documents — while the
swagger gives `<from_timestamp>-<to_timestamp>` in epoch milliseconds, so a
client following the documentation had its range dropped and was handed all
100 applications with a 200. The bespoke implementation is gone and the
parameter goes through the same derived filter as the other ten dated
ranges. The comma spelling is refused: it was mockdr's own invention, and
nothing in the repository used it.

**The generated filter table is sampled from more than one record.**
`gen_documented_filters.py` read a single record to decide what a field
holds, so a field only some records carry — `lastSuccessfulScanDate`, on 29
of 60 agents — looked like anything but a timestamp and its five filters
kept comparing dates as text. It samples a hundred now.

**Every dated range filter answered with an empty list.**
The swagger spells each dated `__between` as
`<from_timestamp>-<to_timestamp>` and gives a 13-digit example
(`1514978764288-1514978999999`) — milliseconds since the epoch — while the
records this mock holds carry ISO-8601. The two were compared as text, and
`"2026-07-21T08:22:15.000Z" <= "1798761600000"` is false for every record
ever written, so *every* dated range answered `200` with nothing: a range
spanning the years 2000 to 2100 returned none of the sixty agents it must
contain, and a client reading that concluded the estate was empty. A
timestamp on one side and a bare number on the other is now read as the
epoch spelling. 11 dated ranges select the range where 0 did; the numeric
ranges the swagger spells the same way (`coreCount__between=2-8`) were never
affected and are unchanged. One consequence worth stating: `createdAt__gt`
and friends, which the swagger gives ISO examples for, now accept the epoch
spelling too. They previously compared it as text, so nothing that worked
has changed — but the mock is more permissive here than anything measured.

**A filter the swagger types now refuses a value that type cannot hold.**
The 2.1 swagger declares forty-odd query filters `integer` or `boolean`;
mockdr took every one of them as text and compared whatever arrived.
`?resolved=maybe` was read as false and answered `200` with all 25
unresolved threats, `?twoFaEnabled=maybe` answered `200` with none, and
`?coreCount__lt=abc` answered `200` with the whole estate — a client with a
formatting bug was handed a filtered-looking result and never told the
filter had not been applied. `?limit=abc` on this same mount has always
answered `400` in SentinelOne's validation envelope; the typed filters now
answer the same way, down to the wording, because they raise pydantic's own
error and let the one measured handler build the body. 87 parameters refuse
a value their type cannot hold where 0 did; the specs carry the declared
type, so `documented_openapi` advertises it too instead of a blanket
`string`. Valid values are untouched: `coreCount__lt=10` still returns
`[2, 4, 8]` and not the lexicographic answer, and an empty value still means
"unset" rather than a type error.

**`param_drift.py` compared parameter names and not their types.**
That is why the above could sit in plain sight: `resolved` and
`coreCount__lt` were on both lists, so they counted as agreed while the mock
read one as text and the other as a string comparison. It now reports the
parameters both sides declare with different types — 4 remain, down from 45.
`array` is excluded by measurement rather than assumption: all 16 222 array
parameters in this swagger are `collectionFormat: csv`, so they travel as
one comma-separated string and a mock that takes a string is right.

**Not fixed, and stated: three parameters whose advertised type still says
`string`.** `infected` on `/agents` and `/agents/count`, and `resolved` on
`/threats`, are declared in the route signature rather than derived from the
swagger. Their *behaviour* is now correct — a non-boolean is refused — but
retyping the signature would also make `?resolved=` a `400`, where every
other filter here treats an empty value as unset. The behaviour is
consistent; the declaration is not, and `param_drift.py` lists it.
`containerizedWorkloadCounts` is the fourth: the swagger declares an
`object` in a query string and nothing measured says how it is spelled.

**`gen_documented_filters.py` emptied its own table on a second run.**
The mock advertises the previous run's output through `documented_openapi`,
so the generator saw its own 343 filters as parameters the routes already
took, found nothing missing, and wrote an empty file — which is what
happened here on the first regeneration. What the generator produced is not
evidence that the route takes it, so its own output is now subtracted before
the comparison, and two consecutive runs produce the same table. It also
wraps the lines it emits, since ruff lints the generated file like any
other and the file's header forbids fixing it by hand.

**Measured and not built: which responses are chunked.**
mockdr sends `Content-Length` on everything, which is splunkd's policy
exactly — that one is right. Kibana sends a length uncompressed and chunks
when it compresses. Elasticsearch decides per endpoint, and not by size:
`_search` chunks at 347 bytes while `_count` sends a length at 71. Of the 22
routes that could be measured, 9 chunk — `_cat/*`, `_search`, `/{index}`,
`_mapping`, `_settings`, `_stats` — and 13 send a length, the split falling
exactly where the response size scales with what the cluster holds. Left
alone: no client behaviour turns on it that I can name, every HTTP library
handles both, and 12 further routes could not be measured with a probe id,
so the table would be incomplete by construction.

**Measured and not built: `%2F` inside a path segment.**
All three products decode it to a slash and keep the segment whole — the
cluster stores a document under the id `a/b` and reads it back, Kibana says
`Saved object [cases/a/b] not found`, splunkd `Could not find object id=a/b`.
mockdr decodes it and *splits*, because Starlette decodes the path before
routing, so `/{index}/_doc/a%2Fb` becomes three segments. The answer is at
least the product's own now — `no handler found for uri [/zzz/_doc/a/b] and
method [PUT]` — but an id with a slash in it works against all three
products and fails against their mock. Keeping the segment whole means
changing how every path parameter is read, which is a bigger change than
this is worth today. The other four encodings agree: `%20` is a space, `%3F`
a question mark, and `+` stays a literal plus, since a path is not a query.

**Elasticsearch has no "resource not found" for a path.**
What it cannot route is a `400` naming the uri and the verb — `no handler
found for uri [/a/b/c/d] and method [GET]` — in the bare-string error shape
it keeps for the HTTP layer. The one exception is a two-segment path:
`/{index}/{type}` is the typed create endpoint 8.x removed, and the pattern
is still registered, so every verb but `POST` is told it takes `POST` while
`POST` itself finds no handler. A doubled slash is an *empty* segment, so
`/{index}//_search` is three of them and matches nothing. mockdr answered
`404 resource_not_found_exception` to all of it, which is a status
Elasticsearch never sends for a path. Eleven shapes compared afterwards,
none differing.

The doubled slash is a third answer again: splunkd collapses it and serves
the request, Kibana answers its ordinary 404, and mockdr already matched
Kibana.

**A paused job says `PAUSE`, and a finalized one says so.**
Two states a client branches on, both wrong for the same reason: they were
the spelling and the value that read naturally rather than the ones
splunkd sends. `pause` puts the job in `PAUSE` — not `PAUSED` — and
`unpause` returns it to whatever progress it had reached. `finalize` stops
the search early and sets `isFinalized: true`, where a job that ran to the
end reports `false`; mockdr took that member from a fixture and answered
`false` to both, so a client asking whether the results it holds are the
whole answer was told they were. Measured on 10.4.2, the spelling twice.

**A job that has not started carries 36 members, not 67.**
Dispatching a search and polling `isDone` until it is true is the standard
way a SOAR connector talks to Splunk, so the *first* answer that loop reads
is a job that has not finished — and mockdr was answering it with a finished
job's document. Measured on 10.4.2 state by state: a job carries 36 members
while PARSING and 65 the moment it reaches RUNNING, 69 when done. The 34
that appear at that one transition include every counter a client reaches
for — `eventCount`, `resultCount`, `scanCount`, `runDuration` — so a
connector reading them on its first poll got a number from the mock and a
missing key from the product. mockdr sent 31 of the 34 from the first poll.

The dispatch window that walks a job through the states already existed and
is off by default, which is why this only ever showed on the installs that
turn it on — the ones testing exactly that loop. QUEUED is treated like
PARSING: it comes before it and cannot carry more, though it is too brief to
catch on a live instance and is inferred rather than measured.

**A write is not searchable until a refresh, and a delete still is.**
Elasticsearch is near real time. `PUT /{index}/_doc/{id}` without a refresh
answers 201 and the document is *not* in the next `_search`, though
`GET /_doc/{id}` finds it at once: a get reads the live state, a search
reads a snapshot. A delete is the mirror — gone to the get, still there to
the search — until a refresh. `_bulk` obeys the same rule.

mockdr made every write searchable immediately, which is the dangerous
direction: a client that wrote and immediately searched worked against the
mock and failed against the product. Fifteen of this repo's own tests were
doing exactly that, and now send the `refresh=true` a real client must.

`refresh=wait_for` turned out to be two questions, not one: it makes the
write searchable — it waits for the next refresh and *then* answers — but
the response carries no `forced_refresh`, which `refresh=true` and a bare
`?refresh` both do. mockdr had one function answering both; it has two now,
each naming what it decides. Measured on 8.15 for writes, deletes and bulk.

**A path that ends in a slash: two products serve it, one redirects.**
A client that builds its URL by joining a base and a path lands on one
constantly. Elasticsearch serves `/{index}/_search/` and every other shape
tried; splunkd serves `/services/...` and `/servicesNS/...` alike; Kibana
answers `302` pointing at the path with its slashes percent-encoded —
`/api/cases/_find/` becomes `location: /api%2Fcases%2F_find`, which then
answers 404 when followed. mockdr answered 404 to all three. `/elastic/` is
the cluster's own root and keeps its slash.

**`GET /_alias` was nobody's route.**
Read as an index name, `_alias` answered `invalid_index_name_exception`
where the cluster lists every index and the aliases it carries. Found by
asking what a trailing slash does: `/_alias/` strips to `/_alias`. The query
behind it already existed and its docstring already said "for `GET
/_alias`"; only the route was missing.

**splunkd's argument values are already exact**, which is worth recording
as the negative it is: `count=abc`, `count=`, `count=-1`, `offset=abc` and
`count=1.5` all answer 200 with the same paging on both sides — including
`count=-1`, where `perPage` comes back as 18446744073709552000.

**A uri parameter fails as an `illegal_argument_exception`, not a parse error.**
The reason text was already right — `Failed to parse int parameter [size]
with value []` — but the *type* was `parsing_exception`, which is what a
malformed body carries. A uri parameter is read before the body is parsed at
all, and a client branching on the type saw a body error for a query it had
not got wrong.

**A time value is a number and one of seven units.**
`nanos`, `micros`, `ms`, `s`, `m`, `h`, `d` — and not `w` or `y`, though
other parts of the stack take those. A bare `5` is not one either. Anything
else is `failed to parse setting [timeout] with value [5] as a time value:
unit is missing or unrecognized`, and a negative one is fine. mockdr took
`timeout` and `scroll` as any string at all and searched anyway, so a client
that sent a duration the cluster refuses got results from the mock.
Twenty-one values compared against 8.15 afterwards, none differing.

**An empty query value is a zero to two validators and a string to the third.**
`?perPage=` on the Cases, detection-engine and lists APIs answers 200 with
the page size at 0 — the real `total` beside an empty page — and `?page=`
becomes page zero, refused for being *out of range* in each API's own words:
`[from] parameter cannot be negative but was [-20]` on Cases, `page: Number
must be greater than or equal to 1` on the detection engine. config-schema
does not coerce at all: to it an empty value is a string, and the answer is
`[request query.page]: expected value of type [number] but got [string]`.

mockdr refused four page sizes the product accepts and answered pydantic's
wording on six routes. Every query member it declares was asked of 8.15
empty and absent: 38 of 56 agreed before, 50 after. Two of the remaining six
are routes where Kibana itself answers a 500 (`/api/lists/_find?page=` and
`/api/osquery/packs?page=`), which is not imitated; the rest are the
endpoint APIs, where a Basic licence answers 403 before anything else.

One 500 of mockdr's own was made and found on the way: reading the empty as
zero *everywhere* let it past config-schema, which then crashed on
`float("")`. The two readings are separate functions now, each saying which
validator it belongs to.

**A query member given twice is refused for a scalar and taken for an array.**
`perPage=1&perPage=3` on the Cases API is a 400; `status=open&status=closed`
beside it is a 200, because that member is declared as an array. mockdr took
the last value and answered 200 for both, so a client whose URL builder
appended a filter twice read a page from the mock and got a 400 from the
product. Every query member mockdr declares was asked of 8.15 once and
twice — 29 of 56 refuse — and the wording is the route's own validator's, in
three dialects and two types: config-schema's `expected value of type
[number] but got [Array]`, io-ts's `Invalid value "["1","2"]" supplied to
"page"` (with the `[request query]: ` prefix on the exception-list API and
without it on Cases), and zod's `Expected number, received nan`. Which
members are scalars cannot be read off mockdr's own signatures — they are
all `str` there on purpose, so that FastAPI's 422 never pre-empts Kibana's
wording — so the table is the measurement. All 56 compared afterwards,
wording included, none differing.

Elasticsearch was asked the same question and takes the last value:
`size=1&size=2` returns two hits, `size=2&size=1` one. mockdr already did
the same.

**`hostile_probe` never sent a hostile credential header, and a 500 walked through.**
Everything it does authenticates *correctly* first and then sends hostile
bodies and queries, so the one header every client must get right was the
one input never made hostile. Teaching the Basic decoder to raise — so the
five refusals below could be told apart — turned every malformed header on
`/api/status`, a route that serves anyone, into `500 Internal Server Error`.
The whole test suite passed. Ten malformed credentials are sent to every
route now, 29912 requests over 515 paths, and the defect was put back once
to watch the audit name it.

splunkd was asked the same question and mockdr already matched it exactly on
all seven headers: `ERROR "Unauthorized"` for anything Basic-shaped or
unknown, `WARN "call not properly authenticated"` for the token schemes —
two answers that differ in their message *type* as well as their text.

**One 401, five reasons, and mockdr gave the same one to five of six.**
Elasticsearch tells apart a request that carried no credentials, one whose
header it could not read, and one whose credentials were wrong — and it
words the two unreadable `Basic` cases differently again: bytes that are not
base64 are an *encoding* failure, base64 without a colon a *value* failure.
A scheme with nothing after it, and a scheme it does not know, are both
`missing authentication credentials`, not bad ones. `ApiKey` and `Bearer`
share a wording of their own that names neither user nor path. mockdr
answered `unable to authenticate user for REST request [...]` to five of the
six, so a connector with a mangled header was told its credentials were
wrong. Seven headers compared against 8.15 afterwards, all agreeing.

**`Accept` is ignored by all three products**, which is a finding of its own
kind: Elasticsearch falls back to JSON for anything it cannot produce and
never refuses, Kibana and splunkd answer JSON whatever is asked. mockdr
already did the same, so nothing changed — the sweep is recorded so nobody
asks again.

**Kibana's three answers to a content type, and none of them Elasticsearch's.**
Hapi decides after routing and only for the verbs that carry a payload, so a
`GET` is never judged. A header that is not `type/subtype` — `json`,
`text/`, `/plain` — is `400 Invalid content-type header`; `text/*` and the
four it parses reach the route, which answers about the body; every other
syntactically valid media type — `application/yaml`, `application/xml`,
`foo/bar`, `*/*`, `application/*` — is `415 Unsupported Media Type`. A
header that is *absent* is parsed, not refused, and the body need not be
there at all, which is where this differs from Elasticsearch's 406. mockdr
answered pydantic's 400 to all of them. Fourteen types compared against 8.15
afterwards, all agreeing. The Boom envelope's status-title table had no 415
either, so every one of them would have read `Internal Server Error`.

**A body under a content type Elasticsearch cannot read is refused, not parsed.**
8.15 answers `406` — not the `415` one would guess — with the bare-string
error it also uses for a 405: `{"error": "Content-Type header [text/plain] is
not supported", "status": 406}`. It reads six types, and only judges the
header when there *is* a body: a GET with none, or a POST with an empty one,
is served whatever was sent. mockdr read every body as JSON and answered a
`parsing_exception` — a 400 about the content where the product refuses the
header, which sends a client that forgot `Content-Type` looking at its query.

Deliberately not imitated: the cluster answers *in* the format asked for, so
`application/yaml` comes back as YAML and `application/cbor` as CBOR. Those
types are accepted here, read as JSON and answered in JSON; refusing them
would invent a 406 the cluster never gives, which is the worse of the two. A
body that really is YAML, CBOR or SMILE is therefore not parsed.

Six repo tests had been posting `_bulk` and `_msearch` bodies with no
`Content-Type` at all, which the cluster refuses outright; they send
`application/x-ndjson` now, as a client must.

splunkd was asked the same question and ignores the header entirely — four
types, four 200s — so there is nothing to imitate there.

**Kibana's versioned routes say which version they are.**
8.15 registers some routes through its versioned router and the rest
plainly, and only the versioned ones answer with
`elastic-api-version: 2023-10-31`. It belongs to the *operation*, not the
path or the family: `GET /api/exception_lists/_find` carries one and
`GET /api/exception_lists/items/_find` does not; `GET /api/endpoint/action`
does and `GET /api/endpoint/action_status` does not. The header comes from
dispatch, so a handler's own 500 carries it — `GET /api/timeline` with no id
— while a query-schema refusal, raised before the handler runs, carries
none. mockdr sent it nowhere; all 48 of its Kibana GET routes now answer
exactly as 8.15 does. The 34 write operations are unmeasured rather than
known to carry none: neither a query-schema nor a body-schema refusal
carries the header, so measuring one means letting it succeed, and that
means creating objects on the probe instance.

**Every answer addressed through a search job now points back at the job.**
splunkd sends `Link: <sid>; rel=info` on the job and everything under it —
on 200, 204, 404 and 405 alike — and the link is relative to the request:
`<sid>` for the job, `<../sid>` for a sub-resource, `<../../sid>` one level
deeper. The collection carries none, and neither do `jobs/export`,
`typeahead` or `parser`, which are not jobs. A client following it reaches
the job a partial answer belongs to, which is why a 204 from `/results`
carries one. Measured on 10.4.2 against a job that exists and sids that do
not; mockdr sent none at all.

**`_search/scroll` ignored the id it said it took, and refused before it validated.**
The route declared `scroll_id` as a query member and then read only the
body, so a client scrolling the documented way was told its perfectly good
id could not be parsed — a 403, for a call that was correct. And naming no
id at all is a *validation* failure, which runs before the security layer:
`400 Validation Failed: 1: scrollId is missing;`, where an id that is
present but unparsable is the 403. mockdr gave the 403 to both. Found by
sweeping response headers across the three live products and noticing that
one Elasticsearch route out of 32 was missing `X-Elastic-Product` — the
symptom of a refusal raised before the handler ran.

**The threat-intelligence metrics were the wrong shape at every level.**
`ThreatIntelligenceMetricsList` is a *list*: `{"value": [{"properties":
{...}}]}`, and every metric entry is `{metricName, metricValue}`. mockdr
answered the properties object alone and named its entries `patternType` and
`source` beside a bare `value`, so a client reading
`value[0].properties.patternTypeMetrics[0].metricName` found nothing at any
level — and `threatTypeMetrics` was absent altogether. Found by
`schema_drift`, which could not reach the route at all while mockdr served
it on `POST`: correcting the verb is what made the comparison possible.

**`schema_drift` runs in CI now**, for all six mounts it supports — 36
CrowdStrike routes, 42 MDE, 52 Cortex XDR, 20 Sentinel, 53 Graph, 39
SentinelOne, none drifting. It needs nothing but the mock and a
specification, which is the audits job's whole premise, and it would have
caught the metrics shape long before a person did.

**Sentinel's tag operations acted on a path and a field the vendor does not have.**
`ThreatIntelligenceIndicator_AppendTags` and `_ReplaceTags` name one
indicator in the path and take `{"threatIntelligenceTags": [...]}`. mockdr
had invented a bulk pair on the collection — `/indicators/appendTags`,
reading `indicatorNames` and `tags` — which no client generated from the
2024-03-01 SecurityInsights swagger would ever call. The two also differ in
what they answer, which is not something anyone would guess: append gives
200 and no body, replace gives the indicator back. And both wrote into
`labels`, the STIX field the swagger declares *beside*
`threatIntelligenceTags`, so a client that tagged an indicator and read the
tags back saw nothing happen. `ThreatIntelligenceIndicatorMetrics_List` is a
`GET`, where mockdr served it on `POST` alone.

Found by finishing the path-and-verb sweep against every vendor spec the
repository holds — Graph, CrowdStrike, Sentinel and MDE. The three Sentinel
paths still unmatched are the two Entra token endpoints and the Log
Analytics query API, which are other services.

An earlier draft of this entry claimed mockdr emitted 15 of the 28
properties the swagger declares on an indicator. That was read off the
source rather than measured, and it was wrong twice over: the response
carries every declared member, and the two it appeared to add
(`additionalData`, `friendlyName`) are declared too. `schema_drift` had it
right all along — it resolves the `kind` discriminator to
`ThreatIntelligenceIndicatorModel` and compares 44 declared paths against 30
seen, the difference being members of array elements where the arrays are
empty. Sentinel's fields are watched, by that comparator.

**Four Kibana routes that answered before the query schema had spoken.**
The schema check runs before the handler, so an unknown query member is a
400 naming it — whatever else the request is wrong about.
`GET /api/cases/{id}` resolved the case first and answered its 404, telling
a client its id was wrong when its spelling was; the three exception-list
routes answered their handler's `id or list_id required`.  Worse, with the
required member actually present they answered **200**:
`?list_id=<real>&zzzTypo=1` came back with the list, so a client that had
misspelled a second filter read a full answer from the mock and got a 400
from the product.  Each route's accepted set measured member by member on
8.15 against the undeclared-versus-bad-value oracle: `/api/cases/{id}` takes
`includeComments` and nothing else, `/api/exception_lists` takes `id`,
`list_id` and `namespace_type`, `/api/exception_lists/items` takes `item_id`
where the list route takes `list_id`, and only `/summary` also takes
`filter`.  `list_id` was declared on `/api/exception_lists/_find` too, and
filtered there — Kibana refuses it outright, so that filter worked in
testing and 400s in production.

**`includeComments=false` empties the comment list; it does not drop it.**
The key is there either way, which is what a client reading
`case.comments.length` depends on, and absent behaves as `true`.  The member
must be one of the two literals — `1` is a type error, not a truthy value —
and the wording is config-schema's `expected value of type [boolean] but got
[string]`, not pydantic's.  Measured against a throwaway case with one
comment on it.

**io-ts words the same refusal two ways.**
The Cases API leaves the `[request query]: ` prefix off and the
exception-list API keeps it — four routes each, measured one by one.  A
fourth dialect now, because a substring check took one for the other.

**`scripts/kbn_param_audit.py`**, the Kibana counterpart to the parameter
audits for Elasticsearch and splunkd: 152 questions across 48 routes, in
both directions — every route asked whether it refuses an unknown member and
in exactly which words, and every member mockdr declares asked of Kibana.
It compares the whole message rather than a phrase inside it, which is what
catches a refusal given in the wrong dialect.

**Three Kibana routes that resolved an object the product does not.**
Every verb each of the 72 Kibana routes does not take, asked of 8.15 and of
the mock — 123 of 128 questions already identical, and 218 left unasked
because a destructive verb at a path with no parameter names nothing to
miss. Four of the five differences turned out to be about the `GET` behind
the `HEAD`, not the verb. `GET /api/timeline` answers `500 please provide id
or template_timeline_id` when *neither* `id` nor `template_timeline_id` is
there at all, and `200 {}` as soon as either is — an empty `id=` included;
mockdr answered `{}` to both, so a client that had built its URL without the
id read "no such timeline" where the product told it what it had forgotten.
`/api/cases/{id}/comments` and `/api/cases/{id}/user_actions` never look the
case up: a case that does not exist is `200 []`, where mockdr borrowed the
saved-object 404 that `GET /api/cases/{id}` beside them does answer — so a
client listing the comments of a case it had just failed to create was told
the wrong call had gone wrong. Two repo tests had asserted the invented 404
and are now the measurement. Left measured and not served:
`GET /api/cases/{id}/alerts`, which Kibana routes and mockdr answers from the
unmatched-route fallback. Deliberately not imitated: `GET /api/endpoint/action`,
where the probe container answers `403 Endpoint authorization failure`
because response actions need a licence it does not have.

**`_cat/indices` listed the indices foreseen, not the ones that exist.**
It walked a fixed table of built-in prefixes, so a client could create an
index, write documents to it, read them back and find it through
`GET /{index}` — and then not see it in the listing it asks for to check its
own work. Four answers, three of them right, and the wrong one a 200 with an
empty place where the index should be.

**Six verbs the cluster serves and mockdr refused.**
Every verb each Elasticsearch route does not take, asked of 8.15 and of the
mock: 177 questions, 161 already identical. `_flush`, `_refresh`, `_analyze`,
`_validate/query`, `_terms_enum` and `_msearch` answer a `GET` with the same
body as a `POST`, byte for byte, because a client may carry its query in the
body of a GET — while `_forcemerge` and `_cache/clear` sit right beside them
and refuse it with a 405. No rule accounts for the split, so both halves are
the measurement. A mapping update is accepted on `POST` as well as `PUT`, and
`DELETE /` is the delete-index endpoint reached with nothing named: the
cluster says which argument is missing where mockdr refused the verb, sending
a client that had built its URL from an empty variable to look in the wrong
place. Left measured and not served: the writable alias family and
`GET /_cat/aliases`, which are a feature and not a refusal to reword.

**Elasticsearch's 405 names the uri with its query string.**
`[/{index}/_search?size=1]`, not `[/{index}/_search]` — and that message is
what ends up in a client's log. Measured on two unrelated endpoints.

**splunkd decides in an order, and the order is visible from outside.**
For every splunk route mockdr serves, the verb it does not take, asked of
10.4.2 and of the mock: 27 of 31 agreed. The search service says FATAL
`Method Not Allowed` for the job collections *and everything addressed
through a job* — `{sid}`, `control`, `results`, `events`, `summary`,
`timeline`, `search.log` — while `jobs/export`, `parser` and `timeparser`
say `The method is not allowed.`; mockdr matched only the bare collections.
`/jobs/{sid}` and `/jobs/{sid}/control` take a write, so the handler runs and
looks the job up: an unknown sid is `404 Unknown sid.` before the verb is
judged at all, where every read-only sub-resource refuses the verb first and
answers 405 with `Allow` even for a sid that never existed, and `PUT` and
`PATCH` are refused above the handler and never reach the lookup. And an EAI
handler maps the verb to an eai action — `DELETE` is `remove` — then looks
for the trailing segment among that action's custom actions, so
`DELETE /saved/searches/{name}/dispatch` is a 404 naming all three and not
the 400 saying there is no target name, on a path that plainly carries one.
Left measured and not served: splunkd takes `DELETE` on
`/authorization/roles/{name}`, `/apps/local/{name}` and
`/admin/macros/{name}`, where mockdr keeps three read-only catalogues.

**`http_contract_audit` was wrong on eight counts, which is why it was never in CI.**
It expected `Allow` on splunkd's search 405s (splunkd sends none, on any
verb), expected the EAI 400 for `PATCH` (a bare 405 everywhere), took
Elasticsearch not to serve `HEAD /{index}/_source/{id}` (it does, 200/404),
and sent `output_mode` and `api-version` to every mount — which
Elasticsearch refuses with a 400, so what it measured there was its own
parameter. Corrected against both live products, it reports nothing, and now
runs in CI.

**A reset that left behind what the API serves back.**
`POST /_dev/reset` promises the initial state and cleared the store, which
does not hold HEC's per-channel acknowledgement ids or the webhook delivery
log. After a reset the next event on a channel carried on counting, and
`/collector/ack` answered `{"acks": {"0": true}}` for an event the reset had
thrown away. Deliberately still not reset, and now said so in the code: the
rate-limit and proxy configuration, which are settings a user set on purpose
rather than data, and the Prometheus counters, which are monotonic by
definition.

**A `runHuntingQuery` spelling the Graph SDKs send and mockdr answered 404 for.**
The documented request line is `POST /security/runHuntingQuery`. The
published v1.0 OpenAPI carries only the namespace-qualified
`/security/microsoft.graph.security.runHuntingQuery`, because the action
lives in `microsoft.graph.security` — and the official SDKs are generated
from that OpenAPI, so an SDK client sends the qualified segment and nothing
else. Both spellings now reach the same endpoint, gated the same way. The
other 59 v1.0 routes were swept for the same shape and for verbs the vendor
does not declare; this was the only one.

**A download that failed is not a specification.**
`data/vendor-specs/sentinel__DataConnectors.json` held 14 bytes reading
`404: Not Found`, committed under a spec's name when a version placeholder
came out empty. Nothing read it, so it answered nothing wrongly — it sat in
the directory the whole repository rests on. One test over all 175 remaining
files now asks that a vendored spec parse and hold something: a file that
cannot be parsed is worse than a missing one, because an audit that globs the
directory counts it as judged.

**Throttling outlived the test that switched it on.**
The rate limiter keeps its config and counters in module globals, outside the
store the re-seed clears. A test switched throttling on at 120 rpm through
the `_dev` route and relied on a later test *in the same file* to switch it
off — which holds right up until xdist puts the two in different workers. It
then throttled everything else that worker ran, and a test asserting on a
response body received the 429 envelope instead: a red build with nothing
wrong in the code under test, seen once in five full runs. The root conftest
puts the limiter back after every test now, and the guard has its own test.

**An empty side is not agreement.**
The conformance comparator skips every path inside a collection that is empty
on either side, and rightly: a fresh Kibana with no rules against a seeded
mock with twenty would report every field of every rule, which is true and
useless. But a probe that declares `needs_seed` has said both targets hold
the same data, and for those a collection empty on one side is not "nothing
to compare" — it is the finding. Skipping it is how a probe scoped to an
index the mock did not list passed while comparing nothing at all. Two `_cat`
probes were also unscoped and listed whatever each target happened to hold: a
cluster that has just started has a closed index, whose `store.size`,
`docs.count`, `docs.deleted`, `pri.store.size` and `dataset.size` are all
null, and the type union then read `null|string` against the mock's `string`
— a CI failure decided by a container's startup timing. Two harness tests
were red on main besides, asserting that every seeded splunk probe compares
values and carries `${sourcetype}`, neither of which fits a probe that reads
a seeded *job* by sid; what a seeded probe must not be is unscoped, which is
what they check now, and six probes that searched all of `index=main` while
claiming the seed now name the run's sourcetype.

**A query member Kibana does not know is a refusal, not something to ignore.**
8.15 checks a route's query schema before the handler runs, and refuses a
member the route does not declare — in three wordings, one per validator:
`[request query.zzz]: definition for this key is missing` on the
config-schema routes, `invalid keys "zzz,qqq"` on the Cases API's io-ts ones,
and `[request query]: Invalid value {...}, excess properties: [...]` on
Timeline's. mockdr answered 200 and ignored the member, so a client that
misspelled a filter read an unfiltered result as a filtered one, and the same
request 400s against the product. Fourteen routes now refuse it the way each
one's validator does — each route's accepted members measured key by key
first, against the 400-versus-not oracle the schema check gives, so nothing
a route actually reads can be refused by it.

That oracle also found the spelling: `/api/endpoint/action` names its filter
`agentIds`, and 8.15 refuses `agent_id` outright. mockdr took the snake_case
one, so a client's filter worked against the mock and 400s in production.

**Three refusals Kibana answers that mockdr answered around.**
`GET /api/endpoint/policy_response` without `agentId` is a 400 naming that
member; mockdr answered `404 Endpoint  not found`, which says an endpoint
with no name does not exist rather than that the caller did not name one.
`GET /api/endpoint/action_log/{id}` requires `start_date` and then
`end_date`; mockdr served `{"data": [], "total": 0}`, so a client that had
forgotten the window was told the endpoint had done nothing.
`GET /api/exception_lists/summary` refuses with `id or list_id required` —
the wording the two exception-list routes beside it already used, while this
one said `list_id: Required`.

**Every job reported the query a fixture had been recorded from.**
A job's `search`, `request` and `eventSearch` came from
`search_jobs.json` alone, so a client polling a job it had just dispatched
read back `search index=_internal | head 5` — somebody else's search, under
HTTP 200. The job now names its own query, and echoes back the arguments the
client actually dispatched with and no others, as splunkd does.
`isGoodSummarizationCandidate` and `reduceSearch` go with them: 10.4.2 sends
neither, in either exec mode.

**`/events` served neither what splunkd stamps on an event nor what it keeps.**
Measured against the same seeded event: splunkd returns `_bkt`, `_cd`,
`_indextime`, `_serial`, `_si`, `_sourcetype`, `linecount` and
`splunk_server` on every event, and mockdr returned none of them — a client
de-duplicating on `_cd` or locating an event through `_si` found nothing to
read, and every event looked identical to every other. What it did return
was the fields it had parsed *out* of `_raw`, which `/events` does not
carry: a client reading `/events` to see what was ingested saw mockdr's
parse of it instead.

**A collection's links pointed at a create target splunkd does not have.**
Every listing answered `{"create": "/services", "_reload": "/services/_reload"}`.
Measured across seventeen collections on 10.4.2, the top-level links are
paths under the collection itself — `/services/messages/_new` — and most
collections offer no `_reload` at all; `authorization/capabilities`,
`server/settings` and `search/jobs` offer nothing. The `create` link is now
derived from the collection, and the four collections that differ from that
name their own. A listing entry also carries no `fields` block — that
appears on a single-entity read, where it lists the members the entity
accepts — and `server/settings` served 6 of its 25 members, with
`mgmtHostPort` as the string `"0.0.0.0:8089"` where splunkd sends the port
as a number.
`scripts/splunk_envelope_audit.py` compares this across every collection and
says which listings mockdr serves empty, so its entry was not compared at
all.

**A parameter the cluster does not know is a refusal, not something to ignore.**
Elasticsearch refuses an unrecognised query parameter before running the
request, naming it and the path it was sent to — and names several of them
alphabetically rather than in the order they arrived. mockdr answered 200 and
ignored them, so a client that wrote `siz` for `size` got a full result set
back where a real cluster refuses outright: an answer that looks right and is
not, which is the worst thing this mock can do. Twenty-two routes refuse it now,
each one's accepted parameters measured one at a time against the cluster's
own oracle — it names an unrecognised parameter and complains about the
*value* of a known one, so the two are told apart by the message and not by
the status. `scripts/es_param_audit.py` asks all of it, 1980 questions across
22 routes, and checks both directions: a parameter the cluster accepts must
not be refused, and one neither knows must be. It earns its keep — a shorter
candidate list had left `ignore_unavailable` off `_stats`, inventing a 400
the cluster never answers, which this repo's own tests caught first. Asking
one parameter at a time has a blind spot too: `source_content_type` is
recognised only beside `source`, and alone reads as unknown.

`_cat/indices` was among them from the other side: `pattern` is the path
segment of `/_cat/indices/{pattern}`, and sharing one handler with the bare
route made it a query parameter there — one the cluster does not know.

The routes that *write* refuse it too now — twenty-one of them, measured the
same way and just as safely, because the refusal precedes the action: a
`DELETE` carrying an unrecognised parameter leaves the document where it
was. mockdr did not, so a client with a typo could empty an index here that
a real cluster would have refused to touch. `es_param_audit.py` covers all
43 routes in both directions, 4859 questions, and it earned its keep a
second time: its own candidate list had left out `index` and `name` — which
nearly every route takes as an alias for its path segment — so mockdr was
inventing a 400 on twenty-one of them.

The sweep also found `/{index}/_mget` answering `{"docs": []}` to a request
that named no documents at all — an empty result reported as a successful
lookup of nothing. 8.15 tells the two empties apart: no body is a
`parse_exception` saying a body or a `source` parameter is required, a body
naming no documents an `action_request_validation_exception`. The route that
takes an index made neither distinction.

**Three routes answered a dialect no Kibana client parses.**
`rules/_bulk_create` let FastAPI answer pydantic's `Input should be a valid
list`; `rules/preview` asked for a `name` alone in the io-ts wording a
different family of routes uses; `signals/assignees` answered one
hand-written `ids is required` for every malformed body. 8.15 words all
three with zod: it names what it got, lists five failures and counts the
rest, and names each member of each block in declaration order — the
assignment's `add` and `remove` inside `assignees`, then `ids`.

Two more findings came out of the last of them. The members are `add` and
`remove`, where mockdr read `assignees_to_add` and `assignees_to_remove` —
so an assignment written the way the product takes it was read as no
assignment at all and answered success. And an assignee is a user id as a
plain *string*, where mockdr read the `{"uid": …}` object it stores
internally, so the same request raised out of the handler.

**One KV Store collection, read back by name.**
splunkd serves a collection's configuration under its own path as well as in
the listing, and mockdr had only the listing — so a client reading back the
collection it had just created met the catch-all's complaint about a missing
target name. The single read carries the `fields` block naming what the
collection accepts, with the first non-empty `wildcard` in this mock: the two
families a schema is written in.

**A page past the result window came back as a page.**
`GET /api/detection_engine/rules/_find` with a `per_page` above
`index.max_result_window` — or a `page` far enough into it, since the limit
is `from + size` and not `size` alone — is refused by 8.15 with the
cluster's own failure relayed, indented under a `Caused by:` and a `Root
causes:` of Kibana's making. mockdr answered the page, so a client asking
for more than the window got one here and a refusal in production. The
schema still speaks first: a `page` that is not a number is zod's
complaint, and reading it as one before the schema ran answered a 500.

**A member of the wrong type read as something it is not.**
The third neighbour of the empty-member question. A `query` of `[]` was read
as "match everything" and answered the whole index; a `sort` of a number was
a 500; `_source`, `stored_fields`, `track_total_hits`, `explain`, `fields`
and `docvalue_fields` were all taken at face value. The cluster reports a
scalar where it wanted an object as though the *key* were unknown — the
parser looked for an object under that name and found something else — and
the members with a shape of their own name it: `_source` lists the four it
takes, `stored_fields` the two, `explain` refuses anything but `true` and
`false`, and `track_total_hits` reads a string as a number and hands back
Java's failure. `_source` and `stored_fields` carry the position; the other
two do not.

`true` and `false` are both `VALUE_BOOLEAN`. mockdr split them into
`VALUE_TRUE` and `VALUE_FALSE` — Jackson's token names — in three separate
tables, and no context measured on 8.15 says either.

And a sort on one field needs no array around it: `sort: "host"` is how a
client sorts on one, where mockdr iterated the string and sorted on its
letters, failing on a mapping for `[h]`. A bare scalar names a field and
fails on the mapping for it; the same scalar *inside* the array is a format
complaint instead, and a flat one rather than a shard failure.

**Numbers outside the range a paginating client reaches.**
`from: -1` and `size: -1` are worded differently and mockdr used one formula
for both — the cluster says `, found [-1]` for one and ` but was [-1]` for
the other. A negative `terminate_after` is refused where zero means no
limit; mockdr read it as a limit and answered nothing. And a `terms`
aggregation's four numeric bounds were taken at face value, so a `size` of
zero produced every bucket and a negative one produced them in reverse — the
cluster refuses each, with the member spelled in camel case in the cause and
in snake case in the reason, and the position pointing at the *value* rather
than the name. Finding that position needed the search for a member to take
a path: the `size` inside the aggregation is not the `size` a search body
carries at the top.

On splunkd, a negative `count` is not the same as zero: it is read as an
unsigned 64-bit integer and reported as the page size, where mockdr answered
the `count=0` number for both.

**Ten SPL commands ran on no argument at all.**
The same question, third product: `| sort`, `| table`, `| eval`, `| dedup`,
`| top`, `| rare`, `| rename`, `| regex`, `| rex` and `| timechart` with
nothing after them answered the rows unchanged here, so a search whose field
list had gone missing came back looking as though it had worked. splunkd
refuses each by name, and the lines are its own: `sort` carries no subject
at all, `regex` and `rex` are answered by the *search operator* rather than
the command, and `rex` describes its own usage as `regex`. `where`, `stats`,
`fields`, `head` and `tail` take no argument and mean it — the other half of
the same measurement.

**Setting an alert's status answered one hand-written line.**
The route a SOAR uses to close an alert refused every malformed body with
`signal_ids and status are required`, where 8.15 names each member of each
arm of the union it accepts — alerts by id, or alerts by query — so a body
with nothing in it reads as *four* failures rather than two. The status enum
is listed in the message, an `signal_ids` of the wrong type is named as
such, one satisfied arm is enough, and an undeclared member is stripped
rather than refused, because this route validates with zod.

**An aggregation that names nothing ran anyway.**
The same question asked of the `aggs` block: fourteen of the fifteen types
this mock serves refuse an empty body, and mockdr ran every one of them. A
`terms` with no field grouped every document into a single bucket and
reported that as the answer — a chart that draws, and means nothing. Twelve
of them say `Required one of fields [field, script], but none were
specified. ` (Elasticsearch's own trailing space included), `filters` has a
line of its own, `filter` borrows the search's empty clause down to the
position, and `top_hits` is the one that takes an empty body and means it.

Naming *no* aggregation type and naming *two* are two different complaints
and mockdr made one of them — and it attached the cause an unknown type
carries to both.

**An empty clause is not a match-all, and twelve of them were a 500.**
`{"query": {}}` came back as every document in the index — a search that
looks like it worked and returns the opposite of what an empty filter should
mean. The cluster refuses it: `query malformed, empty clause found at
[1:11]`, where the position is the closing brace of that empty object.
`_count` refuses it too, in a shape of its own — `Failed to parse` with the
position as `line` and `col` beside the reason and the search's wording
underneath as the cause — and `_validate/query` answers `{"valid": false}`,
because judging that is the whole point of the route.

A clause type with an empty body was worse. Twelve of them reached a builder
that assumed a first key and raised `StopIteration` out of the handler as a
plain-text 500, and five more were read as "match everything". All twenty-two
are measured now, clause by clause: the ones the query builder raises say
`field name is null or empty` and carry no position, the ones the *parser*
raises are `parsing_exception` with a `line` and `col`, `fuzzy` says
*cannot* where its neighbours say *is*, `boosting` keeps the stray apostrophe
Elasticsearch leaves at the end of its line, and `bool`, `ids` and
`match_all` take an empty body and mean it.

An empty clause one level down — `{"bool": {"must": [{}]}}` — was read as
"matches everything" too, so a `must` a client had built from a filter that
matched nothing selected the whole index. The cluster refuses it by arm:
`[bool] failed to parse field [must]`, with the empty clause underneath as
the cause. `scripts/hostile_probe.py` sends that shape now: none of its
bodies reached it, because they were all empty *at the top* and the builders
that assumed a first key sit one level down.

`_validate/query` was wrong in three more ways while it was being looked at:
a body it cannot parse is `{"valid": false}` and not a refusal — which is
the same news in a shape the client does not read — no body at all is
*valid*, since there was nothing to find fault with, and `{"query": null}`
is invalid rather than a 400.

**An alias on one index, and the HEAD that asks about it.**
`GET /{index}/_alias/{alias}` is how a client asks whether an index carries
a particular alias, and mockdr had the route under two other spellings and
not that one — so the question came back 405 from a mount that answers it.
An alias the index does not carry is 404 `alias [x] missing`, in the bare
`{error, status}` envelope the cluster keeps for it rather than the nested
one. `HEAD` is more often how that question is asked, and `_source` was
missing from mockdr's list of the endpoints Elasticsearch answers HEAD on,
so it was 405 rather than yes or no.

Seeding an alias to compare them against then exposed a third: `GET /{index}`
built an empty `aliases` block instead of reading one, so a client asking
that route what an index is called by saw none of its names.

**A verb splunkd's path does not take is answered by the verb, not the path.**
mockdr had it the other way round: one answer for the search endpoints,
another for the KV store's batch paths, and the 400 splunkd keeps for a
`POST` with no name to act on for everything else — so `PUT` and `PATCH` on
any EAI collection came back as that 400. Measured across fifteen paths:
`PATCH` is 405 `Method Not Allowed` everywhere and carries no `Allow`; `PUT`
is 404 `Requested invalid action 'PUT'.` except under `/services/search/`,
where it is the same 405. `DELETE` under `/services/search/` is FATAL rather
than ERROR and names what the path takes — in three wordings, one per group,
which is encoded path by path because no rule accounts for it. The batch
paths take `PUT` as well as `POST`: splunkd's own refusal there names
`Allow: POST,PUT`, and mockdr served one of the two. And deleting a job is
*cancelling* it, in a line that does not name the sid.

Two more of the search endpoints, found in the same sweep: `typeahead`
requires a `count` and says so, where mockdr defaulted to fifty and answered
an empty list — which reads as "there is nothing to complete" rather than
"you did not say how many"; and `timeparser` with no `time` answers **204**
and no body rather than assuming `now`, so a client that had forgotten the
parameter was handed an answer to a question it never asked.

**Four response actions Kibana routes and mockdr answered 404 for.**
8.15 routes nine — `isolate`, `unisolate`, `kill-process`, `suspend-process`,
`running-processes`, `get-file`, `execute`, `upload`, `scan`, which is the
vocabulary its own `commands` filter validates against. mockdr served four,
so a playbook that ran `get_file` or `execute` met a 404 from a product that
has the route. `upload` is the one still left out: it takes a multipart body
and a file, which this mock has nowhere to put.

Their schema also asks in a definite order, and mockdr asked in another. It
checks the members it declares in declaration order, with each action's own
`parameters` block checked *where that block is declared* — so a body with a
bad `agent_type` and no `parameters` is refused for the `parameters` — and
the members it has no definition for last of all. mockdr reported the
unknown key first, and on two actions looked the endpoint up before reading
the body at all, answering `Endpoint x not found` to a request that never
named a valid one. Each action's block has its own declared members too:
`scan` and `get_file` take a `path`, `execute` a `command` and a numeric
`timeout`, the two process actions a union of `pid` and `entity_id` whose
failure lists both arms, and `isolate`, `unisolate` and `running-processes`
declare none at all — so any member of one is a member with no definition.
Eleven bodies against eight actions now answer what 8.15 answers, word for
word.

**An argument splunkd's handler does not take is a refusal too.**
Same shape, third product: splunkd names the alphabetically first argument
it does not recognise — whatever order they arrived in — and mockdr refused
on twelve collections and ignored the rest. A client that misspelled
`sort_key` got the collection in whatever order the mock held it and read
that as the order it had asked for. Twenty-four collections refuse it now,
and the common set is right in the other direction as well:
`add_orphan_field` was in it and belongs to `saved/searches` alone, while
`refresh`, `summarize`, `datatype`, `earliest_time` and `latest_time` were
refused where splunkd takes them. `data/indexes-extended` takes `datatype`
and not `summarize`, so the longer collection path has to win the prefix
match. `scripts/splunk_arg_audit.py` asks all of it — every candidate of
every collection, in both directions.

**A listing named four things nothing would serve.**
splunkd addresses a collection both ways, and splunklib's `.list()` followed
by `[name]` uses both. mockdr listed roles, the capabilities entry, the
settings entry and its macros, and reading any one of them back answered 404
— for something the listing had just named. All four are served now, and a
single read carries the `fields` block naming what the entry accepts, which
the listing does not: a client reading `fields.optional` off a user to learn
what it may write got an empty list. `scripts/unreadable_entries.py` reads
back every entry each listing names, and says how many listings it could not
check because they came back empty.

**Two CI failures on main, neither of them the product's.**
`test_what_is_pending_stops_being_pending` and the four tests beside it
raced the one-second window an action stays pending in: on a loaded runner
more than a second passed between the write and the read, so the action had
already settled and the count was zero. They hold the window open and then
close it, as the tests beside them already did, and are a second and a half
faster each for it. And the seed's referential sweep flagged Defender's
`rbacGroupId` on one draw: it names a group in the tenant's machine-group
configuration, which mockdr does not serve as a collection, so the number
can only ever resolve by collision — marked opaque, like the two fields
before it.

**Graph's threat-intelligence indicator API is gone from v1.0, and so is
mockdr's.** The name `tiIndicator` appears nowhere in the v1.0 OpenAPI, and
beta carries it marked `deprecated`, with a removal date of 2026-04-10 and
the note that the legacy Graph Security API stopped returning data on 31
January 2025 — both documents fetched from `msgraph-metadata` and measured,
not recalled. mockdr served `GET`, `POST` and `DELETE` under
`/v1.0/security/tiIndicators`, so a client could build against a path the
product answers 404 for. The routes are gone, with the repository, the
seeder and the store collection that only they reached — and the two entries
in the reduced reference that claimed them, which carried no schema and so
judged nothing anyway.

**Two Graph writes carried a schema that judged nothing.**
`schema_drift.py` compared GETs alone on that platform, so the `PATCH` on an
alert sat in the reference with a full property list and was never sent. It
is sent now, with the body the route documents, and so is the `POST` that
creates a threat assessment request — a route the vendor's own OpenAPI
describes and the repo's reduced reference had not recorded, which is why it
counted as watched by nothing but this repo's tests.

`audit_coverage.py` stopped counting an entry whose `spec` is null as
judged. Seven Graph routes are named by a reference that carries nothing to
judge them by, and counting them read as though a reference described what
they answer. The number went down: 383 judged became 377, and the vendor
routes on tests alone went from 20 to 26.

### Changed

**The seventeen audits that need nothing but the mock now run in CI.**
They have been release tools run by hand, and by hand is how a regression
reaches main — as two did this round. Every one of them reads the mock alone
and fails on what it finds, so they belong beside the tests rather than
beside the release checklist. `audit_coverage.py` gates now too: a route
nothing watches is a failure, not a number. It also stopped overstating the
gap in two ways — it compared reference paths letter for letter, so
Defender's `/api/Software` did not match the `/api/software` mockdr serves,
and it counted mockdr's own UI API among the routes with nothing to judge
them, which have no vendor to be judged against at all.

**The conformance harness refuses a probe key it would not read.**
A probe that wrote `params:` where the loader reads `query:` had its
parameters dropped in silence and ran against none — and reported the
agreement as a pass. Nine Splunk probes had been running that way. The loader
now refuses an unknown probe or request key, and the nine revived probes
brought 68 differences with them, which are the entries above. The seeded
search job is scoped to the run's own sourcetype too: `index=main | head 1`
took whichever event came first, and the two instances hold different ones.

**Two response-action paths Kibana does not route, and the parameters it demands.**
Measured across the whole action matrix on 8.15: `isolate` is served under
both `/api/endpoint/isolate` and `/api/endpoint/action/isolate`; every other
response action only under `/action/…`, with the bare spelling answering 404
— `scan`, `kill_process`, `suspend_process`, `running_procs`, `get_file`,
`execute` alike. mockdr served `/api/endpoint/scan` and
`/api/endpoint/kill_process`, so a client could build against paths the
product does not have. And Kibana's schema refuses the body before it looks
at the endpoint: a scan without `parameters.path` is a 400 naming that
member, a process action without a `parameters` block at all is a 400 saying
so. mockdr accepted a scan with no parameters and answered 200 with a scan it
had started on nothing.

`/api/endpoint/unisolate` is the one thing here left deliberately unimitated:
8.15 answers it with a 308 to `/api/endpoint/action/unisolate`, which it then
answers 404 for. A mock that cannot release an endpoint is useless to the
playbook that isolated it, so this one keeps working — recorded in the probe
file beside the measurement.

**A scroll cursor the cluster cannot read is a refusal from the security layer.**
The bootstrap can open a scroll and dispatch a search now, so the six routes
addressed by a cursor or a sid — which nothing had ever compared — are
compared. The jobs matched; the scroll did not. A scroll id encodes which
indices the scroll reads, so one Elasticsearch cannot parse cannot be
authorised either: 8.15 answers `403 security_exception` with
`Cannot parse scroll id` as the cause, before the search context is looked
for. mockdr reported a missing context — the answer for a well-formed id
that has expired, which is a different thing to a client deciding whether to
retry. And the product header goes with it: `X-elastic-product` is absent on
a 403 as well as on a 401, present on a 400 and a 404 — measured, where
mockdr had only known about the 401.

**A collector path splunkd does not have, and the 404 it answers with.**
Five probes went to the versioned spellings of the event collector, which
nothing had ever sent anything to. `/services/collector/event/1.0` and
`/raw/1.0` are splunkd's; `/services/collector/1.0` is not — 10.4.2 answers
404 there, measured, and mockdr accepted it. Removing it exposed the next
difference: the collector answers on its own port and its not-found body is
the web server's — `{"text": "The requested URL was not found on this
server.", "code": 404}` — where the management port answers
`{"messages": [{"type": "ERROR", "text": "Not Found"}]}`, and it names no
`Vary` at all, where the collector's own answers do.

**Three more differences, on routes that had never been compared.**
Ten further probes went to the routes the coverage map named, and three of
them differed from the real products:

* **The KV Store's configuration is served only under the `nobody` user
  context.** splunkd 10.4.2 refuses `/services/storage/collections/config`
  and `/servicesNS/admin/…/storage/collections/config` alike, with
  `Must use user context of 'nobody' …` — measured, and the data routes
  beside them are not restricted that way. mockdr answered every collection
  to whoever asked.
* **Kibana's detection privileges were half a document.** 8.15 answers
  twelve cluster privileges and thirteen per index; mockdr answered six of
  each, so a client reading `cluster.manage_pipeline` or
  `index[…].view_index_metadata` — which the Security Solution does, to
  decide what to offer — found `undefined` where a boolean belongs.
* **`/api/detection_engine/rules/tags` does not exist.** Kibana 8.15 answers
  404 there; the route that exists is `/api/detection_engine/tags`, which
  this mount already serves. The second spelling is gone.

**Two answers the real products do not give, found by comparing routes nothing compared.**
The coverage map named 49 routes resting on this repo's own tests while a
real product runs beside them; nine of the cheapest — those that take no
precondition and answer a document — now have conformance probes, and two
of the nine differed. Kibana 8.15 carries `profile_uid` on a case reporter
only for an author that has one and omits it otherwise, where mockdr
answered `null`, so a client asking whether the key is there was told yes,
always. And `GET /_cluster/health/{index}` answers the health *of* that
index, not a body naming it: mockdr added an `index` member no cluster
sends.

**Three Deep Visibility routes that had never been compared.**
`/dv/query-status`, `/dv/events` and `/dv/events/{type}` all take the
`queryId` that `POST /dv/init-query` answers, and the drift audit could not
make one — the swagger branch took only global parameters, so all three sat
behind `HTTP 400 (skipped)` while the run reported no findings. Compared at
last, the status answered a `queryId` and a `status` the 2.1 swagger declares
nowhere — the second a duplicate of `responseState` under a name the vendor
does not use — and carried neither `queryModeInfo` nor `warnings`, which it
does declare. It answers the declared shape now, `responseError` included
only for the two states the swagger says it belongs to. `/sites/{site_id}`
joins them: SentinelOne nests that collection as `data.sites`, so the audit
had never found an id for it and filled the path with a literal placeholder.

**Two Defender collections nothing could be read from.**
`mde_software` and `mde_vulnerabilities` are keyed `softwareId` and
`vulnerabilityId` in the store and `id` on the wire, and the rename never
happened: all forty-four software entries and all fifteen vulnerabilities
answered `id: ""`. Listing them is how a client learns an id, so
`GET /api/software/{id}` and its `machineReferences` were unreachable —
which is also why the drift audit had recorded those four routes as
"Software x not found" and compared nothing.

**A created indicator had a different shape from a listed one.**
`POST /api/indicators` answered four members fewer than the very same record
carries when it is listed — `application`, `externalID`, `rbacGroupIds`,
`sourceType` — so a client reading the create answer saw one shape and got
another a moment later. Defender is compared over 42 routes now, up from 37,
with the two remaining skips honest ones: a `204` has no body to compare, and
an advanced-hunting result's columns are the query's rather than the API's.

**A process for a device the tenant does not have, with five fields Falcon has not.**
`ProcessesapiProcessDetail` declares ten members; mockdr answered five more
beside them — `sha256`, `md5`, `user_name`, `user_sid`, `parent_process_id` —
so anything built against the mock's process breaks against the real product.
The route also generated a process for *any* id, including one naming a
device this install has never held, where Falcon resolves nothing and answers
an empty list. And every process it invented started at the same instant of
January 2025.

**Every entry reported having just been updated.**
An Atom entry's `updated` is the entity's own last change, and splunkd keeps
it stable across reads — for an entity nothing has changed through the REST
layer, `saved/searches` and `apps/local`, it is the epoch. Measured on
10.4.2. mockdr answered *now* for every entry of every collection, so each
read said everything had just changed, the body differed once a second while
nothing in it did, and the ETag over that body could never be revalidated by
a client that waited. Entries carry the epoch now; the feed's own `updated`
is still the time of the read, which is what splunkd does — three reads there
carry three different ETags too.

**The ids of the hidden hosts.**
Falcon publishes every collection twice, the ids under `queries` and the
documents under `combined`, and only `/devices/combined/devices-hidden/v1`
was served. A client following the ids-then-entities pattern — which is how
Falcon's own SDK reads a collection — met a 404 on the half it starts with.

**A filter Falcon writes with parentheses, which narrowed nothing.**
FQL groups terms with parentheses — Falcon's own documentation and its
console write `(device_id:['…'])`, and a host-group action carries that form
verbatim. The action route cut the filter apart by hand and came out with
the id and `'])` still attached, so it matched no host: `add-hosts` answered
`200` with an empty `resources` list, the host never joined the group, and
the device's own `groups` stayed empty. The mount's FQL parser did not know
the character either — a lone group was refused as invalid, and a group
beside another term was dropped in silence, so
`(status:'normal')+platform_name:'Windows'` answered every Windows host
rather than the normal ones. Thirty-five where thirty-three were asked for,
with a 200, on every CrowdStrike route that filters.

**Running a script and collecting its result, which never worked.**
Five more Cortex routes were recorded "skipped: HTTP 500" by the audit and
so were never compared. `run_script` read `endpoint_id_list` where Cortex
requires a `filters` block: a documented call selected nobody, created no
action record at all, and still answered an `action_id` — polling which
answered `500 Action … not found`. So the loop every playbook runs, start a
script and wait for its result, could not close. Where it did resolve, the
status was a tally of zeros while the run had finished, and the result was
one canned row for an endpoint called `xdr-endpoint`. One action covers the
set now, the tally counts the endpoints it ran on, and the rows name them
with the members Cortex declares (`execution_status`, `standard_output`,
`endpoint_ip_address`). `terminate_process` takes the target its siblings
take, and `file_retrieval_details` the `group_action_id` its own retrieval
answered. Cortex is compared over 52 routes now, with none skipped — this
morning it was 35 compared and 8 skipped.

**"0 drift findings" over the routes the audit never asked about.**
`schema_drift.py` reported zero for CrowdStrike and Cortex XDR while printing,
two lines above, that fourteen CrowdStrike routes and eight Cortex ones were
*skipped*: the audit sent the empty default body each of them rightly
refuses, or ids that name nothing, and recorded the refusal instead of a
comparison. Its request table names what each route documents now — 28
CrowdStrike routes compared instead of 19, 47 Cortex instead of 35 — and the
comparison no longer reads a map keyed by record ids as a set of property
names, which had every endpoint of the recorded reply counted "missing" and
this install's own counted "undocumented" for ever. Five real defects were
behind those skips:

* **Five Cortex action routes refused the body Cortex documents.**
  `file_retrieval`, `quarantine` and `scan` name their target with a
  `filters` block and have no `endpoint_id` at all; the handlers read
  `endpoint_id` alone, so every well-formed call answered `500 XDR internal
  server error / Endpoint  not found` — those three routes could not be
  called successfully by a correct client. `isolate` and `unisolate` document
  both spellings and took only one. All five read either now, an action
  covers every endpoint its filter selected, and `get_action_status` keys its
  answer by each of them, which is what a playbook waits on.
* **`UpdateDeviceTags` answered the whole device document.** gofalcon
  declares four members per row — `code`, `device_id`, `error`, `updated` —
  and mockdr answered seventy-one fields of the device, none of them those,
  so a client reading `updated` to see whether its tag took found nothing.
  A device id the tenant does not have was skipped in silence; it is named in
  the result now.
* **Cortex's management audit log answered every documented field blank.**
  The route's recorded reply names each field `AUDIT_*`; mockdr answered
  those keys empty and put the values under the record's own lowercase names
  beside them. An XSOAR client running `xdr-get-audit-management-logs` read a
  page of empty rows, with a 200.
* **Agent reports and device-control violations were canned.** Both answered
  `mock-endpoint-001` on `ACME-WS-001`, an endpoint `get_endpoint` has never
  listed, under undocumented field names — and the violations arrived under
  `reply.data` where Cortex answers `reply.violations`, so a client reading
  the documented member found an empty list beside a populated one it had
  never heard of.
* **`get_original_alerts` answered the parsed alert.** Cortex answers the
  *original* one: `internal_id` and `original_alert_json`, the raw event as a
  JSON string, which is the whole reason to call this rather than
  `get_alerts`.

**A conditional write that was not conditional.**
ARM's common types declare `If-Match` — "the If-Match header that makes a
request conditional" — and point at the normal entity-tag convention, which
is RFC 9110 §13.1.1: a failed condition is `412` and the write does not
happen. The Sentinel mount ignored the header and wrote anyway, answering
`200`. That is the lost update the header exists to prevent: two clients read
the same incident, both write, and the second overwrites the first while
being told its condition held. Incidents and their comments honour it now —
a stale tag is refused and changes nothing, `*` holds for a resource that
exists, and a request without the header behaves as it always did.

**Every Kibana rule written by `elastic`, whoever wrote it.**
`created_by` and `updated_by` were the string `elastic` on create, replace,
patch, duplicate and both bulk toggles — the same failure `/privileges` had
when it named the caller `elastic` too, and invisible for the same reason:
the superuser is a plausible author. The caller is recorded now, on every one
of those paths.

**A comment nobody wrote, at a time that was not there.**
An incident comment named `MockDR` as its author whoever had called, and
answered `lastModifiedTimeUtc` — a `date-time` the service fills in, per
`IncidentCommentProperties` — as an empty string. Editing one changed its
text and left both timestamps as they were, so a client re-reading a comment
saw new words under the old times. The caller is recorded now, the way
Sentinel's `ClientInfo` records an app-only one (the application names
itself, `email` and `userPrincipalName` stay empty because there is no
signed-in user), and an edit moves the modification time and nothing else.

**A page starting before the beginning.**
`$top` was bounded on all 37 routes that take it and `$skip` on none, so
`$skip=-5` was accepted: an empty page on one mount, a shifted one on the
other, both with a `200`. OData v4 §11.2.6.4 says the value of `$skip` MUST
be a non-negative integer, and every route that takes one now says so.

**A query naming a property that does not exist, answered as if it did.**
On both OData mounts, `$select=notAField` answered a page of empty objects,
`$filter=notAField eq 'x'` an empty collection and `$orderby=notAField` an
unsorted one. Three `200`s, and all three read as "nothing matched" — which
is what a client with a typo in a property name concluded, on the two
products that answer `Could not find a property named 'x'`. What each
resource carries is read from the references this repo already vendors:
Graph's from the reduced v1.0 document, which records the properties of the
resource each route answers, and Defender's from its docs' recorded response
paths — 53 Graph routes and four of Defender's. A route neither speaks for is
left alone, because a refusal has to be able to say what the resource *does*
carry, and a documented property this install does not fill in is still a
property: `$select=productName` on an alert is answered, not refused.

**A sort that did not run, reported as one that did.**
Elasticsearch sorts on doc values, so a field with no mapping is refused —
`No mapping found for [x] in order to sort on`, wrapped in a
`search_phase_execution_exception`, measured against 8.15. mockdr refused it
only for indices a client had created with a mapping; for its own collections
it answered the first page of an *unsorted* search with a 200, which tells a
client its sort ran. Those collections are judged by what they publish and
hold now: a field neither their mapping declares nor any document carries is
refused, `unmapped_type` still runs the sort as the cluster does, and the two
alert families keep sorting by the spelling their own documents use —
`.siem-signals-*` by `signal.rule.risk_score`, the `.alerts-*` family by
`kibana.alert.risk_score`. Two conformance probes hold the pair in place.

**A Log Analytics table this workspace does not have, answered with silence.**
`MicrosoftDefender_CL | count` — a name a client can plausibly type, where
the connector's table is `SecurityAlert` — was answered `200` with an empty
`PrimaryResult`. "No such table" and "nothing matched" are different answers,
and a detection engineer reading the second one has no reason to look at
their query. The workspace refuses a table it does not have now, naming the
ones it does, which is what Defender's hunting on this same mock already did.

**Six of seven writes never reached the SIEM the mock bridges them to.**
ADR-009 says that after an EDR command returns, the corresponding Splunk
event already exists. The bridge subscribes to ten event types, and four of
them had a publisher: an agent disconnected through the SentinelOne API, a
threat mitigated, a CrowdStrike alert triaged, a Defender alert closed, an
Elastic signal acknowledged and a Cortex incident moved on all answered 200
while `index=sentinelone`, `index=crowdstrike`, `index=msdefender`,
`index=elastic_security` and `index=cortex_xdr` went on answering the state
this install was seeded with. A playbook that acts through the EDR and then
verifies through the SIEM — which is the ordinary shape of one — was reading
a document its own action had not touched. Every one of those writes
publishes now, and each path has a test that counts the events before and
after.

**A suppression that stopped suppressing.**
`main.py` binds the mock on `0.0.0.0` on purpose and said so with a
`# nosec B104` on the `uvicorn.run(` line. bandit 1.9.4 attributes the
finding to the argument rather than to the call, so the marker no longer
covered it and CI's SAST step failed on every push. The marker sits on the
`host=` line now, where the finding is.

**Work assigned to people the tenant does not employ, on two more products.**
The same defect as the Cortex incidents: a Falcon detection was assigned to a
`fake.email()` under an unrelated `fake.name()`, an incident to another
invented pair, and a case was assigned by `analyst0@acmecorp.internal` to
`responder0@acmecorp.internal` — addresses `/user-management/queries/users/v1`
has never heard of. All three now draw from the console's own user directory,
which is seeded before them, and the case names its assigner the way gofalcon
does: uid, uuid, both name parts, display name and address.

**A Defender alert that named an investigation and an incident nobody had.**
`investigationId` was a `random.randint(1, 50)` and `incidentId` a
`random.randint(1, 100)`, so `/api/investigations/{id}` answered 404 for an id
the alert itself had just supplied, and the incident an alert belonged to
existed on neither surface. Investigations are now the ones the tenant's
alerts triggered — the alert's machine, the alert's id as
`triggeringAlertId`, the alert reporting the investigation's state — and
Defender numbers its incidents, which is what Graph's `incidentId` (an
`Edm.String` in the CSDL) and Defender's (a number, per the Splunk add-on's
own sample) both name. Read an alert through either product now and it points
at the same incident.

**A rule updated eleven hours before it was created.**
`rand_ago(n)` draws *between* 0 and n days back, so `rand_ago(random.randint(30,
180))` could land today — and `seed_es_rules` paired that with an `updated_at`
drawn independently within the last day. The install shipped it whenever the
random stream happened to fall that way, which an unrelated seeder change made
it do. Rules and exception lists derive the later timestamp from the earlier
one now, and the ordering test sweeps four more draws, because an invariant
that holds for one draw is not an invariant.

**Every policy update answered 200 and changed nothing.**
`PUT /sites/{id}/policy`, `PUT /groups/{id}/policy` and `PUT /tenant/policy`
passed the request body in whole to a routine that assigns each of its keys
to the policy — but the 2.1 API wraps a change in `data`, and a policy has no
field of that name, so every update set nothing and answered the unchanged
policy back with a 200. The tenant scope was worse: it resolved to no policy
at all, so `PUT /tenant/policy` answered `{"data": null}`, which is neither a
success nor a failure. Both are fixed, and the round trip is pinned.

**A tag with no key and no value, created and confirmed.**
`POST /tag-manager` requires `key`, `value` and `type` inside `data`, and
mockdr defaulted every one of them: a body that named none of them — a client
sending its fields flat, which is the easy mistake — created a tag with an
empty key and an empty value and answered 200 with it. Nothing can be found
by that tag afterwards. The three required members are required now.

**A route the mock publishes and nothing could reach.**
Starlette matches in registration order and stops at the first hit, so a
literal path declared after a sibling pattern that covers it never runs.
`GET /_dev/webhooks/deliveries` was declared in `dev.py`, which is included
after `webhooks.py`, so `/_dev/webhooks/{id}` matched first: every request
for the delivery log was answered by a search for a subscription called
"deliveries", and a route the mock publishes returned 404. It is declared
ahead of the by-id route now, and `scripts/shadowed_routes.py` walks all 689
routes in match order so the next one cannot hide.

**One field of the wrong type discarded a whole Splunk notable update.**
`POST /services/notable_update` validated a JSON body against a DTO whose
fields were all `str` and swallowed any failure into an empty parameter set,
so `{"ruleUIDs": [...], "status": 2}` — a status code, which is a number —
was answered `success: false, "No event IDs provided"` for a request that
named three of them. The same route form-encoded coerced everything to a
string and went through. The JSON body is read the way the form is read now,
and the two encodings are pinned against each other.

**Cortex XDR assigned its incidents to people the tenant did not employ.**
`rbac/get_users` answered three canned role accounts, while every incident
drew a fresh `fake.name()` for `assigned_user_pretty_name` and built a mail
address from it — so the intersection of "who has incidents" and "who this
tenant has" was empty. A client that read an incident's `assigned_user_mail`
and looked the person up in the user directory found nobody, every time; a
SOAR playbook routing by assignee had nothing to route to. There is a seeded
directory now (the three role accounts plus eight analysts), incidents are
assigned out of it, and `rbac/get_users` reads it back. The directory is part
of the snapshot, so it survives a restart along with the incidents that point
into it.

### Added

**A map of what nothing is watching.**
Every audit here reports what it found; none reported what it never looked
at, and that is where today's defects were — nineteen CrowdStrike routes
compared while fourteen sat behind a "skipped" line, three Deep Visibility
routes never compared at all. `scripts/audit_coverage.py` counts coverage
instead of findings: for each of the 701 routes the mock serves it asks
whether a vendor reference judges its answer, whether a conformance probe
compares it against the real product, and whether any test names it. Nothing
is entirely unwatched — but 113 routes rest on this repo's own tests alone,
and 49 of those are on the three mounts where a real product runs beside the
mock and could be compared.

**Why a route was skipped, and four reasons it should not have been.**
`schema_drift.py` printed `HTTP 400 (skipped)` and no more, so twenty-two
routes sat behind that line while the run reported zero findings. Each skip
now says what the mock said — `query.ids: Field required`, `ids must be an
array` — and the reasons were the audit's own: a placeholder inside a longer
string went out with its braces intact, so an FQL filter matched nothing; a
list placeholder was written in the singular and sent as a string; a
form-encoded token request was sent as JSON because the runner ignored
`data`; and the request table was matched case-sensitively while gofalcon
records `/cases/get/v1` where Falcon serves `/cases/GET/v1`. CrowdStrike is
compared over 36 routes now with none skipped — this morning it was 19 with
14 skipped, and Cortex 35 with 8.

**An audit for two spellings of one filter.**
`param_effect.py` asks whether a filter narrows and `filter_effect.py` asks
it of the filters that travel in a body. Both are satisfied by a filter that
narrows *wrongly*, which is exactly what the parenthesised FQL above did — it
narrowed, just not to the right set. `scripts/filter_spellings.py` runs each
filter twice, in the plain spelling and in the one the vendor's own console
writes, and compares the records that come back. Run against yesterday's
code it reports four differing pairs; against today's, none.

**A sweep for records that name records this install does not have.**
The audits that read answers check one answer at a time, and this defect
needs two. `scripts/dangling_references.py` reads the seeded store instead:
for every id-shaped field it asks whether the values resolve to a record some
collection holds, and flags the field that resolves for some of its values
and not for others. A field that resolves nowhere at all is left alone — a
Falcon customer id or a behaviour id identifies something this mock does not
model, and inventing records for those would be worse than leaving them
opaque; the two that collide with a record key on some draws are listed with
what they identify. The sweep runs as a test too, over four draws besides the
one this install ships with.

**The Falcon case a client could list and never read.**
`/cases/queries/cases/v1` answered case ids and nothing served the cases, so
`POST /message-center/entities/cases/GET/v1` is served now — gofalcon's own
route, carrying the fields its `APIMessageCenterCasesResponse` declares and
not the three the stored record has beside them.

**The same sweep across the other four references, and what Defender hid.**
`scripts/method_drift.py` now asks the question above of every vendor
reference this repo carries — SentinelOne, CrowdStrike, Defender, Graph and
both Cortex documents — over the 209 documented operations whose path this
mock serves. It found one more: `PATCH /api/machines/{id}`, the Defender call
that changes a machine, on a path that already served a GET and six action
routes. It sets `machineTags` and `deviceValue`, refuses a device value MDE
does not have, and answers the machine back the way the GET beside it renders
one.

**Six documented calls that answered 405, and what implementing them found.**
`param_drift.py` compared the parameters of operations both sides describe,
which meant it could not see an operation only one side has: a method the
swagger documents on a path mockdr already serves was skipped in silence.
There were six, and five are how a real client writes — SentinelOne updates
an exclusion and a blocklist entry by body (`PUT /exclusions`,
`PUT /restrictions`, `data.id` naming the record), and deletes rules and tags
by filter (`DELETE /cloud-detection/rules`, `DELETE /tag-manager`) — so an
integration doing the ordinary thing got a 405 from a route that was, on
paper, implemented. `PUT /accounts/{id}/policy` and
`PUT /system/configuration` complete the set. The two delete-by-filter routes
refuse an empty filter, which describes every record there is, and a filter
whose members this install cannot answer, which would delete a different set
than the one asked for. The audit reports the difference now, and it is zero.

**A sweep for code nothing can reach, and the invented numbers it found.**
`unread_params.py` reads the source for a parameter a handler never looks at;
`unreachable_code.py` reads it for the layer below — a query or command
handler no router calls, nothing imports and no test names. Twenty-seven of
them, and two were the reason to look: `cs_iocs.device_count_for_ioc`
answered how many devices had seen an indicator with `(hash(value) % 10) + 1`
— a number Python randomises per process and that has nothing to do with any
device this install holds — and the same file's `processes_ran_on` invented
process ids the same way. Neither was wired to a route, so neither had ever
served anybody; wiring one up would have been enough to make the mock answer
a confident count that came out differently after a restart. Both are gone,
along with twenty-five superseded handlers (`get_agent_passphrase` for one
agent, where SentinelOne publishes `/agents/passphrases` for all of them) and
three modules that held nothing else. Neither Cortex reference documents a
read route for the hash blocklist or allowlist, so the readers that had been
written for one went too — no evidence, no route.

**A sweep that reseeded the world under itself.**
`body_audit.py` probed mockdr's own `_dev` control surface along with the
mocked ones, and posting to `_dev/scenario` reseeds the install — which
invalidated the tokens every later mount was being probed with and turned
three platforms' worth of routes into unexplained 401s that the sweep read
as "never reached". `_dev` imitates nothing and is left out now; the sweep
sees twenty-three more routes than it did.

**Route-level drift, which no audit counted.**
`param_drift.py` compared the parameters of routes both sides describe and
said nothing about a route only one side has — which is how a single wildcard
standing in for thirty-eight documented agent actions answered to any name at
all. It now lists what mockdr serves under the SentinelOne prefix that the
2.1 swagger does not publish: nine routes, each a convenience the vendor
addresses another way (`DELETE /exclusions/{id}` where S1 deletes by body,
`POST /threats/{id}/notes` where it posts to `/threats/notes`). None of them
is a defect on its own; not knowing about them was.

**Narrowing a Splunk collection, and three things its envelope was saying wrongly.**
Every ``/services`` collection takes ``search``, and splunkd reads it two
ways: ``search=name=main`` is an exact match on one field, and a bare term
is matched as a substring against the entry's own fields *and* every value
in its content — broader than it looks, since ``search=main`` matches every
index, each carrying ``defaultDatabase: main``. mockdr declared the
parameter and ignored it, so a client narrowing a collection was handed all
of it, with a ``paging.total`` that agreed with the answer rather than with
the question. The new middleware runs inside the sorting and paging ones, so
what is ordered, sliced and counted is what the search selected.

Two more differences the probes then showed, both measured:

* ``origin`` names the collection — ``…/services/data/indexes`` — and mockdr
  answered ``…/services`` for every one of them, so a client reading it to
  find out what it had asked for learned nothing.
* ``count=0`` means "all", and splunkd reports ``perPage: 10000000``, its
  own maximum, not the number of entries that came back.

**How a collection compares, as well as what it compares.**
``sort_mode`` says whether a value is read as a number or as text: a
descending *alpha* sort of the event counts 97716, 31270, 5907, 4483 is
`97716, 5907, 4483, 31270`. mockdr ignored the parameter and always compared
numerically, so a client asking for one order got the other. ``auto`` and
``num`` are measured; ``alpha`` against ``alpha_case`` follows Splunk's
documented meaning, because this install holds no two names differing only
in case.

**A collection that came back in no order at all.**
splunkd sorts every ``/services`` collection by ``name`` ascending when the
request says nothing, and by ``sort_key``/``sort_dir`` when it does. mockdr
answered in whatever order its store held and applied neither parameter
while declaring both, so ``sort_dir=desc`` came back identical to
``sort_dir=asc`` — and a client paging through a collection had no guarantee
of seeing each record once, which is the guarantee paging exists for. A new
middleware sorts beside the one that pages, and runs inside it, because
sorting a page orders each page separately and leaves the collection
unordered. A ``sort_key`` naming a content field sorts by it, numerically
where the values are numbers; a key nothing carries leaves the order alone,
as splunkd does, rather than reordering by nothing.

**And an index could not be disabled through the link that offers to disable
it.** An index is not disabled by editing a `disabled` argument — the
handler refuses that name, correctly — but through
``POST …/{name}/disable``, which mockdr published in every entry's links and
answered 404 at the end of. Both actions work now, and the links follow the
state: a disabled index offers `enable` and an enabled one `disable`, never
both, and the answer to either action offers neither — it describes what was
done, not what can be done next. All measured on 10.4.2.

**Sorting by severity put the wrong alerts on top.**
OData orders an enum-typed field by where the member sits in the declared
list, not by how it is spelled. Sorted as text, `$orderby=severity desc`
answered `medium` at the top where Graph and Defender both answer `high` —
so a triage client asking for the worst alerts first worked on the wrong
ones, with a 200 and nothing in the reply to say so. Ascending was wrong the
same way, starting at `high`.

The declared orders are read from what is vendored rather than written by
hand: Graph's from the CSDL, and Defender's from its docs' properties
tables, which spell the members out in order —
`scripts/mde_docs_spec.py` now captures those. A value outside the declared
list sorts after every declared one, which is where an unrecognised member
belongs, and a field that is not an enum sorts exactly as before.

**A comparator that stopped looking one level down.**
The Graph evidence above was wrong for as long as it was, and
`schema_drift.py graph` reported no drift the whole time, because the
comparison stopped at an item's top-level keys: a nested object could carry
anything at all. OData marks a polymorphic member with `@odata.type`, which
is exactly the handle needed to judge it, and the comparator now follows
every one of them and checks its keys against the type it names. It reports
clean on the corrected evidence and would have reported the invented
properties — which is the only reason to trust the first half of that
sentence.

**An alert that named a device no client could find.**
Asking whether a reference resolves — a client lists alerts, reads the
device off one, and goes to fetch it — turned up something larger than a
dangling id. Graph's alert evidence was `{"type": "device", "deviceId": …}`,
which is not a shape Graph has: `microsoft.graph.security.alertEvidence`
carries `@odata.type`, `createdDateTime`, `verdict`, `remediationStatus`,
`roles`, `tags` and `detailedRoles`, and `deviceEvidence` adds
`mdeDeviceId`, `azureAdDeviceId`, `deviceDnsName` and twenty more. A client
reading `mdeDeviceId` — the property that exists for exactly this — found
nothing, and the id that was there matched no device the mock serves.

The evidence is now built from the Defender machine the alert names, so the
two products' views of one host agree and all 31 references resolve. Its
enums are Graph's spelling rather than Defender's (`active`, not `Active`),
from the vendored CSDL.

Getting that reference vendored found a bug in the reducer itself:
`scripts/graph_csdl_spec.py` matched only the paired form of a type
declaration, so a self-closing one swallowed everything up to the next
closing tag — 184 of the security namespace's 691 types came back, and
`deviceEvidence` was in the missing half. It also read every `self.` prefix
as `microsoft.graph.`, where in a namespaced schema it means that schema; a
type's namespace is recorded now, and both metadata documents reduce
correctly.

**A field that means two things.**
A client writes one parser per field and runs it over every record, so a
field that is a string in one record and a number in the next breaks it —
and which of the two is right barely matters, because a product does not
answer both. `scripts/type_stability_audit.py` sweeps every listing, walks
1 189 records to their leaves, and asks of each field path whether it held
one type, and — where the name says it is a time — one notation.

**`processId` and `parentProcessId` were sometimes numbers and sometimes
empty strings**, in the same reply. Defender's docs table types the fields
it lists and says nothing about the ones that appear only in an example, so
every member of `evidence` had been defaulted to a string. A recorded reply
settles it: 39 integers, 56 nulls, no strings.

Rather than hand-correcting two fields, `scripts/splunk_ta_samples_spec.py`
now records the JSON type each path was seen holding and which paths were
seen null, and `gen_mde_fixtures.py` prefers that over the guess. Every
`evidence` member the recording ever saw empty now defaults to `null`, which
is what Defender sends — `""` for a missing file name is a different thing
to a typed client, and `0` for a missing process id would have claimed PID 0.

The audit judges within one route rather than across a vendor: `severity` is
a string on a Graph alert and a number on a Graph tiIndicator, and both are
right. The drift that would escape it — one type in a listing and another in
a fetch by id — is what `consistency_audit.py` compares.

**The same record, fetched two ways.**
Every product here serves a record from more than one route, and a client
moves between them freely: it lists to find an id, then fetches that id to
act on it. `scripts/consistency_audit.py` fetches 21 records both ways and
compares every key the two answers share. A mock is unusually good at
breaking that assumption, because each route tends to be built separately
and the two drift.

* **The index listing filled the three bucket paths from the recorded entry**,
  which was captured from the `audit` index — so listing `main` said its
  buckets live in `$SPLUNK_DB/audit/db`, while fetching `main` by name said
  `$SPLUNK_DB/main/db`.
* **Fetching a saved search by name left out `alert_comparator` and
  `alert_threshold`**, the two members that define its alert. The same
  search read as a threshold alert in the listing and as no alert at all
  when fetched.

Both were the same shape of mistake — two hand-written content blocks for
one object — and both routes now build theirs from one function.

Following the second of those to the real product turned up a third: an
index's `minTime` and `maxTime` are the bounds of the events *in* it, and
mockdr answered `''` for every index while holding two hundred events in
some of them. They are computed now, in splunkd's own format for this field
(`2026-08-25T23:46:24+0000`, the offset without a colon, which the rest of
the API does not use), and an index holding nothing still answers `''`.

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

**Graph's advanced hunting is Defender's, and had the implementation
Defender's own route was given up.** `POST /security/runHuntingQuery`
accepted the query and never evaluated it: the same three synthetic rows
came back whatever was asked, so a `where` that excludes everything returned
results and a table this install does not have returned results too. The
device ids in those rows belonged to no machine here, so a hunter who
followed one to `/api/machines/{id}` got a 404 for a device the hunt had
just reported.

It runs the same evaluator over the same seeded tables as
`/api/advancedqueries/run` now — one engine for one product's data — and the
two mounts answer the same query alike, down to the 400 for a table neither
holds.

**Four data connectors that said they were ingesting, into four empty
tables.** This workspace's `dataConnectors` advertise `SentinelOne_CL`,
`CrowdStrikeFalcon_CL`, `ElasticSecurity_CL` and `PaloAltoCortexXDR_CL` —
and hand the client the query to ask each one when data last arrived,
`<Table> | summarize max(TimeGenerated)`. Every one of the four answered an
empty result with no columns at all, and the summarize went unparsed, so the
query a connector publishes about itself returned the whole table. A client
that read the connector list and ran what it was given learned that a
connector this install says is ingesting had ingested nothing.

The events were there the whole time: the same install's Splunk store holds
them, from the same four products, and the code said so — *"these are
populated by the Splunk event store"* — beside a `return []`. Each table now
answers the events its own connector ingests, with the `TimeGenerated` a
workspace orders custom logs by, and `summarize max(...)`/`min(...)` answer
one row named the way Log Analytics names it.

**Every Splunk job control action answered the same sentence.**
`Action 'pause' applied to job '<sid>'` — one generic line for all eleven,
where splunkd says what it did: *Search job paused.*, *continued.*,
*finalized.*, *touched.*, and for the two that change how long a job is kept,
the ttl they set (`save` makes it a week). A client reading the message
could not tell a pause from a finalize. An action splunkd does not have
answers `FATAL` and *Unknown action.*, naming neither the action nor the
job, where mockdr echoed both back as an `ERROR`.

And `cancel` marked the job failed and *kept* it. splunkd removes a
cancelled job: the sid stops resolving, which is exactly what a client
cancelling a runaway search then waits for — and against mockdr it waited
for ever. All measured on 10.4.2, action by action.

Seven functions in the same module were unreachable, among them one whose
comment — *"Simplified: just return the expression as-is"* — described an
`eval if()` that has been evaluated properly for some time. Dead code that
describes a defect the code does not have is worse than none.

**Three routes that ignored the record their own URL names.**
A path parameter is the strongest case of the kind above: it names what the
answer is meant to be about, and ignoring it answers about something else.

* `GET /tenant/policy` and `GET /accounts/{id}/policy` answered
  `{"data": null}` — a 200 with nothing in it — for every id anyone could
  type, including ids the same install refuses on `/accounts/{id}`. The
  lookup underneath took a site or a group and returned nothing when given
  neither, so the account-wide policy every site and group inherits from did
  not exist at all. It is seeded now, both routes answer the document a
  console shows, and an account this install does not have is a 404 like
  everywhere else.
* `POST /api/endpoint/suggestions/{suggestion_type}` answered the same list
  whatever the type — measured on 8.15, which refuses every name but
  `eventFilters`, including Kibana's own `trustedApps`. Its body needs a
  `query` as well as a `field`, which was unchecked too.

`unread_params.py` checks path parameters as well now, with the three it is
right to ignore written down: `/servicesNS/{owner}/{app}`, which the
namespace middleware collapses because this mock holds one namespace, and
the Log Analytics workspace, because the whole ARM surface answers for one
tenant addressed by any name.

**Three parameters a route declared and never looked at.**
Found by reading the source rather than asking the mock: a handler that
takes a parameter and never mentions it again answers 200 with something
plausible, and the parameter the client sent simply never happened. That is
invisible to every other audit here, which can only compare answers.

* `scope` is required on the client-credentials grant at Entra's v2
  endpoint, and all three Entra mounts took it as a form field and dropped
  it — Graph's own docstring said "ignored". Every client written against
  mockdr could omit the one parameter the real directory insists on, and
  fifteen of this repo's own test files did.
* Cortex's `rbac/get_user_group` documents `group_names` and reads none of
  it: a client asking about one group was handed every group.
* Cortex's `quarantine/status` documents `files` — it is the whole point of
  the route — and answered a canned row whatever was asked, so a playbook
  checking whether *its* file was quarantined read somebody else's and
  believed it was its own.

`scripts/unread_params.py` is the audit, and it knows the three ways a
declaration is not a defect: a `Depends` whose presence is the effect, a
parameter another layer answers for (`output_mode` is Splunk middleware's,
`api-version` is the ARM middleware's — each checked against the running
mock before it was written down), and a body the vendor's reference
documents no member for.

**The three things Elasticsearch lets a client do to any answer.**
None of them is a per-route feature — every endpoint takes them — and mockdr
took all three as decoration:

* `?filter_path=` keeps only the paths named, with `*` for one segment and a
  leading `-` to drop instead of keep. A client asking for
  `hits.hits._source` was handed the whole document tree: more data than it
  asked for, in a shape it did not expect. Nothing matching answers `{}`,
  where mockdr answered everything.
* `?pretty` indents two spaces, separates with ` : ` and ends with a
  newline — Jackson's own printer, to the character.
* `X-Opaque-Id` comes back on the response. The official clients offer it as
  `opaque_id` precisely so a request can be found again in a log, and mockdr
  dropped it.

And a fourth of the same kind: `_cat` takes a `bytes` parameter that chooses
the unit, and mockdr's rows carried a rendered `180kb` — a string, which can
only ever answer in one unit. A script reading `bytes=b` to add sizes up got
text it could not add. The rows carry byte counts now and the unit is chosen
at render time, in the product's own human form: one decimal at most,
truncated rather than rounded, and none at all when it would be a zero.

All measured on 8.15, and all four invisible to `param_effect.py`, which
listed `pretty`, `format` and `bytes` among the parameters that are
*structural* and exercised none of them. It exercises them now, per mount
rather than per declaration — these are read off the query string by the
product, so requiring a route to declare one would have been the same blind
spot one level down — and it knows what they do *not* apply to: a `_cat`
table is shaped by neither until `format=json` makes the answer a document,
and a list that a filter leaves empty is written as nothing at all where an
empty object is written `{}`.

`?format=yaml` and `Accept: application/yaml` are the one member of the
family left alone: Elasticsearch answers those in YAML, and rendering YAML
the way Jackson renders it is a larger piece of work than the clients that
would ask for it justify. A client asking for YAML gets JSON here, which is
stated rather than hidden.

**splunkd's own headers, and the caching it publishes.**
`Server: uvicorn` was on every answer, which is the plainest way there is to
tell a mock from the thing it mocks. Under it, measured on 10.4.2 header by
header: splunkd says what each answer depends on (`Vary: Cookie,
Authorization` — or `Authorization` alone for a session token it cannot
resolve, which is refused before its cookie handler, and nothing at all for
a collector token read from the query string); it says how each answer may
be kept (`no-store` with its own already-expired `Expires` of October 1978,
`private` for a credential it refused and for a mode it could not read); and
for the one family it serves as cacheable — `data/indexes`, on a successful
read only — it publishes a weak `ETag` and answers a matching
`If-None-Match` with `304 Not Modified`. mockdr answered the whole
collection every time, so a client revalidating a cached read never learnt
that what it held was current.

**And none of the three runnable products' compression.**
All three compress when a client offers gzip and mockdr compressed nothing —
a difference in every byte on the wire. They disagree about the details, so
one compressor for all of them gets two wrong: Elasticsearch compresses a
74-byte answer and publishes no `Vary`; Kibana, in the same distribution,
leaves an 828-byte answer alone and names the encoding when it does
compress; splunkd leaves a 127-byte refusal alone, and its event collector
never compresses at all. Each mount follows its own product now, and the six
with no runnable product are left uncompressed rather than guessed at.

The harness compares `vary` as the unordered list it is, and without
`accept-encoding`: whether *this* answer was compressed depends on how much
data each install holds, where the rest of the list says what the server
consults.

**The header every Elasticsearch client checks for, which mockdr never sent.**
`X-elastic-product: Elasticsearch` is not decoration: every official client
since 7.14 — Python, JavaScript, Java, Go — reads it off the first response
and refuses to talk to a server that does not send it, with an
`UnsupportedProductError`. The one client this mount exists for could not
use mockdr at all. Measured on 8.15: the header is on every answer including
a 404, and *not* on the 401 that asks for credentials.

Kibana names itself the same way on every answer, whatever the status:
`kbn-name`, `kbn-license-sig`, and a `cache-control` that keeps its API
answers out of every cache. mockdr sent none of the three.

Nothing noticed because the conformance harness compared two headers and no
others — a header no probe compares is a header no probe can miss. It
compares these too now: the two whose value is the behaviour by value, and
Kibana's node name and licence digest by *presence*, since their values name
the install rather than the behaviour.

**Splunk JSON that was the same document and different bytes.**
splunkd writes its JSON compact — `{"name":"x"}`, no space after the colon —
and writes non-ASCII as the UTF-8 bytes themselves. mockdr's Splunk mount
did neither consistently: the paging, search, sort and field-filter
middlewares each re-serialised with Python's defaults, so a saved search
called `Grüße` came back as `Gr\u00fce`, spaced, through one parameter and
compact through another. One server rendered the same collection two ways
depending on which parameter the client happened to send.

The same value to a parser, a different one to anything that reads the bytes
— which is what a SIEM ingesting a raw response does, and what the
conformance harness, comparing parsed documents, could never see. Measured
on 10.4.2 by creating a saved search whose name is not ASCII; the other two
runnable products already matched, because their responses are rendered
once.

**A token answer that any cache was free to keep.**
RFC 6749 §5.1: the authorization server answers a token request with
`Cache-Control: no-store`, and `Pragma: no-cache` for the caches that
predate it. None of the four OAuth mounts sent either, so a proxy or a
client library following its own cache rules could keep a bearer token and
hand it out again — the reason the requirement exists, and a step a client
built against mockdr would not have been designed around.

**One directory answering three ways.**
Defender, Graph and Sentinel sit behind the same Entra directory here.
Defender and Graph refuse a grant they do not issue for; Sentinel took
`grant_type` as a form field and never looked at it, so it minted a token
for `grant_type=password`, and for a request that named no grant at all. It
refuses both now, in the same `AADSTS70003` / `AADSTS900144` wording its two
siblings use — and its token body lost `resource`, which belongs to the v1.0
endpoint this mount is not and which neither sibling has ever sent.

**Four OAuth mounts that refused a request without saying where to get a
token.** RFC 6750 §3: a resource server that turns down a Bearer-protected
request answers with `WWW-Authenticate`, and the challenge is where a client
learns which authority to go to — it is how the Microsoft identity libraries
discover it at all. CrowdStrike, Defender, Graph and Sentinel each answered
401 with a body and no challenge, so a client built against mockdr would be
written without a step the real service requires. Each sends one now,
pointing at its own token endpoint, and keeps the section's other
distinction: a request that carried no credentials is not told its token was
invalid, because nothing was wrong with a token that was never sent.

**Fifteen documented sort fields that ordered nothing.**
The vendor documents `sortBy=createdAt` for a threat whose record keeps that
member inside `threatInfo`, and `sortBy=severity` for a cloud alert that
keeps it in `alertInfo` — and the sorter looked only at the top level, so
every key compared equal and `sortOrder=asc` came back identical to `desc`.
A client that asked for an order got whatever order the store held, and was
told nothing. A documented name is now resolved where the record actually
keeps it: the member itself, or the documented filter that already names its
path, or — for a name no filter mentions — the one nested object these
records keep it in. A name whose holders genuinely disagree is left alone
rather than guessed at, and so is one nothing carries.

`param_effect.py` could not see any of this: it guessed a sort field from
the record's top level, which is empty of sortable members on exactly the
collections that were broken. It asks once per field the vendor documents as
sortable now — 450 parameters exercised where 341 were before.

**Three states that never left `pending`.**
A playbook contains a host, isolates an endpoint, and then waits for the
action to finish. Falcon's host stayed `containment_pending` for ever,
Kibana's endpoint action stayed `pending` with no `completed_at`, and
`/api/endpoint/action_status` — which counts what is pending per agent —
only ever counted upwards. Each settles a second after it is issued now,
which is also what makes the pending state worth observing: a client that
polls twice sees the state move rather than finding it already done.

`lift_containment` went straight to `normal`, skipping the
`lift_containment_pending` the fleet is seeded with; it goes through it now,
the same way containment does. Kibana's settled status is `successful`,
measured on 8.15: `statuses` there takes `failed`, `pending` and
`successful`, and refuses anything else — which is how the vocabulary was
established without the licence that would have let the actions themselves
be called.

**A Cortex action a playbook could poll for ever.**
`get_action_status` answers `data` as a map from endpoint id to status —
which is exactly what a playbook waits on: it isolates an endpoint and polls
until that endpoint's key says `COMPLETED_SUCCESSFULLY`. mockdr answered
with the action's own record, completed against a reply recorded on another
install, so every answer carried the same three foreign endpoint ids and the
one the client had just acted on was never among them. The completion step
is gone from that route — the recorded reply's members are *endpoint ids*,
not member names, so filling an answer out against it adds someone else's
endpoints to it — and the status is spelled the way the recordings spell it.
`errorReasons` appears only for the endpoints that failed, as it does there.

The seeded action statuses shrank with it: `in_progress` and `canceled` were
seeded, and no reading in `data/vendor-specs/` shows how Cortex spells either
on the wire. A client switching on that value would have been handed a
guess, so the seeded vocabulary is now the one that can be answered exactly.

**Six Cortex routes that answered only one spelling of their own path.**
Cortex paths are written both ways in the wild — the community transcription
without a trailing slash, connector code with one — and mockdr served
forty-five of its fifty-one with the slash and six without, refusing the
other form with a 404. A client keeping to either convention hit a wall on
some routes. Each answers to both now, and the alias stays out of the schema
so the published surface still names one path per route.

**Half the agent actions the vendor publishes answered 400.**
SentinelOne publishes one path per agent action, and mockdr serves them
through a single route that knew twenty-three of the thirty-eight — so
`ranger-disable`, `start-profiling`, `update-software`,
`approve-uninstall` and eleven others were refused, and the refusal said the
request had been understood and rejected rather than never offered. The ones
that leave a mark on the agent record now leave it: Network Discovery moves
`rangerStatus`, profiling moves `remoteProfilingState`, an update leaves the
agent up to date, an approved uninstall request stops being pending and the
agent uninstalls. The rest count and log an activity, which is all the
record shows for a broadcast either. Every effect is the one the vendor's
own description states.

And a name that is not an action at all now answers 404 in the envelope a
missing path answers with, because that is what it is — one route standing
in for thirty-eight must not turn a path the product does not have into a
request it understood.

**Thirty-one write routes that answered 200 to an empty body.**
A threat marked as an incident with no verdict in the body, an exclusion
created out of nothing, a policy replaced by an empty document — each
reported success, which leaves a client believing the write happened the way
it asked. The 2.1 swagger says what those bodies are made of: every one of
these routes declares `data`, `filter` or both as required, and declares the
members each holds. `scripts/gen_documented_bodies.py` derives that table,
and a body carrying none of those names is refused in SentinelOne's own
envelope.

What the guard deliberately does not do is decide which combination is
enough. The reference says `data` is required for `/threats/analyst-verdict`
and says nothing about the flat form this mock also takes, so a body
carrying either is let through — the check is that something was sent. A
route the mock declares no body for is left alone for the same reason: the
swagger marks `data` required on some of those, and requiring one there
would invent a rule rather than enforce a documented one.

Two more were Cortex XDR's. Its reference states a requirement for 68 of its
routes and none at all for most of the rest — `xql/get_quota` gives
`{"request_data": null}` as its own example — so quarantine status for no
files and a user group lookup for no group are refused now, and the nine
routes the reference is silent about go on answering, because refusing a
body a product may well accept is the same defect facing the other way.
`scripts/cortex_openapi_spec.py` keeps that side of the transcription now,
alongside the reply shapes it already kept.

Six more were CrowdStrike's, and gofalcon's `request_required` says the same
thing about them: a host action addressed to no host, an indicator create
with no indicators, a case tagged with nothing — each answering 200 with an
empty `resources` list, which reads exactly like a request that matched
nothing. The same check covers both mounts, and stops at the same place:
gofalcon marks `indicators` *and* `bulk_update` required on one route where
a client sends one or the other, so demanding a particular combination would
refuse a request the product takes.

**Five routes that read nothing of the body they declare.**
Found by a new audit that asks every such route what it does with a body
that cannot be what it meant — an empty object, and one carrying a single
member the route never declared:

* `POST /_aliases` answered `acknowledged` to an empty action list, so a
  client whose own filter had matched nothing was told the aliases were
  updated; and it took a member Elasticsearch refuses by name.
* `POST /_count` took `size`, `aggs` and `from` — the neighbouring
  `_search`'s members — and counted with them silently dropped.
* `POST …/rules/_export` exported *everything* when the body named nothing,
  where Kibana requires `objects` and exports nothing for an empty
  selection; the rules it could not find are now listed in `missing_rules`,
  and the summary line carries the fifteen members the real one does.
* `POST …/endpoint/suggestions/{type}` answered with every hostname it held
  when the body said which field to suggest for.

All measured on 8.15. The audit is `scripts/body_audit.py`, and it needs no
vendor reference: a route that accepts a body it cannot have meant is wrong
whatever the product does.

**An exception item nothing checked.**
Every write to `/api/exception_lists/items` was accepted: an empty body
created an item, so did one naming a list that does not exist, and so did an
entry whose `operator` Kibana has never had — each reported as a success. An
exception with no entries matches nothing, so a rule carrying it behaves as
though the exception were not there, and the client had just been told it
was. Twenty error paths are compared against Kibana 8.15 byte for byte now,
including the entry union: an entry is checked against four branches, and
one that satisfies none of them is reported branch by branch, each distinct
failure once. Listing items without a `list_id` was the same class in the
other direction — it answered with every item mockdr held, across every
list, as though they were that list's.

**And the exceptions mockdr ships used an operator no Kibana emits.**
The seeded items were written with `operator: "is"`; the vocabulary is
`included` and `excluded`. A client reading an exception and writing it back
the way it read it is exactly what the new validation answers 400 to — which
is how the fixture was found.

**Nine members a rule was told it had, and one it was not.**
A rule created with the required fields alone carries none of
`building_block_type`, `filters`, `investigation_fields`, `license`, `meta`,
`note`, `throttle`, `timeline_id` or `timeline_title` — mockdr filled all
nine in, so a client read a `note` and a timeline the product would not have
mentioned. They are echoed now only when the client set one. The member
Kibana does add, `execution_summary`, mockdr never had while accepting a
sort over a field inside it; a listing carries it for every rule and leaves
it `null` where nothing has run, a single rule that never ran does not carry
it at all, and the sort now resolves the nested name instead of finding
nothing under it and reporting a sort it had not performed.

**A rule's two counters, and the wrong one moving.**
`version` is the author's and only ever changes because a client set it;
`revision` is Kibana's own modification counter. mockdr incremented
`version` on every update and left `revision` at 0, so a client tracking
either learned the opposite of what it asked. `revision` now counts what
Kibana counts: a change to the rule's parameters, not enabling it and not
re-sending a value it already had.

**The call a client makes to change one member.**
`PATCH /api/detection_engine/rules` had no route, so the only way to change
a rule was a `PUT` that resets everything the body leaves out — and mockdr's
`PUT` merged instead of replacing, which hid that. Both are right now, both
take either identifier (a client that created a rule knows its `rule_id`,
not the internal `id`, and demanding the latter answered 400 for a perfectly
formed request), and both name the missing one the way Kibana does.

**`_bulk_get` served where Kibana does not serve it.**
Cases' `_bulk_get` lives under `/internal`, not `/api`; mockdr had it the
other way round, so a client using the product's path got 404 and one
written against mockdr got a success the product would not give. Its misses
are named after the saved object rather than the case, and the four ways it
rejects an `ids` argument — missing, empty, not an array, not strings — are
each measured, including the one Kibana answers with a 500.

**A conformance stack that could not be rebuilt.**
Elasticsearch starts with a password for `elastic` and none for
`kibana_system`, so Kibana could not authenticate and never left
`unavailable` — and every Kibana probe then compared the mock against a
product that was not running. The password was a manual step in the README,
and it survived unnoticed for as long as a data volume did: the first
`docker compose down -v` took it with the volume, and the harness reported
fifty differences that were all the same fact. `compose.yml` sets it now,
and the bootstrap refuses to run at all while Kibana reports itself
unavailable — saying it once, at the top, beats fifty findings that read as
mock defects.

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


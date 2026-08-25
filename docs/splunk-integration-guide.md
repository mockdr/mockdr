# Splunk Integration Guide

## Overview

MockDR includes a full-fidelity Splunk Enterprise REST API mock that runs on the same port as all other vendors, mounted under the `/splunk` path prefix. It is compatible with the Cortex XSOAR SplunkPy integration.

## Connection Details

| Setting | Value |
|---------|-------|
| Base URL | `http://localhost:8001/splunk` |
| Management API | `/splunk/services/...` |
| HEC | `/splunk/services/collector/...` |
| Auth | Basic Auth or Bearer Token |

## Credentials

| Username | Password | Roles |
|----------|----------|-------|
| `admin` | `mockdr-admin` | `admin` |
| `analyst` | `mockdr-analyst` | `sc_admin` |
| `viewer` | `mockdr-viewer` | `user` |

## HEC Tokens

| Token Name | Token Value | Index | Sourcetype |
|------------|-------------|-------|------------|
| `mockdr-edr-sentinelone` | `11111111-1111-1111-1111-111111111111` | `sentinelone` | `sentinelone:channel:threats` |
| `mockdr-edr-crowdstrike` | `22222222-2222-2222-2222-222222222222` | `crowdstrike` | `CrowdStrike:Event:Streams:JSON` |
| `mockdr-edr-general` | `33333333-3333-3333-3333-333333333333` | `main` | (any) |

## Indexes

| Index | Description | Sourcetypes |
|-------|-------------|-------------|
| `sentinelone` | SentinelOne events | `sentinelone:channel:threats`, `sentinelone:channel:agents`, `sentinelone:channel:activities` |
| `crowdstrike` | CrowdStrike events | `CrowdStrike:Event:Streams:JSON` |
| `msdefender` | Microsoft Defender events | `ms:defender:atp:alerts`, `ms:defender:machines` |
| `elastic_security` | Elastic Security events | `elastic:security:alerts`, `elastic:security:endpoints` |
| `cortex_xdr` | Cortex XDR events | `pan:xdr:incident`, `pan:xdr:alert`, `pan:xdr:endpoint` |
| `notable` | ES notable events | `stash` |
| `main` | Default index | (any) |

## XSOAR SplunkPy Configuration

To connect XSOAR SplunkPy to MockDR:

1. **Host**: `localhost` (or Docker hostname)
2. **Port**: `8001`
3. **Username**: `admin`
4. **Password**: `mockdr-admin`
5. **Splunk URL prefix**: `/splunk`
6. **Fetch notable events**: Enabled
7. **Notable macro**: `` `notable` ``

## Supported SPL

Commands run in the order they are written, so `| head 1 | sort _time` and
`| sort _time | head 1` differ the way they do in Splunk. A command the mock
does not implement is refused the way splunkd refuses an unknown one, rather
than being ignored.

```spl
search index=<index> sourcetype=<sourcetype> <field>=<value>
| makeresults [count=<n>] [annotate=<bool>]
| makeresults format=csv|json data="<inline rows>"
| search <expr>            | where <expr>
| eval <field>=<expr>      | fields [+|-] <field> ...
| table <field> ...        | rename <old> as <new>
| head <N>                 | tail <N>
| sort [-]<field>, ...     | dedup <field> ...
| stats <func>(<field>) [as <name>] [by <field>]
| timechart span=<span> <func>(<field>) [by <field>]
| top [<N>] <field>        | rare [<N>] <field>
| rex field=<field> "<regex>"   | regex <field>="<regex>"
| fillnull [value=<v>] [<field> ...]
`notable`   (macro → search index=notable)
```

Time modifiers: `earliest=-24h`, `latest=now`, `earliest=-7d@d`

### eval functions

Around fifty, measured one by one against Splunk 10.4.2: the multivalue
family (`split`, `mvindex`, `mvjoin`, `mvfilter`, `mvmap`, …), text
(`upper`, `substr`, `replace`, `printf`, `md5`, `sha256`, …), maths
(`round`, `pow`, `sqrt`, `log`, …), time (`strftime`, `strptime`,
`relative_time`), JSON (`spath`, `json_extract`, `json_object`, …),
`cidrmatch`, and the conditionals (`if`, `case`, `coalesce`, `validate`).

The strictness is measured too, because a client keys on it:

* Argument *types* are checked. `len(123)`, `upper(1)` and `md5(1)` are
  "The arguments to the '<name>' function are invalid" — not answers.
* Types the expression can be seen to have are checked before the search
  runs: `"1"+1` is refused, where `field+1` waits for the row and yields
  null if the value is not a number.
* `null()` is a typed null, and not the same thing as a field the row does
  not have: `upper(null())` is an argument error, `upper(nosuchfield)` is
  null and leaves the field unassigned.
* A field cannot be assigned a boolean — `eval v=1==1` is refused with
  splunkd's own suggestion to use `if()`.

## Notable Event Status Values

| Code | Label |
|------|-------|
| `1` | New |
| `2` | In Progress |
| `3` | Pending |
| `4` | Resolved |
| `5` | Closed |

## Example curl Commands

### Login
```bash
curl -X POST "http://localhost:8001/splunk/services/auth/login?output_mode=json" \
  -d "username=admin&password=mockdr-admin"
```

Responses are Atom XML by default, as splunkd's are; `output_mode=json` switches
to JSON, and the Splunk SDKs set it on every request. mockdr reads
`output_mode` from the query string only — real splunkd also accepts it as a
POST parameter — so pass it in the URL. HEC (`/services/collector`) always
answers JSON and ignores the parameter, matching the real service.

### Search
```bash
curl -X POST http://localhost:8001/splunk/services/search/jobs \
  -H "Authorization: Basic YWRtaW46bW9ja2RyLWFkbWlu" \
  -H "Content-Type: application/json" \
  -d '{"search": "search index=sentinelone | head 5"}'
```

### Get Results
```bash
curl http://localhost:8001/splunk/services/search/v2/jobs/{sid}/results \
  -H "Authorization: Basic YWRtaW46bW9ja2RyLWFkbWlu"
```

### Submit HEC Event
```bash
curl -X POST http://localhost:8001/splunk/services/collector/event \
  -H "Authorization: Splunk 11111111-1111-1111-1111-111111111111" \
  -d '{"event": {"message": "test"}, "sourcetype": "test", "index": "sentinelone"}'
```

### Update Notable
```bash
curl -X POST http://localhost:8001/splunk/services/notable_update \
  -H "Authorization: Basic YWRtaW46bW9ja2RyLWFkbWlu" \
  -H "Content-Type: application/json" \
  -d '{"ruleUIDs": ["event-id"], "status": "2", "comment": "Investigating"}'
```

### Server Info
```bash
curl -u admin:mockdr-admin "http://localhost:8001/splunk/services/server/info?output_mode=json"
```

`server/info` requires authentication, as it does on splunkd.

### Health Check
The unauthenticated health endpoint is HEC's, as on a real Splunk:
```bash
curl http://localhost:8001/splunk/services/collector/health
```

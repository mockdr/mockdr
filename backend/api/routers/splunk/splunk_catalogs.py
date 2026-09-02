"""The read-only catalogues splunkd serves beside its data.

An endpoint sweep against 10.4.2 found every one of these answering 404
here: the health tree a monitor polls, the extended index list an app reads
sizes from, the licence a client checks before offering a feature, and the
knowledge objects — macros, event types, source types, lookups — that
content packs enumerate.

Where mockdr has the thing, it serves it: an index per index, a source type
per sourcetype its events carry, and the ``notable`` macro its own SPL
understands. Where it has none — no lookups, no monitored files — it serves
an *empty collection* rather than a 404, which is the difference between
"this deployment has none" and "this endpoint does not exist".

Each entry's content is filled out from a recording of the real collection
(``infrastructure/fixtures/splunk/*.json``), because a client reads deep
into these: a source type carries forty-two settings and an extended index
a hundred and nineteen.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.splunk_auth import require_splunk_auth
from repository.splunk.splunk_event_repo import splunk_event_repo
from repository.splunk.splunk_index_repo import splunk_index_repo
from utils.splunk.response import build_splunk_entry, build_splunk_envelope, complete

router = APIRouter(tags=["Splunk Catalogs"])

#: The macro mockdr's SPL knows: `notable` stands for the notable index, and
#: Splunk ES content is written in terms of it.
_MACROS = {
    "notable": "search index=notable",
}

#: What splunkd puts in a macro's content beyond the five every macro
#: carries. Measured on 10.4.2 across the eight macros a stock install
#: ships: `args` appears only on a macro that takes arguments,
#: `errormsg` and `validation` only on one that validates them, and
#: `iseval` only on an eval macro (`comment(1)`). The recorded fixture is
#: a composite of three different macros, so completing from it gave
#: `notable` an argument it does not take and `histperc`'s error message
#: about `perc` and `hist_rate` -- three members splunkd would have
#: omitted, one of them describing a different macro entirely.
_MACRO_OPTIONAL = ("args", "errormsg", "iseval", "validation")


def _macro_content(definition: str) -> dict:
    """A macro's content: the five every macro carries, and nothing else."""
    content = complete({"definition": definition, "disabled": False}, "macro")
    for optional in _MACRO_OPTIONAL:
        content.pop(optional, None)
    return content

#: A knowledge object — a macro, an event type, a lookup — carries four more
#: acl members than a system entry does, because it can be shared.
#: What each collection offers as a whole. A system collection offers
#: nothing; a knowledge-object one can be created in, reloaded and its
#: permissions read (all measured on 10.4.2).
_KNOWLEDGE_LINKS = {"_acl": "", "_reload": "", "create": ""}


def _collection(entries: list[dict], origin: str, links: dict | None = None) -> dict:
    """A read-only Atom collection, with the links such a one carries."""
    path = f"/services/{origin}"
    return build_splunk_envelope(
        entries,
        origin=path,
        links={name: f"{path}/{name}".replace("//", "/") if name != "create"
               else f"{path}/_new" for name in (links or {})},
    )


def _knowledge_links(origin: str) -> dict:
    """The link block a knowledge-object collection carries."""
    return dict(_KNOWLEDGE_LINKS)


@router.get("/services/server/health/splunkd")
def server_health(_user: dict = Depends(require_splunk_auth)) -> dict:
    """The health tree, which a monitor polls and a client checks first."""
    entry = build_splunk_entry(
        "splunkd",
        {"health": "green", "eai:acl": None},
        collection="server/health",
        links=("alternate", "list", "details"),
        fields=False,
        acl_extra={"perms": {"read": ["admin", "splunk-system-role"],
                                      "write": []}},
    )
    return _collection([entry], "server/health")


@router.get("/services/data/indexes-extended")
def indexes_extended(_user: dict = Depends(require_splunk_auth)) -> dict:
    """Every index, with the bucket and size detail an app reads."""
    entries = [
        build_splunk_entry(
            index.name,
            complete({
                # Every number in an index entry is a *string* there.
                "currentDBSizeMB": "1",
                "totalEventCount": sum(
                    1 for event in splunk_event_repo.list_all()
                    if getattr(event, "index", "") == index.name
                ),
            }, "indexes_extended"),
            collection="data/indexes-extended",
            links=("alternate", "list"),
            fields=False,
            # A read-only view of the indexes, not an editable object.
            acl_extra={"modifiable": False, "perms": {"read": ["*"], "write": []}},
        )
        for index in splunk_index_repo.list_all()
    ]
    return _collection(entries, "data/indexes-extended")


@router.get("/services/licenser/licenses")
def licenses(_user: dict = Depends(require_splunk_auth)) -> dict:
    """The licence this instance runs under."""
    entry = build_splunk_entry(
        "mockdr-enterprise",
        complete({"label": "mockdr Enterprise", "type": "enterprise",
                  "status": "VALID"}, "license"),
        collection="licenser/licenses",
        links=("alternate", "list", "edit"),
        fields=False,
        acl_extra={"perms": {"read": ["admin", "splunk-system-role"],
                                      "write": ["admin", "splunk-system-role"]}},
    )
    return _collection([entry], "licenser/licenses", {"create": ""})


@router.get("/services/authorization/grantable_capabilities")
def grantable_capabilities(_user: dict = Depends(require_splunk_auth)) -> dict:
    """Which capabilities this role may hand on to another."""
    entry = build_splunk_entry(
        "system",
        complete({}, "grantable_capabilities"),
        collection="authorization/grantable_capabilities",
        links=("alternate", "list"),
        fields=False,
        acl_extra={"perms": {"read": ["*"], "write": ["*"]}},
    )
    return _collection([entry], "authorization/grantable_capabilities")


@router.get("/servicesNS/{_owner}/{_app}/admin/macros")
@router.get("/services/admin/macros")
def macros(
    _owner: str = "nobody", _app: str = "search",
    _user: dict = Depends(require_splunk_auth),
) -> dict:
    """The search macros this deployment defines."""
    entries = [
        build_splunk_entry(
            name,
            _macro_content(definition),
            collection="admin/macros",
            links=("_reload", "alternate", "disable", "edit", "list"),
            fields=False,
            acl_extra={"perms": {"read": ["*"], "write": ["admin", "power"]}},
        )
        for name, definition in sorted(_MACROS.items())
    ]
    return _collection(entries, "admin/macros", _knowledge_links("admin/macros"))


@router.get("/servicesNS/{_owner}/{_app}/admin/macros/{name}")
@router.get("/services/admin/macros/{name}")
def macro(
    name: str,
    _owner: str = "nobody", _app: str = "search",
    _user: dict = Depends(require_splunk_auth),
) -> dict:
    """One macro by name.

    The listing named every macro and nothing would serve one, so a client
    that listed them and then read one got 404 for a macro the listing had
    just named. splunkd serves it, with the `fields` block a single read
    carries and the listing does not.
    """
    if name not in _MACROS:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Could not find object id={name}"},
        ]})
    entry = build_splunk_entry(
        name,
        _macro_content(_MACROS[name]),
        collection="admin/macros",
        links=("_reload", "alternate", "disable", "edit", "list"),
        # Measured on 10.4.2: the definition is required, the rest optional.
        fields={
            "required": ["definition"],
            "optional": ["args", "disabled", "errormsg", "iseval", "validation"],
            "wildcard": [],
        },
        acl_extra={"perms": {"read": ["*"], "write": ["admin", "power"]}},
    )
    return _collection([entry], "admin/macros", _knowledge_links("admin/macros"))


@router.get("/services/saved/sourcetypes")
def sourcetypes(_user: dict = Depends(require_splunk_auth)) -> dict:
    """One entry per source type the events actually carry."""
    seen = sorted({
        str(getattr(event, "sourcetype", "") or "")
        for event in splunk_event_repo.list_all()
    } - {""})
    entries = [
        build_splunk_entry(
            name, complete({}, "sourcetype"), collection="saved/sourcetypes",
            links=("_reload", "alternate", "edit", "list", "move", "remove"),
            fields=False,
            acl_extra={"perms": {"read": ["*"], "write": ["*"]}},
        )
        for name in seen
    ]
    return _collection(
        entries, "saved/sourcetypes", _knowledge_links("saved/sourcetypes"),
    )


#: An empty collection is not a 404: it says the endpoint is there and this
#: instance defines none of the thing it lists.


@router.get("/services/saved/eventtypes")
def eventtypes(_user: dict = Depends(require_splunk_auth)) -> dict:
    """Event types, of which this deployment defines none."""
    return _collection([], "saved/eventtypes", _knowledge_links("saved/eventtypes"))


@router.get("/services/data/transforms/lookups")
def lookup_transforms(_user: dict = Depends(require_splunk_auth)) -> dict:
    """Lookup definitions, of which this deployment has none."""
    return _collection([], "data/transforms/lookups", _knowledge_links("data/transforms/lookups"))


@router.get("/services/data/lookup-table-files")
def lookup_files(_user: dict = Depends(require_splunk_auth)) -> dict:
    """Lookup table files, of which this deployment has none."""
    return _collection([], "data/lookup-table-files", _knowledge_links("data/lookup-table-files"))


@router.get("/services/data/inputs/monitor")
def monitor_inputs(_user: dict = Depends(require_splunk_auth)) -> dict:
    """Monitored files, of which this deployment has none."""
    return _collection([], "data/inputs/monitor", _knowledge_links("data/inputs/monitor"))


@router.get("/services/data/inputs/tcp/raw")
def tcp_inputs(_user: dict = Depends(require_splunk_auth)) -> dict:
    """Raw TCP inputs, of which this deployment has none."""
    return _collection([], "data/inputs/tcp/raw", _knowledge_links("data/inputs/tcp/raw"))


@router.get("/services/data/props/extractions")
def extractions(_user: dict = Depends(require_splunk_auth)) -> dict:
    """Field extractions, of which this deployment defines none."""
    return _collection([], "data/props/extractions", _knowledge_links("data/props/extractions"))

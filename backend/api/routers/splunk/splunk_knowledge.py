"""Lookup definitions and data models: what ``lookup`` and ``tstats`` resolve.

``data/transforms/lookups`` lists the lookup definitions a search's
``lookup`` and ``inputlookup`` resolve names through — the KV Store
collections' and the CSV files' — and takes new ones, so a test can define a
lookup over a collection it filled itself. ``datamodel/model`` lists the CIM
data models ``tstats … from datamodel=`` reads, and ``data/lookup-table-files``
the CSV files the file-based definitions read.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from api.splunk_auth import require_splunk_admin, require_splunk_auth
from api.splunk_body import parse_body
from application.splunk.commands.lookups import (
    LookupDefinitionError,
    create_definition,
    delete_definition,
)
from application.splunk.queries.datamodels import get_model, list_models
from application.splunk.queries.lookups import (
    definition_entry,
    get_definition,
    list_definitions,
    list_lookup_files,
    transforms_envelope,
)

router = APIRouter(tags=["Splunk Knowledge Objects"])


def _not_found(name: str) -> HTTPException:
    return HTTPException(status_code=404, detail={"messages": [
        {"type": "ERROR", "text": f"Could not find object id={name}"},
    ]})


@router.get("/services/data/transforms/lookups")
@router.get("/servicesNS/{_owner}/{_app}/data/transforms/lookups")
def lookup_definitions(
    _owner: str = "nobody", _app: str = "search",
    _user: dict = Depends(require_splunk_auth),
) -> dict:
    """Every lookup definition. All are shared globally, so every app sees all."""
    return list_definitions()


@router.get("/services/data/transforms/lookups/{name}")
@router.get("/servicesNS/{_owner}/{_app}/data/transforms/lookups/{name}")
def lookup_definition(
    name: str, _owner: str = "nobody", _app: str = "search",
    _user: dict = Depends(require_splunk_auth),
) -> dict:
    """One lookup definition by name."""
    found = get_definition(name)
    if found is None:
        raise _not_found(name)
    return found


@router.post("/services/data/transforms/lookups")
@router.post("/servicesNS/{owner}/{app}/data/transforms/lookups")
async def create_lookup_definition(
    request: Request, owner: str = "nobody", app: str = "search",
    _user: dict = Depends(require_splunk_admin),
) -> JSONResponse:
    """Define a lookup over a KV Store collection or a CSV file; 201 with the entry."""
    try:
        definition = create_definition(await parse_body(request), app, owner)
    except LookupDefinitionError as exc:
        return JSONResponse(status_code=exc.status, content={"messages": [
            {"type": "ERROR", "text": str(exc)},
        ]})
    return JSONResponse(
        status_code=201, content=transforms_envelope([definition_entry(definition)]),
    )


@router.delete("/services/data/transforms/lookups/{name}")
@router.delete("/servicesNS/{_owner}/{_app}/data/transforms/lookups/{name}")
def delete_lookup_definition(
    name: str, _owner: str = "nobody", _app: str = "search",
    _user: dict = Depends(require_splunk_admin),
) -> dict:
    """Remove a lookup definition; the collection that remains is the answer."""
    if not delete_definition(name):
        raise _not_found(name)
    return list_definitions()


@router.get("/services/data/lookup-table-files")
def lookup_table_files(_user: dict = Depends(require_splunk_auth)) -> dict:
    """The CSV lookup table files the file-based definitions read."""
    return list_lookup_files()


@router.get("/services/datamodel/model")
@router.get("/servicesNS/{_owner}/{_app}/datamodel/model")
def data_models(
    _owner: str = "nobody", _app: str = "search",
    _user: dict = Depends(require_splunk_auth),
) -> dict:
    """The CIM data models ``tstats`` reads."""
    return list_models()


@router.get("/services/datamodel/model/{name}")
@router.get("/servicesNS/{_owner}/{_app}/datamodel/model/{name}")
def data_model(
    name: str, _owner: str = "nobody", _app: str = "search",
    _user: dict = Depends(require_splunk_auth),
) -> dict:
    """One data model by name."""
    found = get_model(name)
    if found is None:
        raise _not_found(name)
    return found

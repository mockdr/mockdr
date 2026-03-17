"""Serve an auto-generated OpenAPI spec and Swagger UI for the mock server.

The spec is derived from FastAPI's registered routes — no external file needed.
"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

router = APIRouter(tags=["docs"])


@router.get("/doc/spec.json", include_in_schema=False)
def spec_json(request: Request) -> JSONResponse:
    """Return the OpenAPI spec generated from the mock server's registered routes."""
    schema = request.app.openapi()
    return JSONResponse(content=schema)


@router.get("/doc", include_in_schema=False)
def swagger_ui() -> HTMLResponse:
    """Render Swagger UI pointing at the local spec endpoint."""
    html = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Mock Server — SentinelOne API v2.1</title>
  <link rel="stylesheet"
        href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body { margin: 0; }
    #banner {
      background: #1a1a2e;
      color: #e0e0e0;
      text-align: center;
      padding: 10px 0;
      font-family: sans-serif;
      font-size: 14px;
      letter-spacing: 0.5px;
    }
    #banner strong { color: #7c4dff; }
  </style>
</head>
<body>
  <div id="banner">
    <strong>Mock Server</strong> &mdash; SentinelOne Management Console API v2.1
  </div>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: "/web/api/v2.1/doc/spec.json",
      dom_id: "#swagger-ui",
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: "BaseLayout",
    });
  </script>
</body>
</html>"""
    return HTMLResponse(content=html)

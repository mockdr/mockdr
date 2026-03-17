"""Splunk users router (forwarded from auth router for modularity).

Users are handled in ``api/routers/splunk/splunk_auth.py`` — this file exists
for organizational completeness but re-exports nothing since all user
endpoints (``/services/authentication/users``, ``/services/authorization/roles``,
etc.) are already registered on the auth router.
"""

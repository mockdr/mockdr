"""Thread-safe in-memory store.

Each domain owns a named collection.  All mutations go through a write lock;
reads acquire a shared read lock so they never see a partially-mutated state.
"""
from __future__ import annotations

import collections
import threading
from typing import Any


class InMemoryStore:
    """Thread-safe in-memory key-value store organised into named collections."""

    def __init__(self) -> None:
        """Initialise all domain collections and the activity-ordering list."""
        self._lock = threading.RLock()
        self._collections: dict[str, dict[str, Any]] = {
            "accounts": {},
            "sites": {},
            "groups": {},
            "agents": {},
            "threats": {},
            "alerts": {},
            "activities": {},      # keyed by id, ordered via list below
            "exclusions": {},
            "blocklist": {},
            "policies": {},        # key pattern: "site:{id}" | "group:{id}"
            "firewall_rules": {},
            "device_control_rules": {},
            "iocs": {},
            "installed_apps": {},
            "dv_queries": {},
            "users": {},
            "api_tokens": {},      # keyed by token string
            "tags": {},
            "webhook_subscriptions": {},
            "webhook_sink": {},    # keyed by id, ordered via list below
            "request_logs": {},    # keyed by id, ordered via list below
            "star_rules": {},      # STAR custom detection rules
            "remote_script_runs": {},  # remote script execution records
            "agent_uploads": {},   # keyed by activity_id; value is raw zip bytes
            # ── CrowdStrike Falcon collections ────────────────────────────────
            "cs_hosts": {},
            "cs_detections": {},
            "cs_incidents": {},
            "cs_iocs": {},
            "cs_host_groups": {},
            "cs_oauth_clients": {},
            "cs_oauth_tokens": {},   # keyed by access token string
            "cs_users": {},
            "cs_quarantined_files": {},
            "cs_cases": {},
            # ── Elastic Security collections ───────────────────────────────
            "es_endpoints": {},
            "es_rules": {},
            "es_alerts": {},
            "es_cases": {},
            "es_case_comments": {},
            "es_exception_lists": {},
            "es_exception_items": {},
            "es_action_responses": {},
            "es_api_keys": {},
            # ── Microsoft Defender for Endpoint collections ────────────────
            "mde_oauth_clients": {},
            "mde_oauth_tokens": {},   # keyed by access token string
            "mde_machines": {},
            "mde_alerts": {},
            "mde_indicators": {},
            "mde_machine_actions": {},
            "mde_investigations": {},
            "mde_software": {},
            "mde_vulnerabilities": {},
            # ── Palo Alto Cortex XDR collections ────────────────────────────
            "xdr_incidents": {},
            "xdr_alerts": {},
            "xdr_endpoints": {},
            "xdr_scripts": {},
            "xdr_iocs": {},
            "xdr_actions": {},
            "xdr_audit_logs": {},
            "xdr_distributions": {},
            "xdr_api_keys": {},
            "xdr_hash_exceptions": {},
            "xdr_xql_queries": {},
            # ── Splunk SIEM collections ─────────────────────────────────────
            "splunk_events": {},
            "splunk_search_jobs": {},
            "splunk_saved_searches": {},
            "splunk_notables": {},
            "splunk_hec_tokens": {},
            "splunk_kv_collections": {},
            "splunk_indexes": {},
            "splunk_users": {},
            "splunk_sessions": {},
            "splunk_fired_alerts": {},
            # ── Microsoft Sentinel collections ──────────────────────────────
            "sentinel_incidents": {},
            "sentinel_alerts": {},
            "sentinel_alert_rules": {},
            "sentinel_watchlists": {},
            "sentinel_threat_indicators": {},
            "sentinel_bookmarks": {},
            "sentinel_entities": {},
            "sentinel_incident_comments": {},
            "sentinel_data_connectors": {},
            "sentinel_oauth_clients": {},
            "sentinel_oauth_tokens": {},
            # ── Cross-EDR identity mapping ───────────────────────────────────
            "edr_id_map": {},  # keyed by s1_agent_id → {cs_device_id, mde_machine_id}
        }
        # newest-first ordered IDs
        self._activity_order: collections.deque[str] = collections.deque(maxlen=10000)
        self._request_log_order: list[str] = []  # newest-first ordered IDs, max 500
        self._webhook_sink_order: list[str] = []  # newest-first ordered IDs, max 500
        self._on_mutate: Any = None  # Optional callback after mutations

    # ── helpers ────────────────────────────────────────────────────────────────

    def _notify(self) -> None:
        """Fire the mutation callback if one is registered."""
        if self._on_mutate is not None:
            self._on_mutate()

    # ── Generic CRUD ─────────────────────────────────────────────────────────

    def get(self, collection: str, id: str) -> Any | None:
        """Return the record with the given ID from the named collection."""
        with self._lock:
            return self._collections[collection].get(id)

    def get_all(self, collection: str) -> list[Any]:
        """Return all records from the named collection.

        .. warning::

            The returned objects are **live references** to the stored domain
            objects.  Mutating them changes the in-memory state directly but
            does **not** trigger the persistence notification.  Callers that
            modify a returned object must call ``save()`` afterwards so that
            the mutation callback fires and any file-based persistence layer
            is notified.
        """
        with self._lock:
            return list(self._collections[collection].values())

    def save(self, collection: str, id: str, record: Any) -> None:
        """Persist a record under the given ID in the named collection."""
        with self._lock:
            self._collections[collection][id] = record
            self._notify()

    def delete(self, collection: str, id: str) -> bool:
        """Delete a record from the named collection.

        Returns:
            True if the record existed and was deleted, False otherwise.
        """
        with self._lock:
            if id not in self._collections[collection]:
                return False
            del self._collections[collection][id]
            self._notify()
        return True

    def exists(self, collection: str, id: str) -> bool:
        """Return True if a record with the given ID exists in the collection."""
        with self._lock:
            return id in self._collections[collection]

    def count(self, collection: str) -> int:
        """Return the number of records in the named collection."""
        with self._lock:
            return len(self._collections[collection])

    # ── Activity append (newest-first) ───────────────────────────────────────

    def append_activity(self, id: str, record: Any) -> None:
        """Append an activity record, maintaining newest-first ordering."""
        with self._lock:
            self._collections["activities"][id] = record
            self._activity_order.appendleft(id)
            self._notify()

    def list_activities(self) -> list[Any]:
        """Return all activity records in newest-first order."""
        with self._lock:
            return [
                self._collections["activities"][id]
                for id in self._activity_order
                if id in self._collections["activities"]
            ]

    def get_activity_order(self) -> list[str]:
        """Return a copy of the activity ordering list (newest-first)."""
        with self._lock:
            return list(self._activity_order)

    def set_activity_order(self, order: list[str]) -> None:
        """Restore the activity ordering list (used by import)."""
        with self._lock:
            self._activity_order = collections.deque(order, maxlen=10000)

    # ── Request log append (newest-first, capped at 500) ─────────────────────

    def append_request_log(self, id: str, record: Any) -> None:
        """Insert a request log record newest-first and trim to 500 entries."""
        with self._lock:
            self._collections["request_logs"][id] = record
            self._request_log_order.insert(0, id)
            if len(self._request_log_order) > 500:
                oldest = self._request_log_order[500:]
                self._request_log_order = self._request_log_order[:500]
                for oid in oldest:
                    self._collections["request_logs"].pop(oid, None)
            self._notify()

    def list_request_logs(self) -> list[Any]:
        """Return all request log records in newest-first order."""
        with self._lock:
            return [
                self._collections["request_logs"][id]
                for id in self._request_log_order
                if id in self._collections["request_logs"]
            ]

    def clear_request_logs(self) -> None:
        """Remove all request log records."""
        with self._lock:
            self._collections["request_logs"].clear()
            self._request_log_order.clear()
            self._notify()

    # ── Webhook sink append (newest-first, capped at 500) ───────────────────

    def append_webhook_sink(self, id: str, record: Any) -> None:
        """Insert a webhook sink record newest-first and trim to 500 entries."""
        with self._lock:
            self._collections["webhook_sink"][id] = record
            self._webhook_sink_order.insert(0, id)
            if len(self._webhook_sink_order) > 500:
                oldest = self._webhook_sink_order[500:]
                self._webhook_sink_order = self._webhook_sink_order[:500]
                for oid in oldest:
                    self._collections["webhook_sink"].pop(oid, None)
            self._notify()

    def list_webhook_sink(self) -> list[Any]:
        """Return all webhook sink records in newest-first order."""
        with self._lock:
            return [
                self._collections["webhook_sink"][id]
                for id in self._webhook_sink_order
                if id in self._collections["webhook_sink"]
            ]

    def clear_webhook_sink(self) -> None:
        """Remove all webhook sink records."""
        with self._lock:
            self._collections["webhook_sink"].clear()
            self._webhook_sink_order.clear()
            self._notify()

    # ── Bulk operations ───────────────────────────────────────────────────────

    def clear(self, collection: str) -> None:
        """Remove all records from the named collection."""
        with self._lock:
            self._collections[collection].clear()
            if collection == "activities":
                self._activity_order.clear()
            self._notify()

    def clear_all(self) -> None:
        """Remove all records from every collection."""
        with self._lock:
            for col in self._collections:
                self._collections[col].clear()
            self._activity_order.clear()
            self._webhook_sink_order.clear()
            self._request_log_order.clear()
            self._notify()


store = InMemoryStore()

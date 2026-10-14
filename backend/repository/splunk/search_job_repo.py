"""Repository for Splunk search job entities.

A job lives for its ``ttl`` after it completes or was last read, as on
splunkd (``SearchJob.expired``); past that it is gone, by sid and from the
listing. Every job holds its results and matched events, so without this a
client that dispatches a search per poll and never deletes it — the way the
SDKs' ``oneshot``-less examples do — kept every result set it ever asked for.
"""
import time

from config import SPLUNK_DISPATCH_SECONDS
from domain.splunk.search_job import SearchJob
from repository.base import Repository
from repository.store import store


class SearchJobRepository(Repository[SearchJob]):
    """In-memory repository for ``SearchJob`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the splunk_search_jobs collection."""
        super().__init__("splunk_search_jobs")

    def get(self, id: str) -> SearchJob | None:
        """The live job with this sid, its ttl restarted; None once reaped.

        Reading a job is viewing it: limits.conf says an actively viewed
        job's modification time "is constantly updated such that the reaper
        does not remove the job from underneath", so a client that polls or
        pages a job keeps it.
        """
        job: SearchJob | None = store.get(self._collection, id)
        if job is None:
            return None
        now = time.time()
        if job.expired(now, SPLUNK_DISPATCH_SECONDS):
            store.delete(self._collection, id)
            return None
        job.touched_at = now
        return job

    def list_all(self) -> list[SearchJob]:
        """Every job the reaper has not removed; listing them touches none."""
        now = time.time()
        return [
            job for job in store.get_all(self._collection)
            if not job.expired(now, SPLUNK_DISPATCH_SECONDS)
        ]

    def reap(self, now: float | None = None) -> int:
        """Remove every job past its ttl; how many were removed."""
        moment = time.time() if now is None else now
        expired = [
            job.sid for job in store.get_all(self._collection)
            if job.expired(moment, SPLUNK_DISPATCH_SECONDS)
        ]
        for sid in expired:
            store.delete(self._collection, sid)
        return len(expired)


search_job_repo = SearchJobRepository()

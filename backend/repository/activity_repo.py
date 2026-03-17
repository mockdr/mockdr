from domain.activity import Activity
from repository.store import store
from utils.dt import utc_now
from utils.id_gen import new_id


class ActivityRepository:
    """Repository for Activity log entries with newest-first ordering."""

    def list_all(self) -> list[Activity]:
        """Return all activities in newest-first order."""
        return store.list_activities()

    def append(self, activity: Activity) -> None:
        """Append an activity record to the store."""
        store.append_activity(activity.id, activity)

    def create(
        self,
        activity_type: int,
        description: str,
        agent_id: str | None = None,
        threat_id: str | None = None,
        user_id: str | None = None,
        site_id: str | None = None,
    ) -> Activity:
        """Create and persist a new activity record.

        Args:
            activity_type: Numeric S1 activity type code.
            description: Human-readable description of the activity.
            agent_id: Optional ID of the related agent.
            threat_id: Optional ID of the related threat.
            user_id: Optional ID of the acting user.
            site_id: Optional ID of the related site.

        Returns:
            The newly created Activity.
        """
        now = utc_now()
        activity = Activity(
            id=new_id(),
            activityType=activity_type,
            description=description,
            primaryDescription=description,
            createdAt=now,
            updatedAt=now,
            agentId=agent_id,
            threatId=threat_id,
            userId=user_id,
            siteId=site_id,
        )
        self.append(activity)
        return activity

    def create_raw(self, activity: Activity) -> None:
        """Persist a pre-built Activity object directly.

        Args:
            activity: A fully constructed Activity instance to append.
        """
        self.append(activity)


activity_repo = ActivityRepository()

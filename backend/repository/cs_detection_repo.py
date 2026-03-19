"""Repository for CrowdStrike Falcon Detection entities."""
from domain.cs_detection import CsDetection
from repository.base import Repository


class CsDetectionRepository(Repository[CsDetection]):
    """In-memory repository for ``CsDetection`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the cs_detections collection."""
        super().__init__("cs_detections")



cs_detection_repo = CsDetectionRepository()

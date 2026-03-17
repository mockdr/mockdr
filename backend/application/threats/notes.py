"""Threat analyst note commands."""
from repository.threat_repo import threat_repo
from utils.dt import utc_now
from utils.id_gen import new_id


def add_note(threat_id: str, note_text: str, user_id: str | None) -> dict | None:
    """Append an analyst note to a threat.

    Args:
        threat_id: The ID of the threat to annotate.
        note_text: The text content of the note.
        user_id: ID of the note author, if authenticated.

    Returns:
        Dict with ``data`` containing the new note, or None if threat not found.
    """
    threat = threat_repo.get(threat_id)
    if not threat:
        return None
    note = {
        "id": new_id(),
        "text": note_text,
        "createdAt": utc_now(),
        "userId": user_id,
    }
    threat.notes.append(note)
    threat_repo.save(threat)
    return {"data": note}


def bulk_add_notes(threat_ids: list[str], note_text: str, user_id: str | None = None) -> dict:
    """Append an analyst note to a list of threats.

    Implements POST /threats/notes (bulk variant).

    Args:
        threat_ids: List of threat IDs to annotate.
        note_text: The text content of the note.
        user_id: ID of the note author, if authenticated.

    Returns:
        Dict with ``data.affected`` indicating how many threats were annotated.
    """
    affected = 0
    for threat_id in threat_ids:
        if add_note(threat_id, note_text, user_id):
            affected += 1
    return {"data": {"affected": affected}}

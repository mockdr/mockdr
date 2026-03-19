from dataclasses import dataclass, field


@dataclass
class Threat:
    """Structure matches the real SentinelOne /threats API response exactly.

    Key nested dicts:
      threatInfo         – all threat-specific details
      agentDetectionInfo – agent state captured at detection time
      agentRealtimeInfo  – current live agent state
      containerInfo / ecsInfo / kubernetesInfo – cloud/container context
    """
    id: str

    threatInfo: dict = field(default_factory=dict)
    agentDetectionInfo: dict = field(default_factory=dict)
    agentRealtimeInfo: dict = field(default_factory=dict)

    indicators: list = field(default_factory=list)
    mitigationStatus: list = field(default_factory=list)
    whiteningOptions: list = field(default_factory=list)

    containerInfo: dict = field(default_factory=lambda: {
        "id": None, "image": None, "isContainerQuarantine": None,
        "labels": None, "name": None,
    })

    ecsInfo: dict = field(default_factory=lambda: {
        "clusterName": None, "serviceArn": None, "serviceName": "",
        "taskArn": None, "taskAvailabilityZone": "",
        "taskDefinitionArn": "", "taskDefinitionFamily": "",
        "taskDefinitionRevision": "", "type": "", "version": "",
    })

    kubernetesInfo: dict = field(default_factory=lambda: {
        "cluster": None, "controllerKind": None, "controllerLabels": None,
        "controllerName": None, "isContainerQuarantine": None,
        "namespace": None, "namespaceLabels": None, "node": None,
        "nodeLabels": None, "pod": None, "podLabels": None,
    })

    # Internal-only — used by mock-specific endpoints
    notes: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    # Set when fetch-file is called; stores fake file bytes (base64-encoded zip)
    _fetched_file: bytes | None = None

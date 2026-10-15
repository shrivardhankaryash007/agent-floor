"""Typed exception hierarchy for agent-floor."""


class AgentFloorError(Exception):
    """Base class for every agent-floor error."""


class PolicyError(AgentFloorError):
    """The owner policy is missing, unparsable, invalid or self-contradictory."""


class FloorUnavailableError(AgentFloorError):
    """The srt sandbox floor cannot be found or does not run; agent-floor fails closed."""

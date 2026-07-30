namespace ThreatBrief.Core.Priority;

public sealed record ThreatPriority(
    int Score,
    string Tier,
    IReadOnlyList<string> Reasons);


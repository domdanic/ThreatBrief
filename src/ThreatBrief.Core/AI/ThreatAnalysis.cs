namespace ThreatBrief.Core.AI;

public sealed record ThreatAnalysis
{
    public required string Summary { get; init; }
    public required string OrganizationalImpact { get; init; }
    public required string ExploitationPath { get; init; }
    public IReadOnlyList<string> RecommendedActions { get; init; } = [];
    public IReadOnlyList<string> Caveats { get; init; } = [];
    public required string Confidence { get; init; }
}

public sealed record StoredThreatAnalysis
{
    public required string ThreatId { get; init; }
    public required string InputFingerprint { get; init; }
    public required string Provider { get; init; }
    public required string Model { get; init; }
    public required string GeneratedAt { get; init; }
    public required ThreatAnalysis Analysis { get; init; }
}

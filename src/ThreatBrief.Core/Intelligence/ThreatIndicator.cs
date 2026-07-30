namespace ThreatBrief.Core.Intelligence;

public sealed record ThreatIndicator
{
    public long Id { get; init; }
    public required string Type { get; init; }
    public required string Value { get; init; }
    public required string NormalizedValue { get; init; }
    public string? ThreatType { get; init; }
    public string? MalwareFamily { get; init; }
    public int? Confidence { get; init; }
    public string? FirstSeenAt { get; init; }
    public string? LastSeenAt { get; init; }
    public string? ExpiresAt { get; init; }
    public bool IsActive { get; init; } = true;
    public string? ReferenceUrl { get; init; }
    public IReadOnlyList<string> Sources { get; init; } = [];
}


namespace ThreatBrief.Core.Models;

public sealed record ThreatSourceObservation
{
    public required string ThreatId { get; init; }
    public required string Source { get; init; }
    public string? ExternalId { get; init; }
    public string? SourceUrl { get; init; }
    public required string FirstSeenAt { get; init; }
    public required string LastSeenAt { get; init; }
}


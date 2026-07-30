namespace ThreatBrief.Core.Intelligence;

public sealed record IntelligenceReport
{
    public long Id { get; init; }
    public required string Source { get; init; }
    public required string ExternalId { get; init; }
    public required string Title { get; init; }
    public string? Description { get; init; }
    public string? Author { get; init; }
    public string? PublishedAt { get; init; }
    public string? ModifiedAt { get; init; }
    public string? SourceUrl { get; init; }
    public string? FirstSeenAt { get; init; }
    public string? LastSeenAt { get; init; }
    public IReadOnlyList<string> CveIds { get; init; } = [];
    public int IndicatorCount { get; init; }
}


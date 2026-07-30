namespace ThreatBrief.Core.Intelligence;

public sealed record IntelligenceBatch
{
    public required string Source { get; init; }
    public IReadOnlyList<IntelligenceReportInput> Reports { get; init; } = [];
    public IReadOnlyList<IndicatorInput> Indicators { get; init; } = [];
}

public sealed record IntelligenceReportInput
{
    public required string ExternalId { get; init; }
    public required string Title { get; init; }
    public string? Description { get; init; }
    public string? Author { get; init; }
    public string? PublishedAt { get; init; }
    public string? ModifiedAt { get; init; }
    public string? SourceUrl { get; init; }
    public IReadOnlyList<string> CveIds { get; init; } = [];
    public IReadOnlyList<IndicatorInput> Indicators { get; init; } = [];
}

public sealed record IndicatorInput
{
    public required string Type { get; init; }
    public required string Value { get; init; }
    public string? ThreatType { get; init; }
    public string? MalwareFamily { get; init; }
    public int? Confidence { get; init; }
    public string? FirstSeenAt { get; init; }
    public string? LastSeenAt { get; init; }
    public string? ExpiresAt { get; init; }
    public string? ReferenceUrl { get; init; }
}

public sealed record IntelligenceImportResult(
    int ReportsProcessed,
    int IndicatorsProcessed,
    int CveRelationshipsProcessed);


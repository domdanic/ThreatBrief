namespace ThreatBrief.Core.Models;

public sealed record ThreatEnrichment
{
    public required string Id { get; init; }
    public string? Severity { get; init; }
    public double? Cvss { get; init; }
    public string? CvssVector { get; init; }
    public string? AttackVector { get; init; }
    public string? AttackComplexity { get; init; }
    public string? PrivilegesRequired { get; init; }
    public string? UserInteraction { get; init; }
    public string? Published { get; init; }
    public string? LastModified { get; init; }
    public string? Status { get; init; }
    public IReadOnlyList<string> Cwes { get; init; } = [];
    public IReadOnlyList<string> References { get; init; } = [];
    public IReadOnlyList<string> AffectedProducts { get; init; } = [];
}


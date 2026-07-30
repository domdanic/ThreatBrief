using System.Text.Json.Serialization;

namespace ThreatBrief.Core.Models;

public sealed record ThreatRecord
{
    public int SchemaVersion { get; init; } = 1;
    public required string Id { get; init; }
    public string? Title { get; init; }
    public string? Vendor { get; init; }
    public string? Product { get; init; }
    public string? Severity { get; init; }
    public double? Cvss { get; init; }
    public string? Published { get; init; }
    public string? DateAdded { get; init; }
    public string? DueDate { get; init; }
    public bool KnownExploited { get; init; }
    public bool RansomwareAssociated { get; init; }
    public string? RansomwareStatus { get; init; }
    public string? Description { get; init; }
    public string? RecommendedAction { get; init; }
    public string? Notes { get; init; }
    public IReadOnlyList<string> Cwes { get; init; } = [];
    public string? Source { get; init; }
    public string? SourceUrl { get; init; }
    public string? NvdStatus { get; init; }
    public string? CvssVector { get; init; }
    public string? AttackVector { get; init; }
    public string? AttackComplexity { get; init; }
    public string? PrivilegesRequired { get; init; }
    public string? UserInteraction { get; init; }
    public string? NvdLastModified { get; init; }
    public string? NvdEnrichedAt { get; init; }
    public IReadOnlyList<string> NvdReferences { get; init; } = [];
    public IReadOnlyList<string> AffectedProducts { get; init; } = [];
    public string TriageStatus { get; init; } = "Backlog";
    public int SourceCount { get; init; } = 1;
    public IReadOnlyList<string> Sources { get; init; } = [];

    [JsonIgnore]
    public bool IsRead { get; init; }

    [JsonIgnore]
    public bool IsSaved { get; init; }

    [JsonIgnore]
    public string? FirstSeenAt { get; init; }

    [JsonIgnore]
    public string? LastSeenAt { get; init; }

    [JsonIgnore]
    public string? LastChangedAt { get; init; }
}

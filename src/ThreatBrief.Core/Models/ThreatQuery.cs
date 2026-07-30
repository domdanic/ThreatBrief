namespace ThreatBrief.Core.Models;

public sealed record ThreatQuery
{
    public string? SearchText { get; init; }
    public string? Vendor { get; init; }
    public bool UnreadOnly { get; init; }
    public bool SavedOnly { get; init; }
    public int? AddedWithinDays { get; init; }
    public int Limit { get; init; } = 100;
}


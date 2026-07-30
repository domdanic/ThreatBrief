using ThreatBrief.Core.Models;
using ThreatBrief.Core.Watchlist;
using ThreatBrief.Core.Priority;

namespace ThreatBrief.Desktop;

public sealed record ThreatListItem(ThreatRecord Record, WatchlistSettings Watchlist)
{
    public string Id => Record.Id;
    public string? Title => Record.Title;
    public string? DateAdded => Record.DateAdded;
    public string VendorProduct => $"{Record.Vendor} / {Record.Product}";
    public string SeverityLabel => Record.Cvss is null
        ? Record.Severity ?? "Not scored"
        : $"{Record.Severity ?? "CVSS"} {Record.Cvss:0.0}";
    public IReadOnlyList<string> WatchlistMatches => Watchlist.Match(Record);
    public int RelevanceScore => WatchlistMatches.Count;
    public string RelevanceLabel => WatchlistMatches.Count == 0
        ? string.Empty
        : $"WATCHLIST {RelevanceScore}: {string.Join(", ", WatchlistMatches)}";
    public ThreatPriority Priority => ThreatPriorityScorer.Score(Record, Watchlist);
    public string PriorityLabel => $"{Priority.Tier} {Priority.Score}";
    public string SourceLabel => $"{Record.SourceCount} source{(Record.SourceCount == 1 ? string.Empty : "s")}";
}

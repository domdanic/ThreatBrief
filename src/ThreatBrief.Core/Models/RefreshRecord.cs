namespace ThreatBrief.Core.Models;

public sealed record RefreshRecord(
    long Id,
    string Collector,
    string RefreshedAt,
    int TotalRecords,
    int AddedRecords,
    int UpdatedRecords);


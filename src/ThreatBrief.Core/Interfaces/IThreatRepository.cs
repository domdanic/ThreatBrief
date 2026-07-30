using ThreatBrief.Core.Models;

namespace ThreatBrief.Core.Interfaces;

public interface IThreatRepository
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
    Task<ImportResult> ImportAsync(
        IReadOnlyCollection<ThreatRecord> records,
        string collector,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatRecord>> QueryAsync(
        ThreatQuery query,
        CancellationToken cancellationToken = default);
    Task<ThreatRecord?> GetAsync(string id, CancellationToken cancellationToken = default);
    Task SetReadAsync(string id, bool isRead, CancellationToken cancellationToken = default);
    Task SetSavedAsync(string id, bool isSaved, CancellationToken cancellationToken = default);
    Task SetTriageStatusAsync(
        string id,
        string status,
        CancellationToken cancellationToken = default);
    Task SetTriageStatusesAsync(
        IReadOnlyCollection<string> ids,
        string status,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatSourceObservation>> GetSourcesAsync(
        string id,
        CancellationToken cancellationToken = default);
    Task SetAllReadAsync(CancellationToken cancellationToken = default);
    Task<int> CountUnreadAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<string>> GetEnrichmentCandidatesAsync(
        int addedWithinDays,
        int limit,
        int cacheHours,
        CancellationToken cancellationToken = default);
    Task ApplyEnrichmentAsync(
        IReadOnlyCollection<ThreatEnrichment> enrichments,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<RefreshRecord>> GetRefreshHistoryAsync(
        int limit = 20,
        CancellationToken cancellationToken = default);
}

using ThreatBrief.Core.Intelligence;

namespace ThreatBrief.Core.Interfaces;

public interface IIntelligenceRepository
{
    Task<IntelligenceImportResult> ImportIntelligenceAsync(
        IntelligenceBatch batch,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<IntelligenceReport>> QueryReportsAsync(
        string? search = null,
        int limit = 250,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatIndicator>> QueryIndicatorsAsync(
        string? search = null,
        bool activeOnly = true,
        int limit = 500,
        CancellationToken cancellationToken = default);
    Task ExpireIndicatorsAsync(
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default);
}

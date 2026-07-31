using ThreatBrief.Core.AI;

namespace ThreatBrief.Core.Interfaces;

public interface IAiAnalysisRepository
{
    Task<StoredThreatAnalysis?> GetLatestAsync(
        string threatId,
        CancellationToken cancellationToken = default);

    Task SaveAsync(
        StoredThreatAnalysis analysis,
        CancellationToken cancellationToken = default);
}

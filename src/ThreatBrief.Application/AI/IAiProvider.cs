using ThreatBrief.Core.AI;
using ThreatBrief.Core.Models;

namespace ThreatBrief.Application.AI;

public interface IAiProvider
{
    string Name { get; }

    Task<string> TestConnectionAsync(CancellationToken cancellationToken = default);

    Task<ThreatAnalysis> AnalyzeThreatAsync(
        ThreatRecord threat,
        IReadOnlyList<string> watchlistMatches,
        CancellationToken cancellationToken = default);
}

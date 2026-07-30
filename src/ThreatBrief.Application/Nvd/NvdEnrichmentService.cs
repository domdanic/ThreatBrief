using ThreatBrief.Core.Interfaces;

namespace ThreatBrief.Application.Nvd;

public sealed class NvdEnrichmentService(
    IThreatRepository repository,
    NvdClient? client = null)
{
    private readonly NvdClient _client = client ?? new NvdClient();

    public async Task<int> EnrichRecentAsync(
        int days = 30,
        CancellationToken cancellationToken = default)
    {
        var ids = await repository.GetEnrichmentCandidatesAsync(
            days,
            limit: 100,
            cacheHours: 24,
            cancellationToken);
        return await EnrichAsync(ids, cancellationToken);
    }

    public async Task<int> EnrichAsync(
        IReadOnlyCollection<string> ids,
        CancellationToken cancellationToken = default)
    {
        if (ids.Count == 0)
        {
            return 0;
        }

        var enrichments = await _client.GetAsync(ids, cancellationToken);
        await repository.ApplyEnrichmentAsync(enrichments, cancellationToken);
        return enrichments.Count;
    }
}


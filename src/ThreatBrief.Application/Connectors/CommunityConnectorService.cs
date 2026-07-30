using ThreatBrief.Core.Configuration;
using ThreatBrief.Core.Interfaces;
using ThreatBrief.Core.Watchlist;

namespace ThreatBrief.Application.Connectors;

public sealed record ConnectorRefreshResult(
    string Source,
    bool Enabled,
    bool Succeeded,
    int Reports,
    int Indicators,
    string? Message);

public sealed class CommunityConnectorService(
    IIntelligenceRepository repository,
    string dataRoot)
{
    public async Task<IReadOnlyList<ConnectorRefreshResult>> RefreshAsync(
        CancellationToken cancellationToken = default)
    {
        var settings = await WatchlistSettings.LoadOrCreateAsync(dataRoot, cancellationToken);
        var secrets = await SecretSettings.LoadAsync(dataRoot, cancellationToken);
        var results = new List<ConnectorRefreshResult>();

        if (settings.Connectors.OtxEnabled)
        {
            results.Add(await RunAsync(
                "AlienVault OTX",
                async () => await new OtxConnector(secrets.OtxApiKey ?? string.Empty)
                    .CollectAsync(settings.Connectors.OtxLookbackDays, cancellationToken),
                cancellationToken));
        }
        else
        {
            results.Add(new ConnectorRefreshResult(
                "AlienVault OTX", false, false, 0, 0, "Disabled"));
        }

        if (settings.Connectors.ThreatFoxEnabled)
        {
            results.Add(await RunAsync(
                "abuse.ch ThreatFox",
                async () => await new ThreatFoxConnector(secrets.AbuseChAuthKey ?? string.Empty)
                    .CollectAsync(settings.Connectors.ThreatFoxLookbackDays, cancellationToken),
                cancellationToken));
        }
        else
        {
            results.Add(new ConnectorRefreshResult(
                "abuse.ch ThreatFox", false, false, 0, 0, "Disabled"));
        }

        return results;
    }

    private async Task<ConnectorRefreshResult> RunAsync(
        string source,
        Func<Task<Core.Intelligence.IntelligenceBatch>> collect,
        CancellationToken cancellationToken)
    {
        try
        {
            var batch = await collect();
            var imported = await repository.ImportIntelligenceAsync(batch, cancellationToken);
            return new ConnectorRefreshResult(
                source,
                true,
                true,
                imported.ReportsProcessed,
                imported.IndicatorsProcessed,
                null);
        }
        catch (Exception exception) when (
            exception is HttpRequestException
                or InvalidDataException
                or InvalidOperationException
                or TaskCanceledException)
        {
            return new ConnectorRefreshResult(
                source, true, false, 0, 0, exception.Message);
        }
    }
}

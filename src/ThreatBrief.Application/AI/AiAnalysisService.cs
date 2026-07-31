using System.Security.Cryptography;
using System.Text;
using ThreatBrief.Core.AI;
using ThreatBrief.Core.Configuration;
using ThreatBrief.Core.Interfaces;
using ThreatBrief.Core.Models;

namespace ThreatBrief.Application.AI;

public sealed class AiAnalysisService(
    IAiAnalysisRepository repository,
    AiSettings settings,
    SecretSettings secrets,
    HttpClient? httpClient = null)
{
    public IAiProvider CreateProvider()
    {
        if (!settings.Enabled || settings.Provider == AiProviders.None)
        {
            throw new InvalidOperationException("AI assistance is disabled.");
        }

        if (!settings.DataSharingConsent)
        {
            throw new InvalidOperationException(
                "Explicit consent is required before threat data is sent to an AI endpoint.");
        }

        if (string.IsNullOrWhiteSpace(settings.Endpoint)
            || string.IsNullOrWhiteSpace(settings.Model))
        {
            throw new InvalidOperationException("AI endpoint and model are required.");
        }

        return settings.Provider switch
        {
            AiProviders.OpenAiCompatible => new OpenAiCompatibleProvider(
                settings.Endpoint,
                settings.Model,
                secrets.AiApiKey,
                httpClient,
                settings.RequestTimeoutSeconds),
            AiProviders.Ollama => new OllamaProvider(
                settings.Endpoint,
                settings.Model,
                httpClient,
                settings.OllamaRequestTimeoutSeconds),
            _ => throw new InvalidOperationException(
                $"Unsupported AI provider '{settings.Provider}'.")
        };
    }

    public async Task<StoredThreatAnalysis> AnalyzeAsync(
        ThreatRecord threat,
        IReadOnlyList<string> watchlistMatches,
        bool forceRefresh = false,
        CancellationToken cancellationToken = default)
    {
        var provider = CreateProvider();
        var fingerprint = CreateFingerprint(threat, watchlistMatches, provider.Name, settings.Model);
        var existing = await repository.GetLatestAsync(threat.Id, cancellationToken);
        if (!forceRefresh
            && existing is not null
            && existing.InputFingerprint == fingerprint)
        {
            return existing;
        }

        var analysis = await provider.AnalyzeThreatAsync(
            threat,
            watchlistMatches,
            cancellationToken);
        var stored = new StoredThreatAnalysis
        {
            ThreatId = threat.Id,
            InputFingerprint = fingerprint,
            Provider = provider.Name,
            Model = settings.Model,
            GeneratedAt = DateTimeOffset.UtcNow.ToString("O"),
            Analysis = analysis
        };
        await repository.SaveAsync(stored, cancellationToken);
        return stored;
    }

    private static string CreateFingerprint(
        ThreatRecord threat,
        IReadOnlyList<string> watchlistMatches,
        string provider,
        string model)
    {
        var material = string.Join(
            "\n",
            threat.Id,
            threat.Title,
            threat.Description,
            threat.RecommendedAction,
            threat.Cvss,
            threat.Severity,
            threat.LastChangedAt,
            provider,
            model,
            string.Join("|", watchlistMatches));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }
}

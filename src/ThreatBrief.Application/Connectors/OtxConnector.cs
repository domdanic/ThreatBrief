using System.Net.Http.Headers;
using System.Text.Json;
using ThreatBrief.Core.Intelligence;

namespace ThreatBrief.Application.Connectors;

public sealed class OtxConnector(string apiKey, HttpClient? httpClient = null)
{
    private readonly HttpClient _httpClient = httpClient ?? new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(60)
    };

    public async Task<IntelligenceBatch> CollectAsync(
        int lookbackDays,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new InvalidOperationException("OTX is enabled but no API key is configured.");
        }

        var since = DateTimeOffset.UtcNow
            .AddDays(-Math.Clamp(lookbackDays, 1, 90))
            .ToString("O");
        string? next =
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since=" +
            Uri.EscapeDataString(since);
        var reports = new List<IntelligenceReportInput>();
        var pages = 0;

        while (!string.IsNullOrWhiteSpace(next) && pages++ < 10)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, next);
            request.Headers.Add("X-OTX-API-KEY", apiKey);
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("ThreatBrief", "1.0"));
            using var response = await _httpClient.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

            if (document.RootElement.TryGetProperty("results", out var results))
            {
                foreach (var pulse in results.EnumerateArray())
                {
                    reports.Add(ParsePulse(pulse));
                }
            }

            next = GetString(document.RootElement, "next");
        }

        return new IntelligenceBatch { Source = "AlienVault OTX", Reports = reports };
    }

    private static IntelligenceReportInput ParsePulse(JsonElement pulse)
    {
        var id = GetString(pulse, "id")
            ?? throw new InvalidDataException("OTX returned a pulse without an ID.");
        var cves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var indicators = new List<IndicatorInput>();

        if (pulse.TryGetProperty("indicators", out var indicatorArray))
        {
            foreach (var indicator in indicatorArray.EnumerateArray())
            {
                var type = GetString(indicator, "type");
                var value = GetString(indicator, "indicator");
                if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                if (string.Equals(type, "CVE", StringComparison.OrdinalIgnoreCase))
                {
                    cves.Add(value.ToUpperInvariant());
                    continue;
                }

                var normalizedType = MapType(type);
                if (normalizedType is null)
                {
                    continue;
                }

                indicators.Add(new IndicatorInput
                {
                    Type = normalizedType,
                    Value = value,
                    FirstSeenAt = GetString(indicator, "created"),
                    ReferenceUrl = $"https://otx.alienvault.com/indicator/{Uri.EscapeDataString(type)}/{Uri.EscapeDataString(value)}"
                });
            }
        }

        if (pulse.TryGetProperty("references", out var references)
            && references.ValueKind == JsonValueKind.Array)
        {
            foreach (var reference in references.EnumerateArray())
            {
                if (reference.ValueKind == JsonValueKind.String)
                {
                    ExtractCves(reference.GetString(), cves);
                }
            }
        }

        ExtractCves(GetString(pulse, "description"), cves);
        return new IntelligenceReportInput
        {
            ExternalId = id,
            Title = GetString(pulse, "name") ?? $"OTX pulse {id}",
            Description = GetString(pulse, "description"),
            Author = GetString(pulse, "author_name"),
            PublishedAt = GetString(pulse, "created"),
            ModifiedAt = GetString(pulse, "modified"),
            SourceUrl = $"https://otx.alienvault.com/pulse/{id}",
            CveIds = cves.ToArray(),
            Indicators = indicators
        };
    }

    private static string? MapType(string type) =>
        type.ToLowerInvariant() switch
        {
            "ipv4" => "ipv4",
            "ipv6" => "ipv6",
            "domain" or "hostname" => "domain",
            "url" or "uri" => "url",
            "filehash-md5" => "md5",
            "filehash-sha1" => "sha1",
            "filehash-sha256" => "sha256",
            _ => null
        };

    private static void ExtractCves(string? text, ISet<string> results)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        foreach (System.Text.RegularExpressions.Match match in
                 System.Text.RegularExpressions.Regex.Matches(
                     text,
                     "CVE-\\d{4}-\\d{4,}",
                     System.Text.RegularExpressions.RegexOptions.IgnoreCase
                     | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        {
            results.Add(match.Value.ToUpperInvariant());
        }
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}


using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ThreatBrief.Core.Intelligence;

namespace ThreatBrief.Application.Connectors;

public sealed class ThreatFoxConnector(string authKey, HttpClient? httpClient = null)
{
    private readonly HttpClient _httpClient = httpClient ?? new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(60)
    };

    public async Task<IntelligenceBatch> CollectAsync(
        int lookbackDays,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(authKey))
        {
            throw new InvalidOperationException(
                "ThreatFox is enabled but no abuse.ch Auth-Key is configured.");
        }

        var body = JsonSerializer.Serialize(new
        {
            query = "get_iocs",
            days = Math.Clamp(lookbackDays, 1, 7)
        });
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "https://threatfox-api.abuse.ch/api/v1/");
        request.Headers.Add("Auth-Key", authKey);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("ThreatBrief", "1.0"));
        request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

        var root = document.RootElement;
        var status = GetString(root, "query_status");
        if (!string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"ThreatFox returned query status '{status ?? "unknown"}'.");
        }

        var indicators = new List<IndicatorInput>();
        if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in data.EnumerateArray())
            {
                var value = GetString(item, "ioc");
                var type = MapType(GetString(item, "ioc_type"));
                if (string.IsNullOrWhiteSpace(value) || type is null)
                {
                    continue;
                }

                var firstSeen = GetString(item, "first_seen");
                var expiresAt = DateTimeOffset.TryParse(firstSeen, out var firstSeenDate)
                    ? firstSeenDate.AddMonths(6).ToString("O")
                    : null;
                indicators.Add(new IndicatorInput
                {
                    Type = type,
                    Value = value,
                    ThreatType = GetString(item, "threat_type"),
                    MalwareFamily =
                        GetString(item, "malware_printable") ?? GetString(item, "malware"),
                    Confidence = GetInt(item, "confidence_level"),
                    FirstSeenAt = firstSeen,
                    LastSeenAt = GetString(item, "last_seen"),
                    ExpiresAt = expiresAt,
                    ReferenceUrl = GetString(item, "reference")
                        ?? (GetString(item, "id") is { } id
                            ? $"https://threatfox.abuse.ch/ioc/{id}/"
                            : "https://threatfox.abuse.ch/")
                });
            }
        }

        return new IntelligenceBatch { Source = "abuse.ch ThreatFox", Indicators = indicators };
    }

    private static string? MapType(string? type) =>
        type?.ToLowerInvariant() switch
        {
            "domain" or "hostname" => "domain",
            "ip:port" => "ip:port",
            "url" => "url",
            "md5_hash" => "md5",
            "sha1_hash" => "sha1",
            "sha256_hash" => "sha256",
            _ => null
        };

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int? GetInt(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.Number
        && value.TryGetInt32(out var result)
            ? result
            : null;
}


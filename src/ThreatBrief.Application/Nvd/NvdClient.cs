using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;
using ThreatBrief.Core.Models;

namespace ThreatBrief.Application.Nvd;

public sealed class NvdClient(HttpClient? httpClient = null)
{
    private readonly HttpClient _httpClient = httpClient ?? new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(45)
    };

    public async Task<IReadOnlyList<ThreatEnrichment>> GetAsync(
        IReadOnlyCollection<string> cveIds,
        CancellationToken cancellationToken = default)
    {
        if (cveIds.Count == 0)
        {
            return [];
        }

        if (cveIds.Count > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(cveIds),
                "NVD accepts at most 100 CVE IDs per request.");
        }

        var joinedIds = string.Join(
            ",",
            cveIds.Distinct(StringComparer.OrdinalIgnoreCase));
        var uri =
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=" +
            Uri.EscapeDataString(joinedIds) +
            "&noRejected";
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("ThreatBrief", "0.1"));
        var apiKey = Environment.GetEnvironmentVariable("NVD_API_KEY");
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            request.Headers.Add("apiKey", apiKey);
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var message = response.Headers.TryGetValues("message", out var values)
                ? string.Join("; ", values)
                : response.ReasonPhrase;
            throw new HttpRequestException(
                $"NVD returned {(int)response.StatusCode}: {message}");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var results = new List<ThreatEnrichment>();
        if (!document.RootElement.TryGetProperty("vulnerabilities", out var vulnerabilities))
        {
            return results;
        }

        foreach (var wrapper in vulnerabilities.EnumerateArray())
        {
            if (!wrapper.TryGetProperty("cve", out var cve))
            {
                continue;
            }

            var metric = FindPreferredMetric(cve);
            results.Add(new ThreatEnrichment
            {
                Id = GetString(cve, "id") ?? throw new InvalidDataException("NVD returned a CVE without an ID."),
                Severity = metric is null ? null : GetString(metric.Value, "baseSeverity"),
                Cvss = metric is null ? null : GetDouble(metric.Value, "baseScore"),
                CvssVector = metric is null ? null : GetString(metric.Value, "vectorString"),
                AttackVector = metric is null ? null : GetString(metric.Value, "attackVector"),
                AttackComplexity = metric is null ? null : GetString(metric.Value, "attackComplexity"),
                PrivilegesRequired = metric is null ? null : GetString(metric.Value, "privilegesRequired"),
                UserInteraction = metric is null ? null : GetString(metric.Value, "userInteraction"),
                Published = GetString(cve, "published"),
                LastModified = GetString(cve, "lastModified"),
                Status = GetString(cve, "vulnStatus"),
                Cwes = ReadCwes(cve),
                References = ReadReferences(cve),
                AffectedProducts = ReadAffectedProducts(cve)
            });
        }

        return results;
    }

    private static JsonElement? FindPreferredMetric(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metrics))
        {
            return null;
        }

        foreach (var metricName in new[]
                 {
                     "cvssMetricV40",
                     "cvssMetricV31",
                     "cvssMetricV30",
                     "cvssMetricV2"
                 })
        {
            if (!metrics.TryGetProperty(metricName, out var metricArray)
                || metricArray.GetArrayLength() == 0)
            {
                continue;
            }

            var first = metricArray[0];
            if (first.TryGetProperty("cvssData", out var cvssData))
            {
                return cvssData;
            }
        }

        return null;
    }

    private static IReadOnlyList<string> ReadCwes(JsonElement cve)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (cve.TryGetProperty("weaknesses", out var weaknesses))
        {
            foreach (var weakness in weaknesses.EnumerateArray())
            {
                if (!weakness.TryGetProperty("description", out var descriptions))
                {
                    continue;
                }

                foreach (var description in descriptions.EnumerateArray())
                {
                    var value = GetString(description, "value");
                    if (!string.IsNullOrWhiteSpace(value) && value.StartsWith("CWE-", StringComparison.OrdinalIgnoreCase))
                    {
                        values.Add(value);
                    }
                }
            }
        }

        return values.ToArray();
    }

    private static IReadOnlyList<string> ReadReferences(JsonElement cve)
    {
        if (!cve.TryGetProperty("references", out var references))
        {
            return [];
        }

        return references.EnumerateArray()
            .Select(reference => GetString(reference, "url"))
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(25)
            .ToArray();
    }

    private static IReadOnlyList<string> ReadAffectedProducts(JsonElement cve)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!cve.TryGetProperty("configurations", out var configurations))
        {
            return values.ToArray();
        }

        foreach (var configuration in configurations.EnumerateArray())
        {
            ReadCpeMatches(configuration, values);
        }

        return values.Take(100).ToArray();
    }

    private static void ReadCpeMatches(JsonElement element, ISet<string> values)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            if (element.TryGetProperty("cpeMatch", out var matches))
            {
                foreach (var match in matches.EnumerateArray())
                {
                    var criteria = GetString(match, "criteria");
                    if (!string.IsNullOrWhiteSpace(criteria))
                    {
                        values.Add(criteria);
                    }
                }
            }

            foreach (var property in element.EnumerateObject())
            {
                if (property.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                {
                    ReadCpeMatches(property.Value, values);
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in element.EnumerateArray())
            {
                ReadCpeMatches(child, values);
            }
        }
    }

    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static double? GetDouble(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var number))
        {
            return number;
        }

        return value.ValueKind == JsonValueKind.String
               && double.TryParse(
                   value.GetString(),
                   NumberStyles.Float,
                   CultureInfo.InvariantCulture,
                   out number)
            ? number
            : null;
    }
}


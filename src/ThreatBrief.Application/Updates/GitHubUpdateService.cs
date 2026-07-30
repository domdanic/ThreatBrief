using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;

namespace ThreatBrief.Application.Updates;

public sealed record UpdateCheckResult(
    bool Configured,
    bool UpdateAvailable,
    Version CurrentVersion,
    Version? LatestVersion,
    string? ReleaseName,
    string? ReleaseUrl,
    string? DownloadUrl,
    string Message);

public sealed class GitHubUpdateService(HttpClient? httpClient = null)
{
    private readonly HttpClient _httpClient = httpClient ?? new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public async Task<UpdateCheckResult> CheckAsync(
        string? repository,
        string channel,
        CancellationToken cancellationToken = default)
    {
        var current = Assembly.GetEntryAssembly()?.GetName().Version ?? new Version(0, 0, 0);
        if (string.IsNullOrWhiteSpace(repository)
            || repository.Split('/', StringSplitOptions.RemoveEmptyEntries).Length != 2)
        {
            return new UpdateCheckResult(
                false, false, current, null, null, null, null,
                "Set the GitHub repository as owner/repository after publication.");
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://api.github.com/repos/{repository.Trim()}/releases/latest");
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("ThreatBrief", current.ToString()));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return new UpdateCheckResult(
                true, false, current, null, null, null, null,
                $"GitHub update check returned {(int)response.StatusCode}.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var root = document.RootElement;
        var tag = GetString(root, "tag_name")?.TrimStart('v', 'V');
        if (!Version.TryParse(tag, out var latest))
        {
            return new UpdateCheckResult(
                true, false, current, null, null, null, null,
                $"Release tag '{tag}' is not a semantic version.");
        }

        var isAi = string.Equals(channel, "ai", StringComparison.OrdinalIgnoreCase);
        string? downloadUrl = null;
        if (root.TryGetProperty("assets", out var assets))
        {
            foreach (var asset in assets.EnumerateArray())
            {
                var name = GetString(asset, "name") ?? string.Empty;
                var aiAsset = name.Contains("ai", StringComparison.OrdinalIgnoreCase);
                if (name.Contains("win-x64", StringComparison.OrdinalIgnoreCase) && aiAsset == isAi)
                {
                    downloadUrl = GetString(asset, "browser_download_url");
                    break;
                }
            }
        }

        var available = latest > current;
        return new UpdateCheckResult(
            true,
            available,
            current,
            latest,
            GetString(root, "name"),
            GetString(root, "html_url"),
            downloadUrl,
            available
                ? $"ThreatBrief {latest} is available."
                : $"ThreatBrief {current} is current.");
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}

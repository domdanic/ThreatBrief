using System.Text.Json;
using ThreatBrief.Core.AI;

namespace ThreatBrief.Core.Watchlist;

public sealed record WatchlistSettings
{
    public int AlertWindowDays { get; init; } = 30;
    public ConnectorSettings Connectors { get; init; } = new();
    public UpdateSettings Updates { get; init; } = new();
    public AiSettings Ai { get; init; } = new();

    public IReadOnlyList<string> Terms { get; init; } =
    [
        "Microsoft",
        "Windows",
        "Microsoft 365",
        "Cisco",
        "Fortinet",
        "VMware",
        "Adobe",
        "Chrome",
        "Exchange",
        "Hyper-V"
    ];

    public static async Task<WatchlistSettings> LoadOrCreateAsync(
        string dataRoot,
        CancellationToken cancellationToken = default)
    {
        var configDirectory = Path.Combine(dataRoot, "config");
        var path = Path.Combine(configDirectory, "watchlist.json");
        Directory.CreateDirectory(configDirectory);

        if (!File.Exists(path))
        {
            var defaults = new WatchlistSettings();
            await File.WriteAllTextAsync(
                path,
                JsonSerializer.Serialize(defaults, new JsonSerializerOptions { WriteIndented = true }),
                cancellationToken);
            return defaults;
        }

        var json = await File.ReadAllTextAsync(path, cancellationToken);
        return JsonSerializer.Deserialize<WatchlistSettings>(
                   json,
                   new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
               ?? new WatchlistSettings();
    }

    public IReadOnlyList<string> Match(Models.ThreatRecord record)
    {
        var text = string.Join(
            "\n",
            record.Vendor,
            record.Product,
            record.Title,
            record.Description,
            string.Join("\n", record.AffectedProducts));
        return Terms
            .Where(term => !string.IsNullOrWhiteSpace(term)
                && text.Contains(term, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

public sealed record ConnectorSettings
{
    public bool OtxEnabled { get; init; }
    public bool ThreatFoxEnabled { get; init; }
    public int OtxLookbackDays { get; init; } = 7;
    public int ThreatFoxLookbackDays { get; init; } = 3;
}

public sealed record UpdateSettings
{
    public bool CheckOnStartup { get; init; } = true;
    public string? GitHubRepository { get; init; } = "domdanic/ThreatBrief";
    public string Channel { get; init; } = "stable";
}

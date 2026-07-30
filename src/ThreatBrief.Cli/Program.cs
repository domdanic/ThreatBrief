using System.Text.Json;
using ThreatBrief.Core;
using ThreatBrief.Core.Models;
using ThreatBrief.Data;
using ThreatBrief.Application;
using ThreatBrief.Application.Refresh;
using ThreatBrief.Application.Nvd;
using ThreatBrief.Core.Priority;
using ThreatBrief.Core.Triage;
using ThreatBrief.Core.Watchlist;

return await RunAsync(args);

static async Task<int> RunAsync(string[] args)
{
    try
    {
        var arguments = args.ToList();
        var dataPath = TakeOption(arguments, "--data-path")
            ?? PortableDataPaths.BesideExecutable().Root;
        var paths = PortableDataPaths.At(dataPath);
        paths.EnsureCreated();
        var repository = new SqliteThreatRepository(paths.DatabasePath);
        await repository.InitializeAsync();

        var command = arguments.FirstOrDefault()?.ToLowerInvariant() ?? "help";
        switch (command)
        {
            case "refresh":
            {
                var appRoot = TakeOption(arguments, "--app-root")
                    ?? ThreatBriefRuntime.FindAppRoot();
                var refreshService = new ThreatRefreshService(repository, appRoot, paths.Root);
                var outcome = await refreshService.RefreshAsync();
                Console.WriteLine(JsonSerializer.Serialize(outcome));
                return 0;
            }

            case "enrich":
            {
                var id = arguments.Skip(1).FirstOrDefault()
                    ?? throw new ArgumentException("enrich requires a CVE identifier.");
                var count = await new NvdEnrichmentService(repository).EnrichAsync([id]);
                Console.WriteLine(JsonSerializer.Serialize(new { Enriched = count }));
                return 0;
            }

            case "init":
                Console.WriteLine(paths.DatabasePath);
                return 0;

            case "import":
            {
                var jsonPath = arguments.Skip(1).FirstOrDefault()
                    ?? throw new ArgumentException("import requires a normalized JSON file.");
                var json = await File.ReadAllTextAsync(Path.GetFullPath(jsonPath));
                var records = JsonSerializer.Deserialize<List<ThreatRecord>>(
                    json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                    ?? throw new InvalidDataException("The normalized JSON file contained no records.");
                var result = await repository.ImportAsync(records, "CISA KEV");
                Console.WriteLine(JsonSerializer.Serialize(result));
                return 0;
            }

            case "list":
            {
                var query = new ThreatQuery
                {
                    SearchText = TakeOption(arguments, "--search"),
                    Vendor = TakeOption(arguments, "--vendor"),
                    UnreadOnly = TakeFlag(arguments, "--unread"),
                    SavedOnly = TakeFlag(arguments, "--saved"),
                    AddedWithinDays = ParseInt(TakeOption(arguments, "--days")),
                    Limit = ParseInt(TakeOption(arguments, "--limit")) ?? 100
                };
                var records = await repository.QueryAsync(query);
                Console.WriteLine(JsonSerializer.Serialize(records, new JsonSerializerOptions
                {
                    WriteIndented = true
                }));
                return 0;
            }

            case "show":
            {
                var id = arguments.Skip(1).FirstOrDefault()
                    ?? throw new ArgumentException("show requires a CVE identifier.");
                var record = await repository.GetAsync(id);
                Console.WriteLine(JsonSerializer.Serialize(record, new JsonSerializerOptions
                {
                    WriteIndented = true
                }));
                return record is null ? 2 : 0;
            }

            case "read":
            case "unread":
            {
                var id = arguments.Skip(1).FirstOrDefault()
                    ?? throw new ArgumentException($"{command} requires a CVE identifier.");
                await repository.SetReadAsync(id, command == "read");
                return 0;
            }

            case "save":
            case "unsave":
            {
                var id = arguments.Skip(1).FirstOrDefault()
                    ?? throw new ArgumentException($"{command} requires a CVE identifier.");
                await repository.SetSavedAsync(id, command == "save");
                return 0;
            }

            case "stats":
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    Database = paths.DatabasePath,
                    Unread = await repository.CountUnreadAsync()
                }));
                return 0;

            case "alerts":
            {
                var watchlist = await WatchlistSettings.LoadOrCreateAsync(paths.Root);
                var records = await repository.QueryAsync(new ThreatQuery { Limit = 5000 });
                var alerting = records.Where(record =>
                    AlertPolicy.IsAlerting(record, watchlist.AlertWindowDays)).ToArray();
                var today = DateOnly.FromDateTime(DateTime.UtcNow);
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    AlertWindowDays = watchlist.AlertWindowDays,
                    Alerting = alerting.Length,
                    Critical = alerting.Count(record =>
                        ThreatPriorityScorer.Score(record, watchlist).Tier == "CRITICAL"),
                    Watchlist = alerting.Count(record => watchlist.Match(record).Count > 0),
                    DueSoon = records.Count(record =>
                        TriageStates.IsActive(record.TriageStatus)
                        && DateOnly.TryParse(record.DueDate, out var due)
                        && due >= today
                        && due <= today.AddDays(7)),
                    Overdue = records.Count(record =>
                        TriageStates.IsActive(record.TriageStatus)
                        && DateOnly.TryParse(record.DueDate, out var due)
                        && due < today)
                }));
                return 0;
            }

            case "read-all":
                await repository.SetAllReadAsync();
                return 0;

            default:
                Console.WriteLine(
                    """
                    ThreatBrief CLI
                      refresh [--app-root <directory>]
                      enrich <CVE-ID>
                      init
                      import <normalized-json>
                      list [--days N] [--search TEXT] [--vendor NAME] [--unread] [--saved] [--limit N]
                      show <CVE-ID>
                      read|unread <CVE-ID>
                      save|unsave <CVE-ID>
                      stats
                      alerts
                      read-all

                    All commands accept: --data-path <directory>
                    """);
                return command == "help" ? 0 : 1;
        }
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine(exception.Message);
        return 1;
    }
}

static string? TakeOption(List<string> arguments, string name)
{
    var index = arguments.FindIndex(value => string.Equals(value, name, StringComparison.OrdinalIgnoreCase));
    if (index < 0)
    {
        return null;
    }

    if (index + 1 >= arguments.Count)
    {
        throw new ArgumentException($"{name} requires a value.");
    }

    var value = arguments[index + 1];
    arguments.RemoveRange(index, 2);
    return value;
}

static bool TakeFlag(List<string> arguments, string name)
{
    var index = arguments.FindIndex(value => string.Equals(value, name, StringComparison.OrdinalIgnoreCase));
    if (index < 0)
    {
        return false;
    }

    arguments.RemoveAt(index);
    return true;
}

static int? ParseInt(string? value) =>
    value is null ? null : int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);

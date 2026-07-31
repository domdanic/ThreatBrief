using ThreatBrief.Core;
using ThreatBrief.Core.Models;
using ThreatBrief.Data;
using ThreatBrief.Core.Priority;
using ThreatBrief.Core.Watchlist;
using ThreatBrief.Core.Triage;
using ThreatBrief.Application.Connectors;
using ThreatBrief.Application.Maintenance;
using ThreatBrief.Application.AI;
using ThreatBrief.Application.Updates;
using ThreatBrief.Core.AI;
using ThreatBrief.Core.Configuration;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.IO.Compression;

var testRoot = Path.Combine(Path.GetTempPath(), $"ThreatBrief.Data.Tests.{Guid.NewGuid():N}");
var assertions = 0;

try
{
    var paths = PortableDataPaths.At(testRoot);
    paths.EnsureCreated();
    Assert(Directory.Exists(paths.ReportsPath), "Portable report directory should be created");
    Assert(new AiSettings().OllamaRequestTimeoutSeconds == 300,
        "Ollama requests should default to a five-minute timeout");
    var legacyAiSettings = JsonSerializer.Deserialize<AiSettings>(
        """{"Provider":"Ollama","RequestTimeoutSeconds":90}""");
    Assert(legacyAiSettings?.OllamaRequestTimeoutSeconds == 300,
        "Existing settings should inherit the new five-minute Ollama timeout");

    Assert(LocalOllamaLifecycleService.IsLocalEndpoint("http://127.0.0.1:11434"),
        "Ollama lifecycle should accept the IPv4 loopback endpoint");
    Assert(LocalOllamaLifecycleService.IsLocalEndpoint("http://localhost:11434"),
        "Ollama lifecycle should accept localhost");
    Assert(!LocalOllamaLifecycleService.IsLocalEndpoint("http://192.168.1.10:11434"),
        "Ollama lifecycle should reject LAN endpoints");
    Assert(!LocalOllamaLifecycleService.IsLocalEndpoint("https://api.example.com"),
        "Ollama lifecycle should reject remote endpoints");

    var fakeAppRoot = Path.Combine(testRoot, "ThreatBrief");
    var fakeBundleRoot = Path.Combine(testRoot, "PortableOllama");
    Directory.CreateDirectory(Path.Combine(fakeBundleRoot, "bin"));
    Directory.CreateDirectory(fakeAppRoot);
    await File.WriteAllTextAsync(Path.Combine(fakeBundleRoot, "bin", "ollama.exe"), string.Empty);
    Assert(string.Equals(
            LocalOllamaLifecycleService.ResolveBundlePath(
                fakeAppRoot,
                "..\\PortableOllama"),
            fakeBundleRoot,
            StringComparison.OrdinalIgnoreCase),
        "Ollama lifecycle should resolve a portable sibling bundle");
    var fakeInstalledRoot = Path.Combine(testRoot, "InstalledOllama");
    Directory.CreateDirectory(fakeInstalledRoot);
    await File.WriteAllTextAsync(Path.Combine(fakeInstalledRoot, "ollama.exe"), string.Empty);
    Assert(string.Equals(
            LocalOllamaLifecycleService.ResolveBundlePath(
                fakeAppRoot,
                fakeInstalledRoot),
            fakeInstalledRoot,
            StringComparison.OrdinalIgnoreCase),
        "Ollama lifecycle should accept a standard installation folder");

    var integrationBundle = Environment.GetEnvironmentVariable(
        "THREATBRIEF_TEST_OLLAMA_BUNDLE");
    if (!string.IsNullOrWhiteSpace(integrationBundle))
    {
        using var lifecycle = new LocalOllamaLifecycleService();
        var startMessage = await lifecycle.EnsureStartedAsync(
            fakeAppRoot,
            integrationBundle,
            "http://127.0.0.1:11434");
        Assert(startMessage.Contains("started by ThreatBrief", StringComparison.Ordinal),
            "Ollama integration test should start the portable process");
        Assert(lifecycle.OwnsProcess,
            "Ollama integration test should track process ownership");
        using var integrationClient = new HttpClient();
        var tags = await integrationClient.GetStringAsync(
            "http://127.0.0.1:11434/api/tags");
        Assert(tags.Contains("qwen3.5:9b", StringComparison.Ordinal),
            "Ollama integration test should expose the bundled model");
        lifecycle.StopOwnedProcess();
        Assert(!lifecycle.OwnsProcess,
            "Ollama integration test should release the owned process");
    }

    var repository = new SqliteThreatRepository(paths.DatabasePath);
    var first = new ThreatRecord
    {
        Id = "CVE-2026-10001",
        Title = "Initial title",
        Vendor = "Contoso",
        Product = "Widget",
        DateAdded = DateTime.UtcNow.ToString("yyyy-MM-dd"),
        KnownExploited = true,
        Description = "Initial description",
        Cwes = ["CWE-78"],
        Source = "CISA KEV"
    };

    var baseline = await repository.ImportAsync([first], "CISA KEV");
    Assert(baseline.EstablishedBaseline, "First import should establish a baseline");
    Assert(baseline.Added == 1, "Baseline should insert one record");
    Assert(await repository.CountUnreadAsync() == 0, "Baseline records should start read");

    var unchanged = await repository.ImportAsync([first], "CISA KEV");
    Assert(unchanged.Unchanged == 1, "Identical imports should be idempotent");

    var second = first with { Title = "Updated title" };
    var update = await repository.ImportAsync([second], "CISA KEV");
    Assert(update.Updated == 1, "Changed content should update the record");
    Assert(await repository.CountUnreadAsync() == 1, "Updated records should become unread");

    var found = await repository.QueryAsync(new ThreatQuery
    {
        SearchText = "Updated",
        UnreadOnly = true
    });
    Assert(found.Count == 1, "Search and unread filters should find the updated record");
    Assert(found[0].Id == first.Id, "The correct record should be returned");

    var candidates = await repository.GetEnrichmentCandidatesAsync(30, 100, 24);
    Assert(candidates.Count == 1, "A recent unenriched record should be an NVD candidate");
    await repository.ApplyEnrichmentAsync(
    [
        new ThreatEnrichment
        {
            Id = first.Id,
            Severity = "CRITICAL",
            Cvss = 9.8,
            CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            AttackVector = "NETWORK",
            AttackComplexity = "LOW",
            PrivilegesRequired = "NONE",
            UserInteraction = "NONE",
            Published = "2026-07-29T00:00:00.000",
            LastModified = "2026-07-30T00:00:00.000",
            Status = "Analyzed",
            Cwes = ["CWE-78"],
            References = ["https://example.test/advisory"],
            AffectedProducts = ["cpe:2.3:a:contoso:widget:*:*:*:*:*:*:*:*"]
        }
    ]);
    var enriched = await repository.GetAsync(first.Id);
    Assert(enriched?.Cvss == 9.8, "NVD CVSS data should persist");
    Assert(enriched?.AttackVector == "NETWORK", "NVD attack metrics should persist");
    Assert(enriched?.NvdReferences.Count == 1, "NVD references should persist");
    Assert(enriched?.SourceCount == 2, "CISA and NVD should correlate to one canonical threat");
    Assert(
        enriched?.Sources.Contains("CISA KEV") == true
        && enriched.Sources.Contains("NVD"),
        "Correlated source names should remain visible");
    var priority = ThreatPriorityScorer.Score(enriched!, new WatchlistSettings { Terms = ["Contoso"] });
    Assert(priority.Score >= 55, "An exploited watchlist match should receive elevated priority");
    Assert(priority.Reasons.Any(reason => reason.Contains("Watchlist", StringComparison.Ordinal)),
        "Priority should explain its watchlist contribution");
    var policyNow = new DateTimeOffset(2026, 7, 30, 12, 0, 0, TimeSpan.Zero);
    var oldBacklog = first with
    {
        DateAdded = "2021-01-01",
        TriageStatus = TriageStates.Backlog
    };
    Assert(!AlertPolicy.IsAlerting(oldBacklog, 30, policyNow),
        "Old backlog records should fall out of dashboard alerts");
    var recentBacklog = oldBacklog with { DateAdded = "2026-07-29" };
    Assert(AlertPolicy.IsAlerting(recentBacklog, 30, policyNow),
        "Recent backlog records should remain visible during the alert window");
    var handledRecent = recentBacklog with { TriageStatus = TriageStates.Handled };
    Assert(!AlertPolicy.IsAlerting(handledRecent, 30, policyNow),
        "Terminal dispositions should leave dashboard alerts immediately");
    var changedOldRecord = oldBacklog with
    {
        TriageStatus = TriageStates.New,
        LastChangedAt = "2026-07-30T10:00:00Z"
    };
    Assert(AlertPolicy.IsAlerting(changedOldRecord, 30, policyNow),
        "Recently changed old CVEs should re-enter the alert window");
    Assert(
        (await repository.GetEnrichmentCandidatesAsync(30, 100, 24)).Count == 0,
        "Fresh NVD enrichment should be cached");
    var refreshHistory = await repository.GetRefreshHistoryAsync();
    Assert(
        refreshHistory.Any(refresh => refresh.Collector == "CISA KEV"),
        "CISA refresh health should be recorded");
    Assert(
        refreshHistory.Any(refresh => refresh.Collector == "NVD"),
        "NVD enrichment health should be recorded");

    await repository.SetReadAsync(first.Id, true);
    Assert(await repository.CountUnreadAsync() == 0, "Read state should persist");
    await repository.SetSavedAsync(first.Id, true);
    var saved = await repository.QueryAsync(new ThreatQuery { SavedOnly = true });
    Assert(saved.Count == 1 && saved[0].IsSaved, "Saved state should persist");
    await repository.SetTriageStatusAsync(first.Id, "Action Required");
    Assert(
        (await repository.GetAsync(first.Id))?.TriageStatus == "Action Required",
        "Triage state should persist");
    await repository.SetReadAsync(first.Id, false);
    await repository.SetTriageStatusesAsync([first.Id], TriageStates.NotApplicable);
    var disposed = await repository.GetAsync(first.Id);
    Assert(disposed?.TriageStatus == TriageStates.NotApplicable,
        "Bulk disposition should persist");
    Assert(disposed?.IsRead == true,
        "Terminal dispositions should leave records read");
    Assert(!TriageStates.IsActive(disposed?.TriageStatus),
        "Not-applicable records should not remain operationally active");

    var reopened = new SqliteThreatRepository(paths.DatabasePath);
    var persisted = await reopened.GetAsync(first.Id);
    Assert(persisted?.Title == "Updated title", "Data should survive reopening the portable database");

    var intelligence = new SqliteIntelligenceRepository(paths.DatabasePath);
    var otxJson =
        """
        {
          "next": null,
          "results": [{
            "id": "pulse-1",
            "name": "Contoso exploitation",
            "description": "Observed exploitation of CVE-2026-10001.",
            "author_name": "analyst",
            "created": "2026-07-29T00:00:00Z",
            "modified": "2026-07-30T00:00:00Z",
            "references": ["https://example.test/report"],
            "indicators": [
              {"type": "CVE", "indicator": "CVE-2026-10001"},
              {"type": "domain", "indicator": "Evil.Example."}
            ]
          }]
        }
        """;
    var otxClient = new HttpClient(new StubHandler(otxJson));
    var otxBatch = await new OtxConnector("test-key", otxClient).CollectAsync(7);
    var otxImport = await intelligence.ImportIntelligenceAsync(otxBatch);
    Assert(otxImport.ReportsProcessed == 1, "OTX pulses should import as reports");
    Assert(otxImport.CveRelationshipsProcessed == 1, "OTX CVEs should correlate to canonical threats");

    var threatFoxJson =
        """
        {
          "query_status": "ok",
          "data": [{
            "id": "41",
            "ioc": "evil.example",
            "threat_type": "botnet_cc",
            "ioc_type": "domain",
            "malware": "win.example",
            "malware_printable": "Example Malware",
            "confidence_level": 75,
            "first_seen": "2026-07-29T00:00:00Z",
            "last_seen": "2026-07-30T00:00:00Z",
            "reference": "https://example.test/ioc"
          }]
        }
        """;
    var threatFoxClient = new HttpClient(new StubHandler(threatFoxJson));
    var threatFoxBatch = await new ThreatFoxConnector("test-key", threatFoxClient).CollectAsync(3);
    await intelligence.ImportIntelligenceAsync(threatFoxBatch);
    var indicators = await intelligence.QueryIndicatorsAsync();
    Assert(indicators.Count == 1, "Equivalent OTX and ThreatFox domains should deduplicate");
    Assert(indicators[0].NormalizedValue == "evil.example", "Domains should normalize canonically");
    Assert(indicators[0].Sources.Count == 2, "A canonical IOC should retain both source observations");
    var reports = await intelligence.QueryReportsAsync();
    Assert(reports.Count == 1 && reports[0].CveIds.Contains(first.Id),
        "Reports should expose related canonical CVEs");

    var analysisJson =
        """
        {
          "summary": "A known-exploited vulnerability affects the selected product.",
          "organizationalImpact": "Compromise may affect systems matching the local watchlist.",
          "exploitationPath": "The supplied record indicates network-reachable exploitation.",
          "recommendedActions": ["Validate exposure", "Apply vendor remediation"],
          "caveats": ["Confirm the installed product version"],
          "confidence": "High"
        }
        """;
    var openAiResponse = JsonSerializer.Serialize(new
    {
        output = new[]
        {
            new
            {
                content = new[]
                {
                    new { type = "output_text", text = analysisJson }
                }
            }
        }
    });
    var openAiHandler = new StubHandler(openAiResponse);
    var openAiProvider = new OpenAiCompatibleProvider(
        "https://ai.example.test/v1",
        "test-model",
        "test-key",
        new HttpClient(openAiHandler));
    var openAiAnalysis = await openAiProvider.AnalyzeThreatAsync(first, ["Contoso"]);
    Assert(openAiAnalysis.Confidence == "High",
        "OpenAI-compatible structured analysis should deserialize");
    Assert(openAiHandler.LastRequestBody?.Contains("\"store\":false") == true,
        "OpenAI-compatible requests should disable provider storage");
    Assert(openAiHandler.LastRequestBody?.Contains("THREAT_DATA_BEGIN") == true,
        "AI requests should delimit normalized threat data");

    var ollamaResponse = JsonSerializer.Serialize(new
    {
        message = new { content = analysisJson }
    });
    var ollamaHandler = new StubHandler(ollamaResponse);
    var ollamaProvider = new OllamaProvider(
        "http://localhost:11434",
        "local-model",
        new HttpClient(ollamaHandler));
    var ollamaAnalysis = await ollamaProvider.AnalyzeThreatAsync(first, []);
    Assert(ollamaAnalysis.RecommendedActions.Count == 2,
        "Ollama structured analysis should deserialize");
    Assert(ollamaHandler.LastRequestUri?.AbsolutePath == "/api/chat",
        "Ollama analysis should use the configured local chat endpoint");

    var aiRepository = new SqliteAiAnalysisRepository(paths.DatabasePath);
    var disabledAi = new AiAnalysisService(
        aiRepository,
        new AiSettings(),
        new SecretSettings());
    var consentRejected = false;
    try
    {
        disabledAi.CreateProvider();
    }
    catch (InvalidOperationException)
    {
        consentRejected = true;
    }
    Assert(consentRejected, "AI should reject use while disabled or lacking consent");

    var aiSettings = new AiSettings
    {
        Enabled = true,
        DataSharingConsent = true,
        Provider = AiProviders.OpenAiCompatible,
        Endpoint = "https://ai.example.test/v1",
        Model = "test-model"
    };
    var cacheHandler = new StubHandler(openAiResponse);
    var aiService = new AiAnalysisService(
        aiRepository,
        aiSettings,
        new SecretSettings { AiApiKey = "test-key" },
        new HttpClient(cacheHandler));
    var generated = await aiService.AnalyzeAsync(first, ["Contoso"]);
    var cached = await aiService.AnalyzeAsync(first, ["Contoso"]);
    Assert(generated.InputFingerprint == cached.InputFingerprint,
        "Unchanged threat analysis should reuse its fingerprinted cache");
    Assert(cacheHandler.RequestCount == 1,
        "Cached AI analysis should avoid a second provider request");
    Assert((await aiRepository.GetLatestAsync(first.Id))?.Model == "test-model",
        "AI audit history should store the provider model");

    var updateMetadata =
        """
        {
          "tag_name": "v9.9.0",
          "name": "ThreatBrief 9.9.0",
          "html_url": "https://github.com/domdanic/ThreatBrief/releases/tag/v9.9.0",
          "assets": [
            {
              "name": "ThreatBrief-v9.9.0-win-x64.zip",
              "browser_download_url": "https://github.com/download/update.zip"
            },
            {
              "name": "ThreatBrief-v9.9.0-win-x64.zip.sha256",
              "browser_download_url": "https://github.com/download/update.zip.sha256"
            }
          ]
        }
        """;
    var updateCheck = await new GitHubUpdateService(
            new HttpClient(new StubHandler(updateMetadata)))
        .CheckAsync("domdanic/ThreatBrief", "stable");
    Assert(updateCheck.UpdateAvailable,
        "A newer semantic GitHub release should trigger an update");
    Assert(updateCheck.DownloadUrl?.EndsWith("update.zip") == true,
        "Update checks should select the portable ZIP");
    Assert(updateCheck.ChecksumUrl?.EndsWith(".sha256") == true,
        "Update checks should require the matching checksum asset");

    byte[] updateArchive;
    using (var archiveBuffer = new MemoryStream())
    {
        using (var archive = new ZipArchive(archiveBuffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            var executableEntry = archive.CreateEntry(
                "ThreatBrief-v9.9.0-win-x64/ThreatBrief.exe");
            await using (var entryStream = executableEntry.Open())
            {
                await entryStream.WriteAsync("test executable"u8.ToArray());
            }
            var readmeEntry = archive.CreateEntry(
                "ThreatBrief-v9.9.0-win-x64/README.md");
            await using (var entryStream = readmeEntry.Open())
            {
                await entryStream.WriteAsync("test release"u8.ToArray());
            }
        }
        updateArchive = archiveBuffer.ToArray();
    }
    var updateChecksum = Encoding.UTF8.GetBytes(
        $"{Convert.ToHexString(SHA256.HashData(updateArchive))}  update.zip");
    var updateAppRoot = Path.Combine(testRoot, "installed");
    Directory.CreateDirectory(updateAppRoot);
    await File.WriteAllTextAsync(
        Path.Combine(updateAppRoot, "ThreatBrief.exe"),
        "old executable");
    var updateAssets = new UpdateAssetHandler(updateArchive, updateChecksum);
    var preparedUpdate = await new PortableUpdateService(
            updateAppRoot,
            paths.Root,
            new HttpClient(updateAssets))
        .PrepareAsync(updateCheck);
    Assert(File.Exists(Path.Combine(preparedUpdate.PayloadDirectory, "ThreatBrief.exe")),
        "Verified updates should extract a portable executable into staging");
    Assert(File.Exists(preparedUpdate.HelperScriptPath),
        "Update preparation should create an external replacement helper");
    Assert(File.Exists(preparedUpdate.SafetyBackupPath),
        "Update preparation should create a portable safety backup");
    Assert(updateAssets.RequestCount == 2,
        "Update preparation should download exactly the ZIP and checksum");
    var checksumRejected = false;
    try
    {
        await new PortableUpdateService(
                updateAppRoot,
                paths.Root,
                new HttpClient(new UpdateAssetHandler(
                    updateArchive,
                    Encoding.UTF8.GetBytes($"{new string('0', 64)}  update.zip"))))
            .PrepareAsync(updateCheck);
    }
    catch (InvalidDataException)
    {
        checksumRejected = true;
    }
    Assert(checksumRejected,
        "Portable updates should reject a ZIP that does not match its published checksum");

    var configDirectory = Path.Combine(paths.Root, "config");
    Directory.CreateDirectory(configDirectory);
    var configPath = Path.Combine(configDirectory, "watchlist.json");
    var secretPath = Path.Combine(configDirectory, "secrets.local.json");
    await File.WriteAllTextAsync(configPath, """{"marker":"original"}""");
    await File.WriteAllTextAsync(secretPath, """{"otxApiKey":"must-not-back-up"}""");
    var backupService = new PortableBackupService(paths.Root);
    var backupPath = await backupService.CreateBackupAsync();
    using (var backup = ZipFile.OpenRead(backupPath))
    {
        Assert(backup.GetEntry("threatbrief.db") is not null,
            "Backup should include the database");
        Assert(backup.GetEntry("config/watchlist.json") is not null,
            "Backup should include non-secret configuration");
        Assert(backup.GetEntry("config/secrets.local.json") is null,
            "Backup should exclude portable API secrets");
    }

    await File.WriteAllTextAsync(configPath, """{"marker":"changed"}""");
    await File.WriteAllTextAsync(secretPath, """{"otxApiKey":"keep-current"}""");
    var restore = await backupService.RestoreBackupAsync(backupPath);
    Assert((await File.ReadAllTextAsync(configPath)).Contains("original"),
        "Restore should replace backed-up configuration");
    Assert((await File.ReadAllTextAsync(secretPath)).Contains("keep-current"),
        "Restore should preserve current API secrets");
    Assert(File.Exists(restore.SafetyBackupPath),
        "Restore should create a pre-restore safety backup");

    Console.WriteLine($"PASS: {assertions} SQLite assertions.");
    return 0;
}

catch (Exception exception)
{
    Console.Error.WriteLine(exception);
    return 1;
}
finally
{
    if (Directory.Exists(testRoot))
    {
        Directory.Delete(testRoot, recursive: true);
    }
}

void Assert(bool condition, string message)
{
    assertions++;
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

sealed class StubHandler(string json) : HttpMessageHandler
{
    public int RequestCount { get; private set; }
    public Uri? LastRequestUri { get; private set; }
    public string? LastRequestBody { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        RequestCount++;
        LastRequestUri = request.RequestUri;
        LastRequestBody = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }
}

sealed class UpdateAssetHandler(byte[] archive, byte[] checksum) : HttpMessageHandler
{
    public int RequestCount { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        RequestCount++;
        var bytes = request.RequestUri?.AbsolutePath.EndsWith(
            ".sha256",
            StringComparison.OrdinalIgnoreCase) == true
            ? checksum
            : archive;
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(bytes)
        });
    }
}

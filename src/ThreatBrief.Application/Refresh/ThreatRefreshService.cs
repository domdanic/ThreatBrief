using System.Diagnostics;
using ThreatBrief.Core.Interfaces;
using ThreatBrief.Application.Nvd;

namespace ThreatBrief.Application.Refresh;

public sealed class ThreatRefreshService(
    IThreatRepository repository,
    string appRoot,
    string dataPath)
{
    public async Task<RefreshOutcome> RefreshAsync(CancellationToken cancellationToken = default)
    {
        var scriptPath = Path.Combine(appRoot, "Invoke-ThreatBrief.ps1");
        if (!File.Exists(scriptPath))
        {
            throw new FileNotFoundException("The ThreatBrief PowerShell collector was not found.", scriptPath);
        }

        Directory.CreateDirectory(dataPath);
        var (powerShellPath, edition) = FindPowerShell();
        var startInfo = new ProcessStartInfo
        {
            FileName = powerShellPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(scriptPath);
        startInfo.ArgumentList.Add("-DataPath");
        startInfo.ArgumentList.Add(dataPath);

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidOperationException("PowerShell could not be started.");
        }

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        var output = await outputTask;
        var error = await errorTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(error) ? "The collector failed." : error.Trim());
        }

        var normalizedPath = Path.Combine(dataPath, "normalized", "cisa-kev-latest.json");
        var json = await File.ReadAllTextAsync(normalizedPath, cancellationToken);
        var records = System.Text.Json.JsonSerializer.Deserialize<List<Core.Models.ThreatRecord>>(
            json,
            new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidDataException("The collector produced no normalized records.");
        var import = await repository.ImportAsync(records, "CISA KEV", cancellationToken);
        var enriched = 0;
        string? nvdWarning = null;
        try
        {
            enriched = await new NvdEnrichmentService(repository)
                .EnrichRecentAsync(30, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            // CISA collection and local import remain useful when NVD is
            // temporarily unavailable or rate-limited.
            nvdWarning = exception.Message;
        }

        return new RefreshOutcome(edition, output.Trim(), import, enriched, nvdWarning);
    }

    private static (string Path, string Edition) FindPowerShell()
    {
        var pwsh = FindOnPath("pwsh.exe");
        if (pwsh is not null)
        {
            return (pwsh, "PowerShell 7");
        }

        var windowsPowerShell = FindOnPath("powershell.exe");
        if (windowsPowerShell is not null)
        {
            return (windowsPowerShell, "Windows PowerShell 5.1");
        }

        throw new FileNotFoundException(
            "ThreatBrief requires PowerShell 7 or Windows PowerShell 5.1.");
    }

    private static string? FindOnPath(string executable)
    {
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(directory.Trim(), executable);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
            catch (ArgumentException)
            {
                // Ignore malformed PATH entries and continue searching.
            }
        }

        return null;
    }
}

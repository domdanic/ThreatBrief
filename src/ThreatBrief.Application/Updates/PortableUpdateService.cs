using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using ThreatBrief.Application.Maintenance;

namespace ThreatBrief.Application.Updates;

public sealed record PreparedPortableUpdate(
    Version Version,
    string PayloadDirectory,
    string HelperScriptPath,
    string RollbackDirectory,
    string SafetyBackupPath);

public sealed class PortableUpdateService(
    string appRoot,
    string dataRoot,
    HttpClient? httpClient = null)
{
    private const long MaximumDownloadBytes = 500L * 1024 * 1024;
    private readonly string _appRoot = Path.GetFullPath(appRoot);
    private readonly string _dataRoot = Path.GetFullPath(dataRoot);
    private readonly HttpClient _httpClient = httpClient ?? new HttpClient
    {
        Timeout = TimeSpan.FromMinutes(10)
    };

    public async Task<PreparedPortableUpdate> PrepareAsync(
        UpdateCheckResult update,
        CancellationToken cancellationToken = default)
    {
        if (!update.UpdateAvailable
            || update.LatestVersion is null
            || string.IsNullOrWhiteSpace(update.DownloadUrl)
            || string.IsNullOrWhiteSpace(update.ChecksumUrl))
        {
            throw new InvalidOperationException(
                "This release cannot be installed automatically because its ZIP or checksum is missing.");
        }

        var downloadUri = ValidateGitHubUri(update.DownloadUrl);
        var checksumUri = ValidateGitHubUri(update.ChecksumUrl);
        VerifyTargetWritable();

        var updatesRoot = Path.Combine(_dataRoot, "updates");
        Directory.CreateDirectory(updatesRoot);
        var versionName = update.LatestVersion.ToString(3);
        var archivePath = Path.Combine(updatesRoot, $"ThreatBrief-{versionName}.zip");
        var checksumPath = archivePath + ".sha256";
        await DownloadFileAsync(downloadUri, archivePath, MaximumDownloadBytes, cancellationToken);
        await DownloadFileAsync(checksumUri, checksumPath, 64 * 1024, cancellationToken);
        await VerifyChecksumAsync(archivePath, checksumPath, cancellationToken);

        var stagingDirectory = Path.Combine(
            updatesRoot,
            $"staging-{versionName}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stagingDirectory);
        ExtractValidated(archivePath, stagingDirectory);
        var executable = Directory
            .EnumerateFiles(
                stagingDirectory,
                "ThreatBrief.exe",
                SearchOption.AllDirectories)
            .SingleOrDefault()
            ?? throw new InvalidDataException(
                "The verified release archive does not contain exactly one ThreatBrief.exe.");
        var payloadDirectory = Path.GetDirectoryName(executable)!;

        var safetyBackup = await new PortableBackupService(_dataRoot)
            .CreateBackupAsync(cancellationToken);
        var rollbackDirectory = Path.Combine(
            updatesRoot,
            $"rollback-{versionName}-{Guid.NewGuid():N}");
        var helperPath = Path.Combine(
            updatesRoot,
            $"apply-{versionName}-{Guid.NewGuid():N}.ps1");
        await File.WriteAllTextAsync(helperPath, UpdaterScript, cancellationToken);

        return new PreparedPortableUpdate(
            update.LatestVersion,
            payloadDirectory,
            helperPath,
            rollbackDirectory,
            safetyBackup);
    }

    public void LaunchAndReplace(PreparedPortableUpdate prepared, int processId)
    {
        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(prepared.HelperScriptPath);
        start.ArgumentList.Add("-Target");
        start.ArgumentList.Add(_appRoot);
        start.ArgumentList.Add("-Payload");
        start.ArgumentList.Add(prepared.PayloadDirectory);
        start.ArgumentList.Add("-ProcessId");
        start.ArgumentList.Add(processId.ToString());
        start.ArgumentList.Add("-Rollback");
        start.ArgumentList.Add(prepared.RollbackDirectory);
        start.ArgumentList.Add("-LogPath");
        start.ArgumentList.Add(Path.Combine(_dataRoot, "updates", "last-update.log"));
        _ = Process.Start(start)
            ?? throw new InvalidOperationException("Unable to launch the portable update helper.");
    }

    private static Uri ValidateGitHubUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps
            || !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Automatic updates only accept HTTPS GitHub release URLs.");
        }

        return uri;
    }

    private void VerifyTargetWritable()
    {
        var testPath = Path.Combine(_appRoot, $".threatbrief-update-test-{Guid.NewGuid():N}");
        try
        {
            using (File.Create(testPath))
            {
            }
        }
        catch (Exception exception)
        {
            throw new UnauthorizedAccessException(
                "ThreatBrief cannot update because its application folder is not writable.",
                exception);
        }
        finally
        {
            if (File.Exists(testPath))
            {
                File.Delete(testPath);
            }
        }
    }

    private async Task DownloadFileAsync(
        Uri uri,
        string destinationPath,
        long limit,
        CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync(
            uri,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > limit)
        {
            throw new InvalidDataException("The update asset exceeds the allowed download size.");
        }

        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var destination = new FileStream(
            destinationPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            81920,
            useAsync: true);
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
        {
            total += read;
            if (total > limit)
            {
                throw new InvalidDataException("The update asset exceeds the allowed download size.");
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    private static async Task VerifyChecksumAsync(
        string archivePath,
        string checksumPath,
        CancellationToken cancellationToken)
    {
        var checksumText = await File.ReadAllTextAsync(checksumPath, cancellationToken);
        var expected = Regex.Match(checksumText, @"\b[A-Fa-f0-9]{64}\b").Value;
        if (expected.Length != 64)
        {
            throw new InvalidDataException("The release checksum file is invalid.");
        }

        await using var archive = File.OpenRead(archivePath);
        var actual = Convert.ToHexString(
            await SHA256.HashDataAsync(archive, cancellationToken));
        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The downloaded update failed SHA-256 verification.");
        }
    }

    private static void ExtractValidated(string archivePath, string stagingDirectory)
    {
        var stagingRoot = Path.GetFullPath(stagingDirectory)
            .TrimEnd(Path.DirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        using var archive = ZipFile.OpenRead(archivePath);
        foreach (var entry in archive.Entries)
        {
            var destination = Path.GetFullPath(
                Path.Combine(stagingDirectory, entry.FullName));
            if (!destination.StartsWith(stagingRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("The release archive contains an unsafe path.");
            }

            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(destination);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            entry.ExtractToFile(destination, overwrite: true);
        }
    }

    private const string UpdaterScript =
        """
        param(
            [Parameter(Mandatory=$true)][string]$Target,
            [Parameter(Mandatory=$true)][string]$Payload,
            [Parameter(Mandatory=$true)][int]$ProcessId,
            [Parameter(Mandatory=$true)][string]$Rollback,
            [Parameter(Mandatory=$true)][string]$LogPath
        )
        $ErrorActionPreference = 'Stop'
        Start-Transcript -Path $LogPath -Force | Out-Null
        try {
            Wait-Process -Id $ProcessId -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force -Path $Rollback | Out-Null
            Get-ChildItem -LiteralPath $Target -Force |
                Where-Object { $_.Name -ne 'data' } |
                Copy-Item -Destination $Rollback -Recurse -Force
            try {
                Get-ChildItem -LiteralPath $Target -Force |
                    Where-Object { $_.Name -ne 'data' } |
                    Remove-Item -Recurse -Force
                Get-ChildItem -LiteralPath $Payload -Force |
                    Where-Object { $_.Name -ne 'data' } |
                    Copy-Item -Destination $Target -Recurse -Force
                $newProcess = Start-Process -FilePath (Join-Path $Target 'ThreatBrief.exe') -PassThru
                Start-Sleep -Seconds 5
                if ($newProcess.HasExited) {
                    throw "Updated ThreatBrief exited during startup."
                }
            }
            catch {
                Get-ChildItem -LiteralPath $Target -Force |
                    Where-Object { $_.Name -ne 'data' } |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Get-ChildItem -LiteralPath $Rollback -Force |
                    Copy-Item -Destination $Target -Recurse -Force
                Start-Process -FilePath (Join-Path $Target 'ThreatBrief.exe')
                throw
            }
        }
        finally {
            Stop-Transcript | Out-Null
        }
        """;
}

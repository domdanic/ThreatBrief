using System.IO.Compression;

namespace ThreatBrief.Application.Maintenance;

public sealed class PortableBackupService(string dataRoot)
{
    public async Task<string> CreateBackupAsync(CancellationToken cancellationToken = default)
    {
        var backupDirectory = Path.Combine(dataRoot, "backups");
        Directory.CreateDirectory(backupDirectory);
        var backupPath = Path.Combine(
            backupDirectory,
            $"ThreatBrief-Backup-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid():N}.zip");

        await using var archiveStream = new FileStream(
            backupPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            81920,
            useAsync: true);
        using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Create);
        await AddIfExistsAsync(
            archive,
            Path.Combine(dataRoot, "threatbrief.db"),
            "threatbrief.db",
            cancellationToken);

        var configDirectory = Path.Combine(dataRoot, "config");
        if (Directory.Exists(configDirectory))
        {
            foreach (var file in Directory.EnumerateFiles(configDirectory, "*.json"))
            {
                if (string.Equals(
                    Path.GetFileName(file),
                    "secrets.local.json",
                    StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                await AddIfExistsAsync(
                    archive,
                    file,
                    $"config/{Path.GetFileName(file)}",
                    cancellationToken);
            }
        }

        return backupPath;
    }

    public async Task<RestoreResult> RestoreBackupAsync(
        string backupPath,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(backupPath))
        {
            throw new FileNotFoundException("The selected backup does not exist.", backupPath);
        }

        var safetyBackupPath = await CreateBackupAsync(cancellationToken);
        var stagingDirectory = Path.Combine(
            dataRoot,
            "backups",
            $".restore-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stagingDirectory);

        try
        {
            using var archive = ZipFile.OpenRead(backupPath);
            var databaseEntry = archive.GetEntry("threatbrief.db")
                ?? throw new InvalidDataException(
                    "This archive is not a ThreatBrief backup: threatbrief.db is missing.");
            var stagedDatabase = Path.Combine(stagingDirectory, "threatbrief.db");
            await ExtractEntryAsync(databaseEntry, stagedDatabase, cancellationToken);

            File.Copy(
                stagedDatabase,
                Path.Combine(dataRoot, "threatbrief.db"),
                overwrite: true);

            var restoredConfigFiles = 0;
            var configDirectory = Path.Combine(dataRoot, "config");
            Directory.CreateDirectory(configDirectory);
            foreach (var entry in archive.Entries.Where(entry =>
                         entry.FullName.StartsWith("config/", StringComparison.OrdinalIgnoreCase)
                         && entry.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                         && !entry.FullName.Contains("..", StringComparison.Ordinal)
                         && !string.Equals(
                             Path.GetFileName(entry.FullName),
                             "secrets.local.json",
                             StringComparison.OrdinalIgnoreCase)))
            {
                var fileName = Path.GetFileName(entry.FullName);
                if (string.IsNullOrWhiteSpace(fileName))
                {
                    continue;
                }

                await ExtractEntryAsync(
                    entry,
                    Path.Combine(configDirectory, fileName),
                    cancellationToken);
                restoredConfigFiles++;
            }

            return new RestoreResult(safetyBackupPath, restoredConfigFiles);
        }
        finally
        {
            if (Directory.Exists(stagingDirectory))
            {
                Directory.Delete(stagingDirectory, recursive: true);
            }
        }
    }

    private static async Task AddIfExistsAsync(
        ZipArchive archive,
        string sourcePath,
        string entryName,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(sourcePath))
        {
            return;
        }

        var entry = archive.CreateEntry(entryName, CompressionLevel.Optimal);
        await using var entryStream = entry.Open();
        await using var source = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            81920,
            useAsync: true);
        await source.CopyToAsync(entryStream, cancellationToken);
    }

    private static async Task ExtractEntryAsync(
        ZipArchiveEntry entry,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        await using var source = entry.Open();
        await using var destination = new FileStream(
            destinationPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            81920,
            useAsync: true);
        await source.CopyToAsync(destination, cancellationToken);
    }
}

public sealed record RestoreResult(
    string SafetyBackupPath,
    int RestoredConfigFiles);

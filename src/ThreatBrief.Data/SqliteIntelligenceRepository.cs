using System.Globalization;
using Microsoft.Data.Sqlite;
using ThreatBrief.Core.Interfaces;
using ThreatBrief.Core.Intelligence;

namespace ThreatBrief.Data;

public sealed class SqliteIntelligenceRepository(string databasePath) : IIntelligenceRepository
{
    private readonly string _databasePath = Path.GetFullPath(databasePath);

    private string ConnectionString => new SqliteConnectionStringBuilder
    {
        DataSource = _databasePath,
        Mode = SqliteOpenMode.ReadWriteCreate,
        Cache = SqliteCacheMode.Shared,
        Pooling = false
    }.ToString();

    public async Task<IntelligenceImportResult> ImportIntelligenceAsync(
        IntelligenceBatch batch,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var timestamp = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        var indicatorsProcessed = 0;
        var relationshipsProcessed = 0;

        foreach (var input in batch.Indicators)
        {
            await UpsertIndicatorAsync(
                connection,
                transaction,
                batch.Source,
                input,
                timestamp,
                cancellationToken);
            indicatorsProcessed++;
        }

        foreach (var report in batch.Reports)
        {
            var reportId = await UpsertReportAsync(
                connection,
                transaction,
                batch.Source,
                report,
                timestamp,
                cancellationToken);

            foreach (var cveId in report.CveIds
                         .Where(IsCveId)
                         .Distinct(StringComparer.OrdinalIgnoreCase))
            {
                await using var relation = connection.CreateCommand();
                relation.Transaction = (SqliteTransaction)transaction;
                relation.CommandText =
                    """
                    INSERT OR IGNORE INTO report_vulnerabilities(report_id, threat_id)
                    SELECT $reportId, id FROM threats WHERE id = $cveId;
                    """;
                relation.Parameters.AddWithValue("$reportId", reportId);
                relation.Parameters.AddWithValue("$cveId", cveId.ToUpperInvariant());
                relationshipsProcessed += await relation.ExecuteNonQueryAsync(cancellationToken);
            }

            foreach (var indicator in report.Indicators)
            {
                var indicatorId = await UpsertIndicatorAsync(
                    connection,
                    transaction,
                    batch.Source,
                    indicator,
                    timestamp,
                    cancellationToken);
                indicatorsProcessed++;

                await using var relation = connection.CreateCommand();
                relation.Transaction = (SqliteTransaction)transaction;
                relation.CommandText =
                    "INSERT OR IGNORE INTO report_indicators(report_id, indicator_id) VALUES($reportId, $indicatorId);";
                relation.Parameters.AddWithValue("$reportId", reportId);
                relation.Parameters.AddWithValue("$indicatorId", indicatorId);
                await relation.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        await transaction.CommitAsync(cancellationToken);
        await ExpireIndicatorsAsync(cancellationToken: cancellationToken);
        return new IntelligenceImportResult(
            batch.Reports.Count,
            indicatorsProcessed,
            relationshipsProcessed);
    }

    public async Task<IReadOnlyList<IntelligenceReport>> QueryReportsAsync(
        string? search = null,
        int limit = 250,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var where = string.IsNullOrWhiteSpace(search)
            ? string.Empty
            : "WHERE r.title LIKE $search OR r.description LIKE $search OR r.source LIKE $search";
        command.CommandText =
            $"""
             SELECT r.*,
                    (SELECT group_concat(threat_id, '|') FROM report_vulnerabilities rv WHERE rv.report_id = r.id) AS cves,
                    (SELECT COUNT(*) FROM report_indicators ri WHERE ri.report_id = r.id) AS indicator_count
             FROM intelligence_reports r
             {where}
             ORDER BY COALESCE(r.modified_at, r.published_at, r.last_seen_at) DESC
             LIMIT $limit;
             """;
        if (!string.IsNullOrWhiteSpace(search))
        {
            command.Parameters.AddWithValue("$search", $"%{search.Trim()}%");
        }

        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 2000));
        var results = new List<IntelligenceReport>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new IntelligenceReport
            {
                Id = reader.GetInt64(reader.GetOrdinal("id")),
                Source = reader.GetString(reader.GetOrdinal("source")),
                ExternalId = reader.GetString(reader.GetOrdinal("external_id")),
                Title = reader.GetString(reader.GetOrdinal("title")),
                Description = ReadNullable(reader, "description"),
                Author = ReadNullable(reader, "author"),
                PublishedAt = ReadNullable(reader, "published_at"),
                ModifiedAt = ReadNullable(reader, "modified_at"),
                SourceUrl = ReadNullable(reader, "source_url"),
                FirstSeenAt = ReadNullable(reader, "first_seen_at"),
                LastSeenAt = ReadNullable(reader, "last_seen_at"),
                CveIds = (ReadNullable(reader, "cves") ?? string.Empty)
                    .Split('|', StringSplitOptions.RemoveEmptyEntries),
                IndicatorCount = reader.GetInt32(reader.GetOrdinal("indicator_count"))
            });
        }

        return results;
    }

    public async Task<IReadOnlyList<ThreatIndicator>> QueryIndicatorsAsync(
        string? search = null,
        bool activeOnly = true,
        int limit = 500,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var conditions = new List<string>();
        if (activeOnly)
        {
            conditions.Add("i.is_active = 1");
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            conditions.Add(
                "(i.value LIKE $search OR i.type LIKE $search OR i.malware_family LIKE $search)");
            command.Parameters.AddWithValue("$search", $"%{search.Trim()}%");
        }

        var where = conditions.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", conditions)}";
        command.CommandText =
            $"""
             SELECT i.*,
                    (SELECT group_concat(source, '|') FROM indicator_sources s WHERE s.indicator_id = i.id) AS source_names
             FROM indicators i
             {where}
             ORDER BY COALESCE(i.last_seen_at, i.first_seen_at) DESC
             LIMIT $limit;
             """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 5000));
        var results = new List<ThreatIndicator>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new ThreatIndicator
            {
                Id = reader.GetInt64(reader.GetOrdinal("id")),
                Type = reader.GetString(reader.GetOrdinal("type")),
                Value = reader.GetString(reader.GetOrdinal("value")),
                NormalizedValue = reader.GetString(reader.GetOrdinal("normalized_value")),
                ThreatType = ReadNullable(reader, "threat_type"),
                MalwareFamily = ReadNullable(reader, "malware_family"),
                Confidence = ReadNullableInt(reader, "confidence"),
                FirstSeenAt = ReadNullable(reader, "first_seen_at"),
                LastSeenAt = ReadNullable(reader, "last_seen_at"),
                ExpiresAt = ReadNullable(reader, "expires_at"),
                IsActive = reader.GetBoolean(reader.GetOrdinal("is_active")),
                ReferenceUrl = ReadNullable(reader, "reference_url"),
                Sources = (ReadNullable(reader, "source_names") ?? string.Empty)
                    .Split('|', StringSplitOptions.RemoveEmptyEntries)
            });
        }

        return results;
    }

    public async Task ExpireIndicatorsAsync(
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE indicators
            SET is_active = CASE
                WHEN expires_at IS NOT NULL AND datetime(expires_at) < datetime($now) THEN 0
                ELSE 1
            END;
            """;
        command.Parameters.AddWithValue(
            "$now",
            (now ?? DateTimeOffset.UtcNow).ToString("O", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task InitializeAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)
            ?? throw new InvalidOperationException("The database path has no parent directory."));
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            PRAGMA journal_mode = DELETE;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS intelligence_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                external_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                author TEXT,
                published_at TEXT,
                modified_at TEXT,
                source_url TEXT,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                UNIQUE(source, external_id)
            );

            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                canonical_key TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                threat_type TEXT,
                malware_family TEXT,
                confidence INTEGER,
                first_seen_at TEXT,
                last_seen_at TEXT,
                expires_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                reference_url TEXT,
                UNIQUE(type, normalized_value)
            );

            CREATE TABLE IF NOT EXISTS indicator_sources (
                indicator_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY(indicator_id, source),
                FOREIGN KEY(indicator_id) REFERENCES indicators(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS report_indicators (
                report_id INTEGER NOT NULL,
                indicator_id INTEGER NOT NULL,
                PRIMARY KEY(report_id, indicator_id),
                FOREIGN KEY(report_id) REFERENCES intelligence_reports(id) ON DELETE CASCADE,
                FOREIGN KEY(indicator_id) REFERENCES indicators(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS report_vulnerabilities (
                report_id INTEGER NOT NULL,
                threat_id TEXT NOT NULL,
                PRIMARY KEY(report_id, threat_id),
                FOREIGN KEY(report_id) REFERENCES intelligence_reports(id) ON DELETE CASCADE,
                FOREIGN KEY(threat_id) REFERENCES threats(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS ix_indicators_active ON indicators(is_active);
            CREATE INDEX IF NOT EXISTS ix_indicators_normalized ON indicators(normalized_value);
            CREATE INDEX IF NOT EXISTS ix_reports_modified ON intelligence_reports(modified_at DESC);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<long> UpsertReportAsync(
        SqliteConnection connection,
        System.Data.Common.DbTransaction transaction,
        string source,
        IntelligenceReportInput report,
        string timestamp,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText =
            """
            INSERT INTO intelligence_reports(
                source, external_id, title, description, author, published_at,
                modified_at, source_url, first_seen_at, last_seen_at)
            VALUES(
                $source, $externalId, $title, $description, $author, $publishedAt,
                $modifiedAt, $sourceUrl, $timestamp, $timestamp)
            ON CONFLICT(source, external_id) DO UPDATE SET
                title = excluded.title,
                description = excluded.description,
                author = excluded.author,
                published_at = excluded.published_at,
                modified_at = excluded.modified_at,
                source_url = excluded.source_url,
                last_seen_at = excluded.last_seen_at
            RETURNING id;
            """;
        command.Parameters.AddWithValue("$source", source);
        command.Parameters.AddWithValue("$externalId", report.ExternalId);
        command.Parameters.AddWithValue("$title", report.Title);
        AddNullable(command, "$description", report.Description);
        AddNullable(command, "$author", report.Author);
        AddNullable(command, "$publishedAt", report.PublishedAt);
        AddNullable(command, "$modifiedAt", report.ModifiedAt);
        AddNullable(command, "$sourceUrl", report.SourceUrl);
        command.Parameters.AddWithValue("$timestamp", timestamp);
        return Convert.ToInt64(
            await command.ExecuteScalarAsync(cancellationToken),
            CultureInfo.InvariantCulture);
    }

    private static async Task<long> UpsertIndicatorAsync(
        SqliteConnection connection,
        System.Data.Common.DbTransaction transaction,
        string source,
        IndicatorInput input,
        string timestamp,
        CancellationToken cancellationToken)
    {
        var normalized = IndicatorNormalizer.Normalize(input.Type, input.Value);
        var key = IndicatorNormalizer.CanonicalKey(input.Type, input.Value);
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText =
            """
            INSERT INTO indicators(
                canonical_key, type, value, normalized_value, threat_type,
                malware_family, confidence, first_seen_at, last_seen_at,
                expires_at, is_active, reference_url)
            VALUES(
                $key, $type, $value, $normalized, $threatType,
                $malwareFamily, $confidence, $firstSeenAt, $lastSeenAt,
                $expiresAt, 1, $referenceUrl)
            ON CONFLICT(canonical_key) DO UPDATE SET
                value = excluded.value,
                threat_type = COALESCE(excluded.threat_type, threat_type),
                malware_family = COALESCE(excluded.malware_family, malware_family),
                confidence = MAX(COALESCE(excluded.confidence, 0), COALESCE(confidence, 0)),
                first_seen_at = COALESCE(first_seen_at, excluded.first_seen_at),
                last_seen_at = COALESCE(excluded.last_seen_at, last_seen_at),
                expires_at = COALESCE(excluded.expires_at, expires_at),
                is_active = 1,
                reference_url = COALESCE(excluded.reference_url, reference_url)
            RETURNING id;
            """;
        command.Parameters.AddWithValue("$key", key);
        command.Parameters.AddWithValue("$type", input.Type.Trim().ToLowerInvariant());
        command.Parameters.AddWithValue("$value", input.Value.Trim());
        command.Parameters.AddWithValue("$normalized", normalized);
        AddNullable(command, "$threatType", input.ThreatType);
        AddNullable(command, "$malwareFamily", input.MalwareFamily);
        AddNullable(command, "$confidence", input.Confidence);
        AddNullable(command, "$firstSeenAt", input.FirstSeenAt);
        AddNullable(command, "$lastSeenAt", input.LastSeenAt);
        AddNullable(command, "$expiresAt", input.ExpiresAt);
        AddNullable(command, "$referenceUrl", input.ReferenceUrl);
        var indicatorId = Convert.ToInt64(
            await command.ExecuteScalarAsync(cancellationToken),
            CultureInfo.InvariantCulture);

        await using var observation = connection.CreateCommand();
        observation.Transaction = (SqliteTransaction)transaction;
        observation.CommandText =
            """
            INSERT INTO indicator_sources(indicator_id, source, first_seen_at, last_seen_at)
            VALUES($indicatorId, $source, $timestamp, $timestamp)
            ON CONFLICT(indicator_id, source) DO UPDATE SET
                last_seen_at = excluded.last_seen_at;
            """;
        observation.Parameters.AddWithValue("$indicatorId", indicatorId);
        observation.Parameters.AddWithValue("$source", source);
        observation.Parameters.AddWithValue("$timestamp", timestamp);
        await observation.ExecuteNonQueryAsync(cancellationToken);
        return indicatorId;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static void AddNullable(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    private static string? ReadNullable(SqliteDataReader reader, string name)
    {
        var ordinal = reader.GetOrdinal(name);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static int? ReadNullableInt(SqliteDataReader reader, string name)
    {
        var ordinal = reader.GetOrdinal(name);
        return reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);
    }

    private static bool IsCveId(string value) =>
        System.Text.RegularExpressions.Regex.IsMatch(
            value,
            "^CVE-\\d{4}-\\d{4,}$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
            | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
}

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ThreatBrief.Core.Interfaces;
using ThreatBrief.Core.Models;
using ThreatBrief.Core.Triage;

namespace ThreatBrief.Data;

public sealed class SqliteThreatRepository(string databasePath) : IThreatRepository
{
    private readonly string _databasePath = Path.GetFullPath(databasePath);

    private string ConnectionString => new SqliteConnectionStringBuilder
    {
        DataSource = _databasePath,
        Mode = SqliteOpenMode.ReadWriteCreate,
        Cache = SqliteCacheMode.Shared,
        Pooling = false
    }.ToString();

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)
            ?? throw new InvalidOperationException("The database path has no parent directory."));

        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            PRAGMA journal_mode = DELETE;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS schema_info (
                version INTEGER NOT NULL
            );
            INSERT INTO schema_info(version)
            SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_info);

            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                title TEXT,
                vendor TEXT,
                product TEXT,
                severity TEXT,
                cvss REAL,
                published TEXT,
                date_added TEXT,
                due_date TEXT,
                known_exploited INTEGER NOT NULL,
                ransomware_associated INTEGER NOT NULL,
                ransomware_status TEXT,
                description TEXT,
                recommended_action TEXT,
                notes TEXT,
                cwes_json TEXT NOT NULL,
                source TEXT,
                source_url TEXT,
                content_hash TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                last_changed_at TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                is_saved INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS ix_threats_date_added ON threats(date_added DESC);
            CREATE INDEX IF NOT EXISTS ix_threats_vendor ON threats(vendor);
            CREATE INDEX IF NOT EXISTS ix_threats_is_read ON threats(is_read);

            CREATE TABLE IF NOT EXISTS refreshes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                collector TEXT NOT NULL,
                refreshed_at TEXT NOT NULL,
                total_records INTEGER NOT NULL,
                added_records INTEGER NOT NULL,
                updated_records INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS threat_sources (
                threat_id TEXT NOT NULL,
                source TEXT NOT NULL,
                external_id TEXT,
                source_url TEXT,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY(threat_id, source),
                FOREIGN KEY(threat_id) REFERENCES threats(id) ON DELETE CASCADE
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);

        await EnsureColumnAsync(connection, "nvd_status", "TEXT", cancellationToken);
        await EnsureColumnAsync(connection, "cvss_vector", "TEXT", cancellationToken);
        await EnsureColumnAsync(connection, "attack_vector", "TEXT", cancellationToken);
        await EnsureColumnAsync(connection, "attack_complexity", "TEXT", cancellationToken);
        await EnsureColumnAsync(connection, "privileges_required", "TEXT", cancellationToken);
        await EnsureColumnAsync(connection, "user_interaction", "TEXT", cancellationToken);
        await EnsureColumnAsync(connection, "nvd_last_modified", "TEXT", cancellationToken);
        await EnsureColumnAsync(connection, "nvd_enriched_at", "TEXT", cancellationToken);
        await EnsureColumnAsync(connection, "nvd_references_json", "TEXT NOT NULL DEFAULT '[]'", cancellationToken);
        await EnsureColumnAsync(connection, "affected_products_json", "TEXT NOT NULL DEFAULT '[]'", cancellationToken);
        await EnsureColumnAsync(connection, "triage_status", "TEXT NOT NULL DEFAULT 'Backlog'", cancellationToken);

        await using var seedSources = connection.CreateCommand();
        seedSources.CommandText =
            """
            INSERT OR IGNORE INTO threat_sources(
                threat_id, source, external_id, source_url, first_seen_at, last_seen_at)
            SELECT id, COALESCE(source, 'Unknown'), id, source_url, first_seen_at, last_seen_at
            FROM threats;

            INSERT OR IGNORE INTO threat_sources(
                threat_id, source, external_id, source_url, first_seen_at, last_seen_at)
            SELECT id, 'NVD', id, 'https://nvd.nist.gov/vuln/detail/' || id,
                   nvd_enriched_at, nvd_enriched_at
            FROM threats
            WHERE nvd_enriched_at IS NOT NULL;
            """;
        await seedSources.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<ImportResult> ImportAsync(
        IReadOnlyCollection<ThreatRecord> records,
        string collector,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(collector);
        await InitializeAsync(cancellationToken);

        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var existingCount = await CountAllAsync(connection, transaction, cancellationToken);
        var isBaseline = existingCount == 0;
        var added = 0;
        var updated = 0;
        var unchanged = 0;
        var timestamp = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);

        foreach (var record in records)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hash = ContentHash(record);
            var existingHash = await GetHashAsync(connection, transaction, record.Id, cancellationToken);

            if (existingHash is null)
            {
                await InsertAsync(
                    connection,
                    transaction,
                    record,
                    hash,
                    timestamp,
                    isBaseline,
                    cancellationToken);
                added++;
            }
            else if (!string.Equals(existingHash, hash, StringComparison.Ordinal))
            {
                await UpdateAsync(connection, transaction, record, hash, timestamp, cancellationToken);
                updated++;
            }
            else
            {
                await TouchAsync(connection, transaction, record.Id, timestamp, cancellationToken);
                unchanged++;
            }

            await UpsertSourceAsync(
                connection,
                transaction,
                record.Id,
                collector,
                record.Id,
                record.SourceUrl,
                timestamp,
                cancellationToken);
        }

        await using (var refresh = connection.CreateCommand())
        {
            refresh.Transaction = (SqliteTransaction)transaction;
            refresh.CommandText =
                """
                INSERT INTO refreshes(
                    collector, refreshed_at, total_records, added_records, updated_records)
                VALUES ($collector, $refreshedAt, $total, $added, $updated);
                """;
            refresh.Parameters.AddWithValue("$collector", collector);
            refresh.Parameters.AddWithValue("$refreshedAt", timestamp);
            refresh.Parameters.AddWithValue("$total", records.Count);
            refresh.Parameters.AddWithValue("$added", added);
            refresh.Parameters.AddWithValue("$updated", updated);
            await refresh.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return new ImportResult(records.Count, added, updated, unchanged, isBaseline);
    }

    public async Task<IReadOnlyList<ThreatRecord>> QueryAsync(
        ThreatQuery query,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        var limit = Math.Clamp(query.Limit, 1, 5000);
        var conditions = new List<string>();

        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();

        if (!string.IsNullOrWhiteSpace(query.SearchText))
        {
            conditions.Add(
                "(id LIKE $search OR title LIKE $search OR vendor LIKE $search " +
                "OR product LIKE $search OR description LIKE $search)");
            command.Parameters.AddWithValue("$search", $"%{query.SearchText.Trim()}%");
        }

        if (!string.IsNullOrWhiteSpace(query.Vendor))
        {
            conditions.Add("vendor = $vendor COLLATE NOCASE");
            command.Parameters.AddWithValue("$vendor", query.Vendor.Trim());
        }

        if (query.UnreadOnly)
        {
            conditions.Add("is_read = 0");
        }

        if (query.SavedOnly)
        {
            conditions.Add("is_saved = 1");
        }

        if (query.AddedWithinDays is > 0)
        {
            conditions.Add("date(date_added) >= date('now', $days)");
            command.Parameters.AddWithValue("$days", $"-{query.AddedWithinDays.Value - 1} days");
        }

        var where = conditions.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", conditions)}";
        command.CommandText =
            $"""
             SELECT t.*,
                    (SELECT COUNT(*) FROM threat_sources s WHERE s.threat_id = t.id) AS source_count,
                    (SELECT group_concat(source, '|') FROM threat_sources s WHERE s.threat_id = t.id) AS source_names
             FROM threats t
             {where}
             ORDER BY date_added DESC, id DESC
             LIMIT $limit;
             """;
        command.Parameters.AddWithValue("$limit", limit);

        var results = new List<ThreatRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(ReadRecord(reader));
        }

        return results;
    }

    public async Task<ThreatRecord?> GetAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT t.*,
                   (SELECT COUNT(*) FROM threat_sources s WHERE s.threat_id = t.id) AS source_count,
                   (SELECT group_concat(source, '|') FROM threat_sources s WHERE s.threat_id = t.id) AS source_names
            FROM threats t
            WHERE id = $id;
            """;
        command.Parameters.AddWithValue("$id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadRecord(reader) : null;
    }

    public Task SetReadAsync(string id, bool isRead, CancellationToken cancellationToken = default) =>
        SetFlagAsync(id, "is_read", isRead, cancellationToken);

    public Task SetSavedAsync(string id, bool isSaved, CancellationToken cancellationToken = default) =>
        SetFlagAsync(id, "is_saved", isSaved, cancellationToken);

    public async Task SetTriageStatusAsync(
        string id,
        string status,
        CancellationToken cancellationToken = default)
    {
        if (!TriageStates.All.Contains(status, StringComparer.Ordinal))
        {
            throw new ArgumentException($"Unsupported triage status '{status}'.", nameof(status));
        }

        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE threats
            SET triage_status = $status,
                is_read = CASE WHEN $terminal = 1 THEN 1 ELSE is_read END
            WHERE id = $id;
            """;
        command.Parameters.AddWithValue("$status", status);
        command.Parameters.AddWithValue("$terminal", TriageStates.IsTerminal(status) ? 1 : 0);
        command.Parameters.AddWithValue("$id", id);
        if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
        {
            throw new KeyNotFoundException($"Threat '{id}' was not found.");
        }
    }

    public async Task SetTriageStatusesAsync(
        IReadOnlyCollection<string> ids,
        string status,
        CancellationToken cancellationToken = default)
    {
        if (!TriageStates.All.Contains(status, StringComparer.Ordinal))
        {
            throw new ArgumentException($"Unsupported triage status '{status}'.", nameof(status));
        }

        if (ids.Count == 0)
        {
            return;
        }

        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        foreach (var id in ids.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            await using var command = connection.CreateCommand();
            command.Transaction = (SqliteTransaction)transaction;
            command.CommandText =
                """
                UPDATE threats
                SET triage_status = $status,
                    is_read = CASE WHEN $terminal = 1 THEN 1 ELSE is_read END
                WHERE id = $id;
                """;
            command.Parameters.AddWithValue("$status", status);
            command.Parameters.AddWithValue("$terminal", TriageStates.IsTerminal(status) ? 1 : 0);
            command.Parameters.AddWithValue("$id", id);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<ThreatSourceObservation>> GetSourcesAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT threat_id, source, external_id, source_url, first_seen_at, last_seen_at
            FROM threat_sources
            WHERE threat_id = $id
            ORDER BY source;
            """;
        command.Parameters.AddWithValue("$id", id);
        var results = new List<ThreatSourceObservation>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new ThreatSourceObservation
            {
                ThreatId = reader.GetString(0),
                Source = reader.GetString(1),
                ExternalId = reader.IsDBNull(2) ? null : reader.GetString(2),
                SourceUrl = reader.IsDBNull(3) ? null : reader.GetString(3),
                FirstSeenAt = reader.GetString(4),
                LastSeenAt = reader.GetString(5)
            });
        }

        return results;
    }

    public async Task SetAllReadAsync(CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE threats SET is_read = 1;";
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<int> CountUnreadAsync(CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM threats WHERE is_read = 0;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }

    public async Task<IReadOnlyList<string>> GetEnrichmentCandidatesAsync(
        int addedWithinDays,
        int limit,
        int cacheHours,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT id
            FROM threats
            WHERE date(date_added) >= date('now', $days)
              AND (
                nvd_enriched_at IS NULL
                OR datetime(nvd_enriched_at) < datetime('now', $cache)
              )
            ORDER BY date_added DESC, id DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$days", $"-{Math.Max(0, addedWithinDays - 1)} days");
        command.Parameters.AddWithValue("$cache", $"-{Math.Max(1, cacheHours)} hours");
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 100));
        var ids = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            ids.Add(reader.GetString(0));
        }

        return ids;
    }

    public async Task ApplyEnrichmentAsync(
        IReadOnlyCollection<ThreatEnrichment> enrichments,
        CancellationToken cancellationToken = default)
    {
        if (enrichments.Count == 0)
        {
            return;
        }

        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var enrichedAt = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);

        foreach (var enrichment in enrichments)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = (SqliteTransaction)transaction;
            command.CommandText =
                """
                UPDATE threats SET
                    severity = COALESCE($severity, severity),
                    cvss = COALESCE($cvss, cvss),
                    published = COALESCE($published, published),
                    cwes_json = CASE WHEN $cwesJson = '[]' THEN cwes_json ELSE $cwesJson END,
                    nvd_status = $nvdStatus,
                    cvss_vector = $cvssVector,
                    attack_vector = $attackVector,
                    attack_complexity = $attackComplexity,
                    privileges_required = $privilegesRequired,
                    user_interaction = $userInteraction,
                    nvd_last_modified = $nvdLastModified,
                    nvd_enriched_at = $nvdEnrichedAt,
                    nvd_references_json = $nvdReferencesJson,
                    affected_products_json = $affectedProductsJson
                WHERE id = $id;
                """;
            command.Parameters.AddWithValue("$id", enrichment.Id);
            AddNullable(command, "$severity", enrichment.Severity);
            AddNullable(command, "$cvss", enrichment.Cvss);
            AddNullable(command, "$published", enrichment.Published);
            command.Parameters.AddWithValue("$cwesJson", JsonSerializer.Serialize(enrichment.Cwes));
            AddNullable(command, "$nvdStatus", enrichment.Status);
            AddNullable(command, "$cvssVector", enrichment.CvssVector);
            AddNullable(command, "$attackVector", enrichment.AttackVector);
            AddNullable(command, "$attackComplexity", enrichment.AttackComplexity);
            AddNullable(command, "$privilegesRequired", enrichment.PrivilegesRequired);
            AddNullable(command, "$userInteraction", enrichment.UserInteraction);
            AddNullable(command, "$nvdLastModified", enrichment.LastModified);
            command.Parameters.AddWithValue("$nvdEnrichedAt", enrichedAt);
            command.Parameters.AddWithValue(
                "$nvdReferencesJson",
                JsonSerializer.Serialize(enrichment.References));
            command.Parameters.AddWithValue(
                "$affectedProductsJson",
                JsonSerializer.Serialize(enrichment.AffectedProducts));
            await command.ExecuteNonQueryAsync(cancellationToken);
            await UpsertSourceAsync(
                connection,
                transaction,
                enrichment.Id,
                "NVD",
                enrichment.Id,
                $"https://nvd.nist.gov/vuln/detail/{enrichment.Id}",
                enrichedAt,
                cancellationToken);
        }

        await using (var refresh = connection.CreateCommand())
        {
            refresh.Transaction = (SqliteTransaction)transaction;
            refresh.CommandText =
                """
                INSERT INTO refreshes(
                    collector, refreshed_at, total_records, added_records, updated_records)
                VALUES('NVD', $refreshedAt, $total, 0, $total);
                """;
            refresh.Parameters.AddWithValue("$refreshedAt", enrichedAt);
            refresh.Parameters.AddWithValue("$total", enrichments.Count);
            await refresh.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<RefreshRecord>> GetRefreshHistoryAsync(
        int limit = 20,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT id, collector, refreshed_at, total_records, added_records, updated_records
            FROM refreshes
            ORDER BY id DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 100));
        var records = new List<RefreshRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(new RefreshRecord(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetInt32(3),
                reader.GetInt32(4),
                reader.GetInt32(5)));
        }

        return records;
    }

    private async Task SetFlagAsync(
        string id,
        string column,
        bool value,
        CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"UPDATE threats SET {column} = $value WHERE id = $id;";
        command.Parameters.AddWithValue("$value", value ? 1 : 0);
        command.Parameters.AddWithValue("$id", id);
        if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
        {
            throw new KeyNotFoundException($"Threat '{id}' was not found.");
        }
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static async Task EnsureColumnAsync(
        SqliteConnection connection,
        string column,
        string definition,
        CancellationToken cancellationToken)
    {
        await using var inspect = connection.CreateCommand();
        inspect.CommandText = "SELECT COUNT(*) FROM pragma_table_info('threats') WHERE name = $name;";
        inspect.Parameters.AddWithValue("$name", column);
        var exists = Convert.ToInt32(
            await inspect.ExecuteScalarAsync(cancellationToken),
            CultureInfo.InvariantCulture) > 0;
        if (exists)
        {
            return;
        }

        await using var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE threats ADD COLUMN {column} {definition};";
        await alter.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<int> CountAllAsync(
        SqliteConnection connection,
        System.Data.Common.DbTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = "SELECT COUNT(*) FROM threats;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }

    private static async Task<string?> GetHashAsync(
        SqliteConnection connection,
        System.Data.Common.DbTransaction transaction,
        string id,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = "SELECT content_hash FROM threats WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id);
        return await command.ExecuteScalarAsync(cancellationToken) as string;
    }

    private static async Task InsertAsync(
        SqliteConnection connection,
        System.Data.Common.DbTransaction transaction,
        ThreatRecord record,
        string hash,
        string timestamp,
        bool markRead,
        CancellationToken cancellationToken)
    {
        await using var command = BuildWriteCommand(connection, transaction, record, hash, timestamp);
        command.CommandText =
            """
            INSERT INTO threats(
                id, schema_version, title, vendor, product, severity, cvss, published,
                date_added, due_date, known_exploited, ransomware_associated,
                ransomware_status, description, recommended_action, notes, cwes_json,
                source, source_url, content_hash, first_seen_at, last_seen_at,
                last_changed_at, is_read, triage_status)
            VALUES(
                $id, $schemaVersion, $title, $vendor, $product, $severity, $cvss, $published,
                $dateAdded, $dueDate, $knownExploited, $ransomwareAssociated,
                $ransomwareStatus, $description, $recommendedAction, $notes, $cwesJson,
                $source, $sourceUrl, $hash, $timestamp, $timestamp, $timestamp,
                $isRead, $triageStatus);
            """;
        command.Parameters.AddWithValue("$isRead", markRead ? 1 : 0);
        command.Parameters.AddWithValue("$triageStatus", markRead ? "Backlog" : "New");
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task UpdateAsync(
        SqliteConnection connection,
        System.Data.Common.DbTransaction transaction,
        ThreatRecord record,
        string hash,
        string timestamp,
        CancellationToken cancellationToken)
    {
        await using var command = BuildWriteCommand(connection, transaction, record, hash, timestamp);
        command.CommandText =
            """
            UPDATE threats SET
                schema_version = $schemaVersion, title = $title, vendor = $vendor,
                product = $product, severity = COALESCE($severity, severity),
                cvss = COALESCE($cvss, cvss),
                published = COALESCE($published, published),
                date_added = $dateAdded, due_date = $dueDate,
                known_exploited = $knownExploited,
                ransomware_associated = $ransomwareAssociated,
                ransomware_status = $ransomwareStatus, description = $description,
                recommended_action = $recommendedAction, notes = $notes,
                cwes_json = $cwesJson, source = $source, source_url = $sourceUrl,
                content_hash = $hash, last_seen_at = $timestamp,
                last_changed_at = $timestamp, is_read = 0, triage_status = 'New'
            WHERE id = $id;
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static SqliteCommand BuildWriteCommand(
        SqliteConnection connection,
        System.Data.Common.DbTransaction transaction,
        ThreatRecord record,
        string hash,
        string timestamp)
    {
        var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.Parameters.AddWithValue("$id", record.Id);
        command.Parameters.AddWithValue("$schemaVersion", record.SchemaVersion);
        AddNullable(command, "$title", record.Title);
        AddNullable(command, "$vendor", record.Vendor);
        AddNullable(command, "$product", record.Product);
        AddNullable(command, "$severity", record.Severity);
        AddNullable(command, "$cvss", record.Cvss);
        AddNullable(command, "$published", record.Published);
        AddNullable(command, "$dateAdded", record.DateAdded);
        AddNullable(command, "$dueDate", record.DueDate);
        command.Parameters.AddWithValue("$knownExploited", record.KnownExploited ? 1 : 0);
        command.Parameters.AddWithValue("$ransomwareAssociated", record.RansomwareAssociated ? 1 : 0);
        AddNullable(command, "$ransomwareStatus", record.RansomwareStatus);
        AddNullable(command, "$description", record.Description);
        AddNullable(command, "$recommendedAction", record.RecommendedAction);
        AddNullable(command, "$notes", record.Notes);
        command.Parameters.AddWithValue("$cwesJson", JsonSerializer.Serialize(record.Cwes));
        AddNullable(command, "$source", record.Source);
        AddNullable(command, "$sourceUrl", record.SourceUrl);
        command.Parameters.AddWithValue("$hash", hash);
        command.Parameters.AddWithValue("$timestamp", timestamp);
        return command;
    }

    private static async Task TouchAsync(
        SqliteConnection connection,
        System.Data.Common.DbTransaction transaction,
        string id,
        string timestamp,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = "UPDATE threats SET last_seen_at = $timestamp WHERE id = $id;";
        command.Parameters.AddWithValue("$timestamp", timestamp);
        command.Parameters.AddWithValue("$id", id);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task UpsertSourceAsync(
        SqliteConnection connection,
        System.Data.Common.DbTransaction transaction,
        string threatId,
        string source,
        string? externalId,
        string? sourceUrl,
        string timestamp,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText =
            """
            INSERT INTO threat_sources(
                threat_id, source, external_id, source_url, first_seen_at, last_seen_at)
            VALUES($threatId, $source, $externalId, $sourceUrl, $timestamp, $timestamp)
            ON CONFLICT(threat_id, source) DO UPDATE SET
                external_id = excluded.external_id,
                source_url = excluded.source_url,
                last_seen_at = excluded.last_seen_at;
            """;
        command.Parameters.AddWithValue("$threatId", threatId);
        command.Parameters.AddWithValue("$source", source);
        AddNullable(command, "$externalId", externalId);
        AddNullable(command, "$sourceUrl", sourceUrl);
        command.Parameters.AddWithValue("$timestamp", timestamp);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddNullable(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    private static string ContentHash(ThreatRecord record)
    {
        // Only collector-owned fields participate. NVD enrichment, read state,
        // and future UI metadata must never make a CISA record appear changed.
        var json = JsonSerializer.Serialize(new
        {
            record.SchemaVersion,
            record.Id,
            record.Title,
            record.Vendor,
            record.Product,
            record.DateAdded,
            record.DueDate,
            record.KnownExploited,
            record.RansomwareAssociated,
            record.RansomwareStatus,
            record.Description,
            record.RecommendedAction,
            record.Notes,
            record.Cwes,
            record.Source,
            record.SourceUrl
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
    }

    private static ThreatRecord ReadRecord(SqliteDataReader reader) =>
        new()
        {
            SchemaVersion = reader.GetInt32(reader.GetOrdinal("schema_version")),
            Id = reader.GetString(reader.GetOrdinal("id")),
            Title = ReadNullableString(reader, "title"),
            Vendor = ReadNullableString(reader, "vendor"),
            Product = ReadNullableString(reader, "product"),
            Severity = ReadNullableString(reader, "severity"),
            Cvss = ReadNullableDouble(reader, "cvss"),
            Published = ReadNullableString(reader, "published"),
            DateAdded = ReadNullableString(reader, "date_added"),
            DueDate = ReadNullableString(reader, "due_date"),
            KnownExploited = reader.GetBoolean(reader.GetOrdinal("known_exploited")),
            RansomwareAssociated = reader.GetBoolean(reader.GetOrdinal("ransomware_associated")),
            RansomwareStatus = ReadNullableString(reader, "ransomware_status"),
            Description = ReadNullableString(reader, "description"),
            RecommendedAction = ReadNullableString(reader, "recommended_action"),
            Notes = ReadNullableString(reader, "notes"),
            Cwes = JsonSerializer.Deserialize<string[]>(
                reader.GetString(reader.GetOrdinal("cwes_json"))) ?? [],
            Source = ReadNullableString(reader, "source"),
            SourceUrl = ReadNullableString(reader, "source_url"),
            NvdStatus = ReadNullableString(reader, "nvd_status"),
            CvssVector = ReadNullableString(reader, "cvss_vector"),
            AttackVector = ReadNullableString(reader, "attack_vector"),
            AttackComplexity = ReadNullableString(reader, "attack_complexity"),
            PrivilegesRequired = ReadNullableString(reader, "privileges_required"),
            UserInteraction = ReadNullableString(reader, "user_interaction"),
            NvdLastModified = ReadNullableString(reader, "nvd_last_modified"),
            NvdEnrichedAt = ReadNullableString(reader, "nvd_enriched_at"),
            NvdReferences = ReadStringArray(reader, "nvd_references_json"),
            AffectedProducts = ReadStringArray(reader, "affected_products_json"),
            TriageStatus = ReadNullableString(reader, "triage_status") ?? "Backlog",
            SourceCount = reader.GetInt32(reader.GetOrdinal("source_count")),
            Sources = (ReadNullableString(reader, "source_names") ?? string.Empty)
                .Split('|', StringSplitOptions.RemoveEmptyEntries),
            FirstSeenAt = reader.GetString(reader.GetOrdinal("first_seen_at")),
            LastSeenAt = reader.GetString(reader.GetOrdinal("last_seen_at")),
            LastChangedAt = reader.GetString(reader.GetOrdinal("last_changed_at")),
            IsRead = reader.GetBoolean(reader.GetOrdinal("is_read")),
            IsSaved = reader.GetBoolean(reader.GetOrdinal("is_saved"))
        };

    private static string? ReadNullableString(SqliteDataReader reader, string name)
    {
        var ordinal = reader.GetOrdinal(name);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static double? ReadNullableDouble(SqliteDataReader reader, string name)
    {
        var ordinal = reader.GetOrdinal(name);
        return reader.IsDBNull(ordinal) ? null : reader.GetDouble(ordinal);
    }

    private static IReadOnlyList<string> ReadStringArray(SqliteDataReader reader, string name)
    {
        var value = ReadNullableString(reader, name);
        return value is null ? [] : JsonSerializer.Deserialize<string[]>(value) ?? [];
    }
}

using System.Text.Json;
using Microsoft.Data.Sqlite;
using ThreatBrief.Core.AI;
using ThreatBrief.Core.Interfaces;

namespace ThreatBrief.Data;

public sealed class SqliteAiAnalysisRepository(string databasePath) : IAiAnalysisRepository
{
    private readonly string _databasePath = Path.GetFullPath(databasePath);

    private string ConnectionString => new SqliteConnectionStringBuilder
    {
        DataSource = _databasePath,
        Mode = SqliteOpenMode.ReadWriteCreate,
        Cache = SqliteCacheMode.Shared,
        Pooling = false
    }.ToString();

    public async Task<StoredThreatAnalysis?> GetLatestAsync(
        string threatId,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT threat_id, input_fingerprint, provider, model, generated_at, analysis_json
            FROM ai_threat_analyses
            WHERE threat_id = $threatId
            ORDER BY generated_at DESC
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$threatId", threatId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new StoredThreatAnalysis
        {
            ThreatId = reader.GetString(0),
            InputFingerprint = reader.GetString(1),
            Provider = reader.GetString(2),
            Model = reader.GetString(3),
            GeneratedAt = reader.GetString(4),
            Analysis = JsonSerializer.Deserialize<ThreatAnalysis>(reader.GetString(5))
                ?? throw new InvalidDataException("Stored AI analysis is invalid.")
        };
    }

    public async Task SaveAsync(
        StoredThreatAnalysis analysis,
        CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO ai_threat_analyses(
                threat_id, input_fingerprint, provider, model, generated_at, analysis_json)
            VALUES($threatId, $fingerprint, $provider, $model, $generatedAt, $json);
            """;
        command.Parameters.AddWithValue("$threatId", analysis.ThreatId);
        command.Parameters.AddWithValue("$fingerprint", analysis.InputFingerprint);
        command.Parameters.AddWithValue("$provider", analysis.Provider);
        command.Parameters.AddWithValue("$model", analysis.Model);
        command.Parameters.AddWithValue("$generatedAt", analysis.GeneratedAt);
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(analysis.Analysis));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task InitializeAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)!);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            CREATE TABLE IF NOT EXISTS ai_threat_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id TEXT NOT NULL,
                input_fingerprint TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                analysis_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ai_threat_latest
                ON ai_threat_analyses(threat_id, generated_at DESC);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}

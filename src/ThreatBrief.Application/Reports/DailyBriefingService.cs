using System.Net;
using System.Text.Json;
using ThreatBrief.Core.Interfaces;
using ThreatBrief.Core.Models;
using ThreatBrief.Core.Priority;
using ThreatBrief.Core.Triage;
using ThreatBrief.Core.Watchlist;

namespace ThreatBrief.Application.Reports;

public sealed record BriefingExportResult(
    string MarkdownPath,
    string HtmlPath,
    string JsonPath);

public sealed class DailyBriefingService(
    IThreatRepository threats,
    IIntelligenceRepository intelligence,
    string dataRoot)
{
    public async Task<BriefingExportResult> GenerateAsync(
        CancellationToken cancellationToken = default)
    {
        var settings = await WatchlistSettings.LoadOrCreateAsync(dataRoot, cancellationToken);
        var records = await threats.QueryAsync(
            new ThreatQuery { Limit = 5000 },
            cancellationToken);
        var alerting = records
            .Where(record => AlertPolicy.IsAlerting(record, settings.AlertWindowDays))
            .Select(record => new
            {
                Record = record,
                Priority = ThreatPriorityScorer.Score(record, settings),
                Matches = settings.Match(record)
            })
            .OrderByDescending(item => item.Priority.Score)
            .ThenByDescending(item => item.Record.DateAdded)
            .ToArray();
        var activeIndicators = await intelligence.QueryIndicatorsAsync(
            activeOnly: true,
            limit: 5000,
            cancellationToken: cancellationToken);
        var recentReports = await intelligence.QueryReportsAsync(
            limit: 100,
            cancellationToken: cancellationToken);
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var dueSoon = records.Count(record =>
            TriageStates.IsActive(record.TriageStatus)
            && DateOnly.TryParse(record.DueDate, out var due)
            && due >= today
            && due <= today.AddDays(7));
        var overdue = records.Count(record =>
            TriageStates.IsActive(record.TriageStatus)
            && DateOnly.TryParse(record.DueDate, out var due)
            && due < today);

        var payload = new
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            settings.AlertWindowDays,
            Summary = new
            {
                Alerting = alerting.Length,
                Critical = alerting.Count(item => item.Priority.Tier == "CRITICAL"),
                Watchlist = alerting.Count(item => item.Matches.Count > 0),
                DueSoon = dueSoon,
                Overdue = overdue,
                ActiveIndicators = activeIndicators.Count,
                IntelligenceReports = recentReports.Count
            },
            Alerts = alerting.Take(100).Select(item => new
            {
                item.Record.Id,
                item.Record.Title,
                item.Record.Vendor,
                item.Record.Product,
                item.Record.DateAdded,
                item.Record.DueDate,
                item.Priority.Score,
                item.Priority.Tier,
                item.Priority.Reasons,
                WatchlistMatches = item.Matches,
                item.Record.Description,
                item.Record.RecommendedAction,
                item.Record.Sources
            })
        };

        var reportDirectory = Path.Combine(dataRoot, "reports");
        Directory.CreateDirectory(reportDirectory);
        var stamp = DateTime.UtcNow.ToString("yyyy-MM-dd");
        var markdownPath = Path.Combine(reportDirectory, $"ThreatBrief-Daily-{stamp}.md");
        var htmlPath = Path.Combine(reportDirectory, $"ThreatBrief-Daily-{stamp}.html");
        var jsonPath = Path.Combine(reportDirectory, $"ThreatBrief-Daily-{stamp}.json");
        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        var markdown = BuildMarkdown(payload.Summary, payload.Alerts);
        var html = BuildHtml(markdown);
        await File.WriteAllTextAsync(markdownPath, markdown, cancellationToken);
        await File.WriteAllTextAsync(htmlPath, html, cancellationToken);
        await File.WriteAllTextAsync(jsonPath, json, cancellationToken);
        return new BriefingExportResult(markdownPath, htmlPath, jsonPath);
    }

    private static string BuildMarkdown(dynamic summary, dynamic alerts)
    {
        var lines = new List<string>
        {
            "# ThreatBrief Daily Intelligence",
            string.Empty,
            $"Generated: {DateTimeOffset.UtcNow:O}",
            string.Empty,
            "## Current posture",
            string.Empty,
            $"- Alerting vulnerabilities: **{summary.Alerting}**",
            $"- Critical priority: **{summary.Critical}**",
            $"- Watchlist matches: **{summary.Watchlist}**",
            $"- Due this week: **{summary.DueSoon}**",
            $"- Overdue active work: **{summary.Overdue}**",
            $"- Active indicators: **{summary.ActiveIndicators}**",
            $"- Intelligence reports: **{summary.IntelligenceReports}**",
            string.Empty,
            "## Priority alerts",
            string.Empty
        };

        foreach (var item in alerts)
        {
            lines.Add($"### {item.Id} - {item.Title}");
            lines.Add(string.Empty);
            lines.Add($"**Priority:** {item.Tier} {item.Score}/100");
            lines.Add($"**Vendor/product:** {item.Vendor} / {item.Product}");
            lines.Add($"**Added:** {item.DateAdded}  **Due:** {item.DueDate}");
            lines.Add(string.Empty);
            lines.Add(item.Description ?? string.Empty);
            lines.Add(string.Empty);
            lines.Add($"**Required action:** {item.RecommendedAction}");
            lines.Add(string.Empty);
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string BuildHtml(string markdown)
    {
        var encoded = WebUtility.HtmlEncode(markdown);
        return
            $$"""
              <!doctype html>
              <html lang="en">
              <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>ThreatBrief Daily Intelligence</title>
                <style>
                  body { background:#0d0f13; color:#e4e7ec; font:16px/1.55 system-ui; margin:0 auto; max-width:980px; padding:36px; }
                  pre { white-space:pre-wrap; font:inherit; }
                </style>
              </head>
              <body><pre>{{encoded}}</pre></body>
              </html>
              """;
    }
}

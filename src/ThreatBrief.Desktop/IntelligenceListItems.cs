using ThreatBrief.Core.Intelligence;

namespace ThreatBrief.Desktop;

public sealed record ReportListItem(IntelligenceReport Report)
{
    public string Title => Report.Title;
    public string Source => Report.Source;
    public string? Date => Report.ModifiedAt ?? Report.PublishedAt;
    public string RelationshipSummary =>
        $"{Report.CveIds.Count} CVE link(s) • {Report.IndicatorCount} indicator(s)";
}

public sealed record IndicatorListItem(ThreatIndicator Indicator)
{
    public string Type => Indicator.Type.ToUpperInvariant();
    public string Value => Indicator.Value;
    public string Malware => Indicator.MalwareFamily ?? Indicator.ThreatType ?? string.Empty;
    public string Confidence => Indicator.Confidence is null ? "—" : $"{Indicator.Confidence}%";
    public string Sources => string.Join(", ", Indicator.Sources);
}

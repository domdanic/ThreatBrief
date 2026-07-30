using ThreatBrief.Core.Models;

namespace ThreatBrief.Application.Refresh;

public sealed record RefreshOutcome(
    string PowerShellEdition,
    string StandardOutput,
    ImportResult Import,
    int NvdEnriched,
    string? NvdWarning);

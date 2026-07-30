using ThreatBrief.Core.Models;
using ThreatBrief.Core.Triage;

namespace ThreatBrief.Core.Priority;

public static class AlertPolicy
{
    public static bool IsAlerting(
        ThreatRecord record,
        int alertWindowDays,
        DateTimeOffset? now = null)
    {
        if (TriageStates.IsTerminal(record.TriageStatus))
        {
            return false;
        }

        var referenceDate = GetReferenceDate(record);
        if (referenceDate is null)
        {
            return false;
        }

        var today = DateOnly.FromDateTime((now ?? DateTimeOffset.UtcNow).UtcDateTime);
        var cutoff = today.AddDays(-(Math.Clamp(alertWindowDays, 1, 3650) - 1));
        return referenceDate >= cutoff;
    }

    private static DateOnly? GetReferenceDate(ThreatRecord record)
    {
        // An old CVE changed by a source re-enters active triage based on the
        // change time. Reference-only backlog records age from CISA's date.
        if (TriageStates.IsActive(record.TriageStatus)
            && DateTimeOffset.TryParse(record.LastChangedAt, out var changedAt))
        {
            return DateOnly.FromDateTime(changedAt.UtcDateTime);
        }

        return DateOnly.TryParse(record.DateAdded, out var added) ? added : null;
    }
}


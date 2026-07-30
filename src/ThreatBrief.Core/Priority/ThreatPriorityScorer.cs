using ThreatBrief.Core.Models;
using ThreatBrief.Core.Watchlist;

namespace ThreatBrief.Core.Priority;

public static class ThreatPriorityScorer
{
    public static ThreatPriority Score(ThreatRecord record, WatchlistSettings watchlist)
    {
        var score = 0;
        var reasons = new List<string>();

        Add(record.KnownExploited, 35, "Confirmed active exploitation");
        Add(record.RansomwareAssociated, 25, "Known ransomware association");

        var matches = watchlist.Match(record);
        if (matches.Count > 0)
        {
            var points = Math.Min(25, 15 + (matches.Count * 3));
            score += points;
            reasons.Add($"Watchlist match: {string.Join(", ", matches)} (+{points})");
        }

        if (record.Cvss is >= 9)
        {
            Add(true, 15, $"Critical CVSS {record.Cvss:0.0}");
        }
        else if (record.Cvss is >= 7)
        {
            Add(true, 10, $"High CVSS {record.Cvss:0.0}");
        }
        else if (record.Cvss is >= 4)
        {
            Add(true, 5, $"Medium CVSS {record.Cvss:0.0}");
        }

        if (DateOnly.TryParse(record.DueDate, out var dueDate))
        {
            var days = dueDate.DayNumber - DateOnly.FromDateTime(DateTime.UtcNow).DayNumber;
            if (days < 0)
            {
                Add(true, 15, $"Remediation overdue by {-days} day(s)");
            }
            else if (days <= 7)
            {
                Add(true, 10, $"Remediation due in {days} day(s)");
            }
            else if (days <= 14)
            {
                Add(true, 5, $"Remediation due in {days} day(s)");
            }
        }

        Add(
            string.Equals(record.AttackVector, "NETWORK", StringComparison.OrdinalIgnoreCase),
            5,
            "Network attack vector");
        Add(
            string.Equals(record.PrivilegesRequired, "NONE", StringComparison.OrdinalIgnoreCase),
            5,
            "No privileges required");
        Add(
            string.Equals(record.UserInteraction, "NONE", StringComparison.OrdinalIgnoreCase),
            3,
            "No user interaction required");

        score = Math.Min(100, score);
        var tier = score switch
        {
            >= 75 => "CRITICAL",
            >= 55 => "HIGH",
            >= 35 => "MEDIUM",
            _ => "LOW"
        };
        return new ThreatPriority(score, tier, reasons);

        void Add(bool condition, int points, string reason)
        {
            if (!condition)
            {
                return;
            }

            score += points;
            reasons.Add($"{reason} (+{points})");
        }
    }
}


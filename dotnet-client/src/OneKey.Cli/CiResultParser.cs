using System.Text.Json;

namespace OneKey.Cli;

internal static class CiResultParser
{
    internal static (List<JsonElement> NewIssues, List<JsonElement> DroppedIssues, List<JsonElement> NewCves, List<string> DroppedCves)
        ParseCompareFirmware(JsonElement res)
    {
        var issues = res.GetProperty("compareFirmwareAnalyses").GetProperty("issues");
        var newIssues = issues.GetProperty("new").EnumerateArray().ToList();
        var droppedIssues = issues.GetProperty("dropped").EnumerateArray().ToList();

        var cves = res.GetProperty("compareFirmwareAnalyses").GetProperty("cveEntries");
        var newCves = cves.GetProperty("new").EnumerateArray().ToList();
        var droppedCves = cves.GetProperty("dropped")
            .EnumerateArray()
            .Select(el => el.GetProperty("id").GetString() ?? string.Empty)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .ToList();

        return (newIssues, droppedIssues, newCves, droppedCves);
    }

    internal static (List<JsonElement> NewIssues, List<JsonElement> NewCves) ParseLatestIssues(JsonElement res)
    {
        var firmware = res.GetProperty("firmware");
        var newIssues = firmware.GetProperty("latestIssues").EnumerateArray().ToList();
        var newCves = firmware.GetProperty("cveMatches")
            .EnumerateArray()
            .Select(match => match.GetProperty("cve"))
            .ToList();

        return (newIssues, newCves);
    }

    internal static List<Guid> ParseFirmwareTimeline(JsonElement res)
    {
        var timeline = res.GetProperty("firmware").GetProperty("product").GetProperty("firmwareTimeline");
        var firmwareIds = new List<Guid>();
        foreach (var item in timeline.EnumerateArray())
        {
            var idStr = item.GetProperty("firmware").GetProperty("id").GetString();
            if (Guid.TryParse(idStr, out var parsed))
            {
                firmwareIds.Add(parsed);
            }
        }

        return firmwareIds;
    }
}

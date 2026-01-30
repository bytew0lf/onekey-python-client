using System.Text.Json;
using OneKey.Cli;
using Xunit;

namespace OneKey.Cli.Tests;

public class CiResultParserTests
{
    [Fact]
    public void ParseCompareFirmware_ReturnsIssuesAndCves()
    {
        var json = """
        {
          "compareFirmwareAnalyses": {
            "issues": {
              "new": [{ "id": "i1", "type": "TYPE", "file": { "path": "file.c" }, "severity": "HIGH" }],
              "dropped": [{ "id": "i2", "type": "TYPE", "file": { "path": "file2.c" }, "severity": "LOW" }]
            },
            "cveEntries": {
              "new": [{ "id": "CVE-1", "severity": "HIGH", "description": "desc" }],
              "dropped": [{ "id": "CVE-2" }]
            }
          }
        }
        """;

        using var doc = JsonDocument.Parse(json);
        var res = CiResultParser.ParseCompareFirmware(doc.RootElement);

        Assert.Single(res.NewIssues);
        Assert.Single(res.DroppedIssues);
        Assert.Single(res.NewCves);
        Assert.Single(res.DroppedCves);
        Assert.Equal("CVE-2", res.DroppedCves[0]);
    }

    [Fact]
    public void ParseLatestIssues_ReturnsLatestIssuesAndCves()
    {
        var json = """
        {
          "firmware": {
            "latestIssues": [{ "id": "i1", "type": "TYPE", "file": { "path": "file.c" }, "severity": "HIGH" }],
            "cveMatches": [{ "cve": { "id": "CVE-9", "severity": "MEDIUM", "description": "desc" } }]
          }
        }
        """;

        using var doc = JsonDocument.Parse(json);
        var res = CiResultParser.ParseLatestIssues(doc.RootElement);

        Assert.Single(res.NewIssues);
        Assert.Single(res.NewCves);
        Assert.Equal("CVE-9", res.NewCves[0].GetProperty("id").GetString());
    }

    [Fact]
    public void ParseFirmwareTimeline_ReturnsIdsInOrder()
    {
        var json = """
        {
          "firmware": {
            "product": {
              "firmwareTimeline": [
                { "firmware": { "id": "11111111-1111-1111-1111-111111111111" } },
                { "firmware": { "id": "22222222-2222-2222-2222-222222222222" } }
              ]
            }
          }
        }
        """;

        using var doc = JsonDocument.Parse(json);
        var ids = CiResultParser.ParseFirmwareTimeline(doc.RootElement);

        Assert.Equal(2, ids.Count);
        Assert.Equal(Guid.Parse("11111111-1111-1111-1111-111111111111"), ids[0]);
        Assert.Equal(Guid.Parse("22222222-2222-2222-2222-222222222222"), ids[1]);
    }
}

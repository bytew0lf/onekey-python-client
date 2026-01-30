using System.Text.Json;
using OneKey.Cli;
using Xunit;

namespace OneKey.Cli.Tests;

public class ResultHandlerTests
{
    [Fact]
    public async Task GetResultAsync_WithPreviousFirmware_ReturnsCompareData()
    {
        var firmwareId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var previousId = Guid.Parse("22222222-2222-2222-2222-222222222222");

        var timelineJson = $@"
{{ ""firmware"": {{ ""product"": {{ ""firmwareTimeline"": [
    {{ ""firmware"": {{ ""id"": ""{firmwareId}"" }} }},
    {{ ""firmware"": {{ ""id"": ""{previousId}"" }} }}
]}}}}}}";

        var responses = new[]
        {
            """
            { "firmware": { "latestAnalysis": { "state": "DONE", "result": "COMPLETE" } } }
            """,
            timelineJson,
            """
            { "compareFirmwareAnalyses": {
                "issues": {
                  "new": [{ "id": "i1", "type": "TYPE", "file": { "path": "file.c" }, "severity": "HIGH" }],
                  "dropped": [{ "id": "i2", "type": "TYPE", "file": { "path": "file2.c" }, "severity": "LOW" }]
                },
                "cveEntries": {
                  "new": [{ "id": "CVE-1", "severity": "HIGH", "description": "desc" }],
                  "dropped": [{ "id": "CVE-2" }]
                }
            } }
            """
        };

        var client = new FakeOneKeyClient(responses);
        var handler = new ResultHandler(client, firmwareId, retryCount: 0, retryWait: 0, checkInterval: 0);

        var result = await handler.GetResultAsync();

        Assert.Single(result.NewIssues);
        Assert.Single(result.DroppedIssues);
        Assert.Single(result.NewCves);
        Assert.Single(result.DroppedCves);
        Assert.Equal(1, client.RefreshCount);
    }

    [Fact]
    public async Task GetResultAsync_NoPreviousFirmware_UsesLatestIssues()
    {
        var firmwareId = Guid.Parse("11111111-1111-1111-1111-111111111111");

        var noPreviousTimelineJson = $@"
{{ ""firmware"": {{ ""product"": {{ ""firmwareTimeline"": [
    {{ ""firmware"": {{ ""id"": ""{firmwareId}"" }} }}
]}}}}}}";

        var responses = new[]
        {
            """
            { "firmware": { "latestAnalysis": { "state": "DONE", "result": "COMPLETE" } } }
            """,
            noPreviousTimelineJson,
            """
            { "firmware": {
                "latestIssues": [{ "id": "i1", "type": "TYPE", "file": { "path": "file.c" }, "severity": "HIGH" }],
                "cveMatches": [{ "cve": { "id": "CVE-9", "severity": "MEDIUM", "description": "desc" } }]
            } }
            """
        };

        var client = new FakeOneKeyClient(responses);
        var handler = new ResultHandler(client, firmwareId, retryCount: 0, retryWait: 0, checkInterval: 0);

        var result = await handler.GetResultAsync();

        Assert.Single(result.NewIssues);
        Assert.Empty(result.DroppedIssues);
        Assert.Single(result.NewCves);
        Assert.Empty(result.DroppedCves);
        Assert.Equal(1, client.RefreshCount);
    }

    [Fact]
    public async Task GetResultAsync_AnalysisFailed_ThrowsExitCode2()
    {
        var firmwareId = Guid.Parse("11111111-1111-1111-1111-111111111111");

        var responses = new[]
        {
            """
            { "firmware": { "latestAnalysis": { "state": "DONE", "result": "FAILED" } } }
            """
        };

        var client = new FakeOneKeyClient(responses);
        var handler = new ResultHandler(client, firmwareId, retryCount: 0, retryWait: 0, checkInterval: 0);

        var ex = await Assert.ThrowsAsync<CliExitException>(() => handler.GetResultAsync());
        Assert.Equal(2, ex.ExitCode);
        Assert.Contains("Firmware analysis failed", ex.Message);
    }
}

internal sealed class FakeOneKeyClient : IOneKeyClient
{
    private readonly Queue<JsonDocument> _responses;

    public FakeOneKeyClient(IEnumerable<string> responses)
    {
        ApiUrl = new Uri("https://app.eu.onekey.com/api");
        _responses = new Queue<JsonDocument>(responses.Select(r => JsonDocument.Parse(r)));
    }

    public Uri ApiUrl { get; }

    public int RefreshCount { get; private set; }

    public Task RefreshTenantTokenAsync(CancellationToken ct = default)
    {
        RefreshCount++;
        return Task.CompletedTask;
    }

    public Task<JsonElement> QueryAsync(string query, object? variables, CancellationToken ct = default)
    {
        if (_responses.Count == 0)
        {
            throw new InvalidOperationException("No more queued responses.");
        }

        return Task.FromResult(_responses.Dequeue().RootElement);
    }
}

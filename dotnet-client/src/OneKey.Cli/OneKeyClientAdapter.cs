using System.Text.Json;
using OneKey.Client;

namespace OneKey.Cli;

internal sealed class OneKeyClientAdapter : IOneKeyClient
{
    private readonly OneKeyClient _client;

    public OneKeyClientAdapter(OneKeyClient client)
    {
        _client = client;
    }

    public Uri ApiUrl => _client.ApiUrl;

    public Task RefreshTenantTokenAsync(CancellationToken ct = default)
        => _client.RefreshTenantTokenAsync(ct);

    public Task<JsonElement> QueryAsync(string query, object? variables, CancellationToken ct = default)
        => _client.QueryAsync(query, variables, ct);
}

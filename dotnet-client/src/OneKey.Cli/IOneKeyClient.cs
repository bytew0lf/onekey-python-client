using System.Text.Json;

namespace OneKey.Cli;

internal interface IOneKeyClient
{
    Uri ApiUrl { get; }
    Task RefreshTenantTokenAsync(CancellationToken ct = default);
    Task<JsonElement> QueryAsync(string query, object? variables, CancellationToken ct = default);
}

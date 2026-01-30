using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace OneKey.Client;

public sealed class OneKeyClient
{
    private const string ClientId = "ONEKEY Python SDK";
    private const string TokenNamespace = "https://www.onekey.com/";

    private readonly HttpClient _http;
    private readonly Uri _baseUri;
    private SecurityKey? _idTokenSigningKey;
    private SecurityKey? _tenantTokenSigningKey;

    private LoginState _state = new();

    public static OneKeyClient Create(
        Uri apiUrl,
        ProxyOptions? proxyOptions = null,
        string? caBundlePath = null,
        bool disableTlsVerify = false)
    {
        var proxy = ProxyUtilities.BuildProxy(proxyOptions);
        return new OneKeyClient(apiUrl, caBundlePath, disableTlsVerify, proxy);
    }

    public OneKeyClient(
        Uri apiUrl,
        string? caBundlePath = null,
        bool disableTlsVerify = false,
        IWebProxy? proxy = null)
    {
        _baseUri = apiUrl;

        var handler = new HttpClientHandler
        {
            Proxy = proxy,
            UseProxy = proxy != null
        };

        if (disableTlsVerify)
        {
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }
        else
        {
            var caPathToUse = caBundlePath ?? TryFindDefaultCaBundlePath();
            if (caBundlePath is not null && !File.Exists(caBundlePath))
            {
                throw new InvalidCaBundle();
            }

            if (caPathToUse is not null && File.Exists(caPathToUse))
            {
                var caCerts = LoadCaCertificates(caPathToUse);
                handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                    ValidateWithCustomRoot(cert, caCerts);
            }
        }

        _http = new HttpClient(handler) { BaseAddress = _baseUri };
    }

    public Uri ApiUrl => _baseUri;

    public async Task LoginAsync(string email, string password, CancellationToken ct = default)
    {
        var nonce = Guid.NewGuid().ToString("N");
        var payload = new
        {
            email,
            password,
            client_id = ClientId,
            nonce
        };

        var json = await PostJsonAsync("/authorize", payload, ct);
        var idToken = json.GetProperty("id_token").GetString()!;

        var signingKey = await GetIdTokenSigningKeyAsync(ct);
        var principal = VerifyToken(idToken, signingKey, email, nonce);
        _state.Email = email;
        _state.RawIdToken = idToken;
        _state.Tenants = ParseTenantsFromClaims(principal);
    }

    public async Task UseTokenAsync(string token, CancellationToken ct = default)
    {
        var parts = token.Split('/', 2);
        if (parts.Length != 2) throw new InvalidApiToken();

        _state.RawTenantToken = token;

        var selfQuery = QueryLoader.Load("get_self.graphql");
        var response = await QueryAsync(selfQuery, null, ct);

        var tenantId = Guid.Parse(parts[0]);
        var tenantName = response.GetProperty("tenant").GetProperty("name").GetString()!;
        _state.Tenant = new Tenant(tenantId, tenantName);
        _state.Tenants = new Dictionary<string, Tenant> { [tenantName] = _state.Tenant };
    }

    public async Task UseTenantAsync(Tenant tenant, CancellationToken ct = default)
    {
        RequireLoggedIn();
        var nonce = Guid.NewGuid().ToString("N");

        var payload = new
        {
            id_token = _state.RawIdToken,
            client_id = ClientId,
            tenant_id = tenant.Id.ToString(),
            nonce
        };

        var json = await PostJsonAsync("/token", payload, ct);
        var tenantToken = json.GetProperty("tenant_token").GetString()!;

        var signingKey = await GetTenantTokenSigningKeyAsync(ct);
        VerifyToken(tenantToken, signingKey, _state.Email ?? string.Empty, nonce);
        _state.RawTenantToken = tenantToken;
        _state.Tenant = tenant;
    }

    public async Task RefreshTenantTokenAsync(CancellationToken ct = default)
    {
        if (_state.RawIdToken is not null && _state.Tenant is not null)
        {
            await UseTenantAsync(_state.Tenant, ct);
        }
    }

    public Tenant GetTenant(string name)
    {
        RequireLoggedIn();
        return _state.Tenants![name];
    }

    public IReadOnlyCollection<Tenant> GetAllTenants()
    {
        RequireLoggedIn();
        return _state.Tenants!.Values;
    }

    public Dictionary<string, string> GetAuthHeaders()
    {
        RequireTenant();
        return new Dictionary<string, string> { ["Authorization"] = "Bearer " + _state.RawTenantToken };
    }

    public async Task<JsonElement> QueryAsync(string query, object? variables, CancellationToken ct = default)
    {
        RequireTenant();
        var payload = new { query, variables };
        var json = await PostJsonAsync("/graphql", payload, ct, auth: true);
        if (json.TryGetProperty("errors", out var errors))
            throw new QueryError(errors.GetRawText());
        return json.GetProperty("data");
    }

    public async Task<JsonElement> UploadFirmwareAsync(
        FirmwareMetadata metadata,
        string path,
        bool enableMonitoring,
        CancellationToken ct = default)
    {
        RequireTenant();

        var variables = new
        {
            firmware = new
            {
                name = metadata.Name,
                version = metadata.Version,
                releaseDate = metadata.ReleaseDate,
                notes = metadata.Notes,
                enableMonitoring,
                analysisConfigurationId = metadata.AnalysisConfigurationId.ToString()
            },
            vendorName = metadata.VendorName,
            productName = metadata.ProductName,
            productCategory = metadata.ProductCategory,
            productGroupID = metadata.ProductGroupId.ToString()
        };

        var uploadMutation = QueryLoader.Load("create_firmware_upload.graphql");
        var res = await QueryAsync(uploadMutation, variables, ct);

        var uploadUrl = res.GetProperty("createFirmwareUpload").GetProperty("uploadUrl").GetString()!;
        using var content = new MultipartFormDataContent();
        using var file = File.OpenRead(path);
        var fileContent = new StreamContent(file);
        content.Add(fileContent, "firmware", Path.GetFileName(path));

        using var request = new HttpRequestMessage(HttpMethod.Post, uploadUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _state.RawTenantToken);
        request.Content = content;

        var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var responseBody = await response.Content.ReadAsStringAsync(ct);
        return JsonDocument.Parse(responseBody).RootElement;
    }

    public async Task<Dictionary<string, Guid>> GetProductGroupsAsync(CancellationToken ct = default)
    {
        var productGroupsQuery = QueryLoader.Load("get_product_groups.graphql");
        var response = await QueryAsync(productGroupsQuery, null, ct);
        var groups = new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase);
        foreach (var pg in response.GetProperty("allProductGroups").EnumerateArray())
        {
            var id = Guid.Parse(pg.GetProperty("id").GetString()!);
            var name = pg.GetProperty("name").GetString()!;
            groups[name] = id;
        }

        return groups;
    }

    public async Task<Dictionary<string, Guid>> GetAnalysisConfigurationsAsync(CancellationToken ct = default)
    {
        var analysisConfigurationsQuery = QueryLoader.Load("get_analysis_configurations.graphql");
        var response = await QueryAsync(analysisConfigurationsQuery, null, ct);
        var configs = new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase);
        foreach (var config in response.GetProperty("allAnalysisConfigurations").EnumerateArray())
        {
            var id = Guid.Parse(config.GetProperty("id").GetString()!);
            var name = config.GetProperty("name").GetString()!;
            configs[name] = id;
        }

        return configs;
    }

    internal static Dictionary<string, Tenant> ParseTenantsFromClaims(ClaimsPrincipal principal)
    {
        try
        {
            var claim = principal.Claims.FirstOrDefault(c => c.Type == TokenNamespace + "tenants");
            if (claim is null)
            {
                return new Dictionary<string, Tenant>(StringComparer.OrdinalIgnoreCase);
            }

            using var doc = JsonDocument.Parse(claim.Value);
            var tenants = new Dictionary<string, Tenant>(StringComparer.OrdinalIgnoreCase);
            foreach (var tenantEl in doc.RootElement.EnumerateArray())
            {
                var id = tenantEl.GetProperty("id").GetString();
                var name = tenantEl.GetProperty("name").GetString();
                if (id is null || name is null) continue;
                if (Guid.TryParse(id, out var guid))
                {
                    tenants[name] = new Tenant(guid, name);
                }
            }

            return tenants;
        }
        catch
        {
            return new Dictionary<string, Tenant>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private async Task<JsonElement> PostJsonAsync(
        string path, object payload, CancellationToken ct, bool auth = false)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path);
        if (auth) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _state.RawTenantToken);

        var json = JsonSerializer.Serialize(payload);
        req.Content = new StringContent(json, Encoding.UTF8, "application/json");

        var res = await _http.SendAsync(req, ct);
        res.EnsureSuccessStatusCode();
        var body = await res.Content.ReadAsStringAsync(ct);
        return JsonDocument.Parse(body).RootElement;
    }

    private void RequireLoggedIn()
    {
        if (_state.Tenants is null) throw new NotLoggedIn();
    }

    private void RequireTenant()
    {
        if (_state.RawTenantToken is null) throw new TenantNotSelected();
    }

    private async Task<SecurityKey> GetIdTokenSigningKeyAsync(CancellationToken ct)
    {
        _idTokenSigningKey ??= await LoadSigningKeyAsync("id-token-public-key", ct);
        return _idTokenSigningKey;
    }

    private async Task<SecurityKey> GetTenantTokenSigningKeyAsync(CancellationToken ct)
    {
        _tenantTokenSigningKey ??= await LoadSigningKeyAsync("tenant-token-public-key", ct);
        return _tenantTokenSigningKey;
    }

    private async Task<SecurityKey> LoadSigningKeyAsync(string keyName, CancellationToken ct)
    {
        using var response = await _http.GetAsync($"/{keyName}.pem", ct);
        response.EnsureSuccessStatusCode();
        var pem = await response.Content.ReadAsStringAsync(ct);

        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return new RsaSecurityKey(rsa);
    }

    private static ClaimsPrincipal VerifyToken(string rawToken, SecurityKey signingKey, string email, string nonce)
    {
        var handler = new JwtSecurityTokenHandler();
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = TokenNamespace,
            ValidateAudience = true,
            ValidAudience = ClientId,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2)
        };

        var principal = handler.ValidateToken(rawToken, parameters, out _);
        var subject = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? principal.FindFirst("sub")?.Value;
        if (!string.Equals(subject, email, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityTokenValidationException("Token subject does not match email.");
        }

        var nonceClaim = principal.FindFirst("nonce")?.Value;
        if (!string.Equals(nonceClaim, nonce, StringComparison.Ordinal))
        {
            throw new SecurityTokenValidationException("Token nonce is invalid.");
        }

        return principal;
    }

    private static string? TryFindDefaultCaBundlePath()
    {
        var candidate = Path.Combine(AppContext.BaseDirectory, "Keys", "ca.pem");
        return File.Exists(candidate) ? candidate : null;
    }

    private static X509Certificate2Collection LoadCaCertificates(string path)
    {
        var collection = new X509Certificate2Collection();
        collection.ImportFromPemFile(path);
        if (collection.Count == 0)
        {
            throw new InvalidCaBundle();
        }

        return collection;
    }

    private static bool ValidateWithCustomRoot(X509Certificate? certificate, X509Certificate2Collection caCerts)
    {
        if (certificate is null)
        {
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(caCerts);
        chain.ChainPolicy.ExtraStore.AddRange(caCerts);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        return chain.Build(new X509Certificate2(certificate));
    }

    private sealed class LoginState
    {
        public string? Email { get; set; }
        public Dictionary<string, Tenant>? Tenants { get; set; }
        public string? RawIdToken { get; set; }
        public string? RawTenantToken { get; set; }
        public Tenant? Tenant { get; set; }
    }
}

public sealed record ProxyOptions(
    string HostOrUrl,
    int Port,
    string? Username = null,
    string? Password = null,
    string? BypassList = null);

public static class ProxyUtilities
{
    public static IWebProxy? BuildProxy(ProxyOptions? options)
    {
        if (options is null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(options.HostOrUrl))
        {
            throw new ArgumentException("Proxy host or URL must be provided.", nameof(options));
        }

        if (options.Port <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Proxy port must be a positive integer.");
        }

        string scheme;
        string host;
        if (Uri.TryCreate(options.HostOrUrl, UriKind.Absolute, out var parsed))
        {
            scheme = parsed.Scheme;
            host = parsed.Host;
        }
        else
        {
            scheme = "http";
            host = options.HostOrUrl;
        }

        var proxy = new WebProxy(new Uri($"{scheme}://{host}:{options.Port}"));
        if (!string.IsNullOrWhiteSpace(options.Username) || !string.IsNullOrWhiteSpace(options.Password))
        {
            proxy.Credentials = new NetworkCredential(options.Username, options.Password);
        }

        if (!string.IsNullOrWhiteSpace(options.BypassList))
        {
            proxy.BypassList = options.BypassList
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        return proxy;
    }
}

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Xml;
using OneKey.Cli;
using OneKey.Client;

var root = new RootCommand("ONEKEY CLI");

var apiUrlOpt = new Option<string>(
    name: "--api-url",
    getDefaultValue: () => "https://app.eu.onekey.com/api",
    description: "ONEKEY platform API endpoint");

var disableTlsOpt = new Option<bool>(
    "--disable-tls-verify",
    "Disable verifying server certificate, use only for testing");

var emailOpt = new Option<string?>("--email", "Email to authenticate on the ONEKEY platform");
var passwordOpt = new Option<string?>("--password", "Password to authenticate on the ONEKEY platform");
var tenantOpt = new Option<string?>("--tenant", "Tenant name on ONEKEY platform");
var tokenOpt = new Option<string?>("--token", "API token to authenticate on the ONEKEY platform");

var proxyUrlOpt = new Option<string?>("--proxy-url", "Proxy host or URL (no port)");
var proxyPortOpt = new Option<int?>("--proxy-port", "Proxy port");
var proxyUserOpt = new Option<string?>("--proxy-user");
var proxyPassOpt = new Option<string?>("--proxy-password");
var proxyBypassOpt = new Option<string?>("--proxy-bypass", "Comma-separated bypass list");

root.AddGlobalOption(apiUrlOpt);
root.AddGlobalOption(disableTlsOpt);
root.AddGlobalOption(emailOpt);
root.AddGlobalOption(passwordOpt);
root.AddGlobalOption(tenantOpt);
root.AddGlobalOption(tokenOpt);
root.AddGlobalOption(proxyUrlOpt);
root.AddGlobalOption(proxyPortOpt);
root.AddGlobalOption(proxyUserOpt);
root.AddGlobalOption(proxyPassOpt);
root.AddGlobalOption(proxyBypassOpt);

root.AddCommand(BuildListTenantsCommand(
    apiUrlOpt,
    disableTlsOpt,
    emailOpt,
    passwordOpt,
    tenantOpt,
    tokenOpt,
    proxyUrlOpt,
    proxyPortOpt,
    proxyUserOpt,
    proxyPassOpt,
    proxyBypassOpt));

root.AddCommand(BuildGetTenantTokenCommand(
    apiUrlOpt,
    disableTlsOpt,
    emailOpt,
    passwordOpt,
    tenantOpt,
    tokenOpt,
    proxyUrlOpt,
    proxyPortOpt,
    proxyUserOpt,
    proxyPassOpt,
    proxyBypassOpt));

root.AddCommand(BuildUploadFirmwareCommand(
    apiUrlOpt,
    disableTlsOpt,
    emailOpt,
    passwordOpt,
    tenantOpt,
    tokenOpt,
    proxyUrlOpt,
    proxyPortOpt,
    proxyUserOpt,
    proxyPassOpt,
    proxyBypassOpt));

root.AddCommand(BuildCiResultCommand(
    apiUrlOpt,
    disableTlsOpt,
    emailOpt,
    passwordOpt,
    tenantOpt,
    tokenOpt,
    proxyUrlOpt,
    proxyPortOpt,
    proxyUserOpt,
    proxyPassOpt,
    proxyBypassOpt));

return await root.InvokeAsync(args);

static Command BuildListTenantsCommand(
    Option<string> apiUrlOpt,
    Option<bool> disableTlsOpt,
    Option<string?> emailOpt,
    Option<string?> passwordOpt,
    Option<string?> tenantOpt,
    Option<string?> tokenOpt,
    Option<string?> proxyUrlOpt,
    Option<int?> proxyPortOpt,
    Option<string?> proxyUserOpt,
    Option<string?> proxyPassOpt,
    Option<string?> proxyBypassOpt)
{
    var command = new Command("list-tenants", "List available tenants");
    command.SetHandler(async ctx =>
        {
            try
            {
                var globals = ReadGlobals(
                    ctx.ParseResult,
                    apiUrlOpt,
                    disableTlsOpt,
                    emailOpt,
                    passwordOpt,
                    tenantOpt,
                    tokenOpt,
                    proxyUrlOpt,
                    proxyPortOpt,
                    proxyUserOpt,
                    proxyPassOpt,
                    proxyBypassOpt);
                var client = await CreateClientAsync(
                    globals.ApiUrl,
                    globals.DisableTlsVerify,
                    globals.Email,
                    globals.Password,
                    globals.TenantName,
                    globals.Token,
                    globals.ProxyUrl,
                    globals.ProxyPort,
                    globals.ProxyUser,
                    globals.ProxyPassword,
                    globals.ProxyBypass,
                    requireTenant: false,
                    CancellationToken.None);

                foreach (var tenant in client.GetAllTenants())
                {
                    Console.WriteLine($"{tenant.Name} ({tenant.Id})");
                }
            }
            catch (CliExitException ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = ex.ExitCode;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = 1;
            }
        });

    return command;
}

static Command BuildGetTenantTokenCommand(
    Option<string> apiUrlOpt,
    Option<bool> disableTlsOpt,
    Option<string?> emailOpt,
    Option<string?> passwordOpt,
    Option<string?> tenantOpt,
    Option<string?> tokenOpt,
    Option<string?> proxyUrlOpt,
    Option<int?> proxyPortOpt,
    Option<string?> proxyUserOpt,
    Option<string?> proxyPassOpt,
    Option<string?> proxyBypassOpt)
{
    var command = new Command("get-tenant-token", "Get tenant specific Bearer token");
    command.SetHandler(async ctx =>
        {
            try
            {
                var globals = ReadGlobals(
                    ctx.ParseResult,
                    apiUrlOpt,
                    disableTlsOpt,
                    emailOpt,
                    passwordOpt,
                    tenantOpt,
                    tokenOpt,
                    proxyUrlOpt,
                    proxyPortOpt,
                    proxyUserOpt,
                    proxyPassOpt,
                    proxyBypassOpt);
                var client = await CreateClientAsync(
                    globals.ApiUrl,
                    globals.DisableTlsVerify,
                    globals.Email,
                    globals.Password,
                    globals.TenantName,
                    globals.Token,
                    globals.ProxyUrl,
                    globals.ProxyPort,
                    globals.ProxyUser,
                    globals.ProxyPassword,
                    globals.ProxyBypass,
                    requireTenant: true,
                    CancellationToken.None);

                var headers = client.GetAuthHeaders();
                Console.WriteLine(JsonSerializer.Serialize(headers));
            }
            catch (CliExitException ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = ex.ExitCode;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = 1;
            }
        });

    return command;
}

static Command BuildUploadFirmwareCommand(
    Option<string> apiUrlOpt,
    Option<bool> disableTlsOpt,
    Option<string?> emailOpt,
    Option<string?> passwordOpt,
    Option<string?> tenantOpt,
    Option<string?> tokenOpt,
    Option<string?> proxyUrlOpt,
    Option<int?> proxyPortOpt,
    Option<string?> proxyUserOpt,
    Option<string?> proxyPassOpt,
    Option<string?> proxyBypassOpt)
{
    var command = new Command("upload-firmware", "Upload a firmware to the ONEKEY platform");

    var productOpt = new Option<string>("--product", "Product name to add the firmware") { IsRequired = true };
    var vendorOpt = new Option<string>("--vendor", "Vendor name to add the firmware") { IsRequired = true };
    var productGroupOpt = new Option<string>("--product-group", () => "Default", "Product group name to add the firmware");
    var analysisConfigOpt = new Option<string>("--analysis-configuration", () => "Default", "Analysis configuration name");
    var versionOpt = new Option<string?>("--version", "Firmware version");
    var nameOpt = new Option<string?>("--name", "Firmware name");
    var filenameArg = new Argument<FileInfo>("filename");
    filenameArg.ExistingOnly();

    command.AddOption(productOpt);
    command.AddOption(vendorOpt);
    command.AddOption(productGroupOpt);
    command.AddOption(analysisConfigOpt);
    command.AddOption(versionOpt);
    command.AddOption(nameOpt);
    command.AddArgument(filenameArg);

    command.SetHandler(async ctx =>
        {
            try
            {
                var globals = ReadGlobals(
                    ctx.ParseResult,
                    apiUrlOpt,
                    disableTlsOpt,
                    emailOpt,
                    passwordOpt,
                    tenantOpt,
                    tokenOpt,
                    proxyUrlOpt,
                    proxyPortOpt,
                    proxyUserOpt,
                    proxyPassOpt,
                    proxyBypassOpt);
                var product = ctx.ParseResult.GetValueForOption(productOpt)!;
                var vendor = ctx.ParseResult.GetValueForOption(vendorOpt)!;
                var productGroup = ctx.ParseResult.GetValueForOption(productGroupOpt)!;
                var analysisConfiguration = ctx.ParseResult.GetValueForOption(analysisConfigOpt)!;
                var version = ctx.ParseResult.GetValueForOption(versionOpt);
                var name = ctx.ParseResult.GetValueForOption(nameOpt);
                var filename = ctx.ParseResult.GetValueForArgument(filenameArg)!;

                var client = await CreateClientAsync(
                    globals.ApiUrl,
                    globals.DisableTlsVerify,
                    globals.Email,
                    globals.Password,
                    globals.TenantName,
                    globals.Token,
                    globals.ProxyUrl,
                    globals.ProxyPort,
                    globals.ProxyUser,
                    globals.ProxyPassword,
                    globals.ProxyBypass,
                    requireTenant: true,
                    CancellationToken.None);

                var productGroups = await client.GetProductGroupsAsync();
                if (!productGroups.TryGetValue(productGroup, out var productGroupId))
                {
                    Console.Error.WriteLine($"Missing product group: {productGroup}");
                    Console.Error.WriteLine("Available product groups:");
                    foreach (var pg in productGroups.Keys)
                    {
                        Console.Error.WriteLine($"- {pg}");
                    }
                    Environment.ExitCode = 10;
                    return;
                }

                var configs = await client.GetAnalysisConfigurationsAsync();
                if (!configs.TryGetValue(analysisConfiguration, out var configId))
                {
                    Console.Error.WriteLine($"Missing analysis configuration {analysisConfiguration}");
                    Console.Error.WriteLine("Available analysis configurations:");
                    foreach (var config in configs.Keys)
                    {
                        Console.Error.WriteLine($"- {config}");
                    }
                    Environment.ExitCode = 12;
                    return;
                }

                var firmwareName = name ?? (version is null
                    ? $"{vendor}-{product}-{filename.Name}"
                    : $"{vendor}-{product}-{version}");

                var metadata = new FirmwareMetadata(
                    firmwareName,
                    vendor,
                    product,
                    productGroupId,
                    configId,
                    version);

                var response = await client.UploadFirmwareAsync(metadata, filename.FullName, enableMonitoring: false);
                if (response.TryGetProperty("id", out var id))
                {
                    Console.WriteLine(id.GetString());
                }
                else
                {
                    Console.WriteLine(response.GetRawText());
                }
            }
            catch (CliExitException ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = ex.ExitCode;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = 11;
            }
        });

    return command;
}

static Command BuildCiResultCommand(
    Option<string> apiUrlOpt,
    Option<bool> disableTlsOpt,
    Option<string?> emailOpt,
    Option<string?> passwordOpt,
    Option<string?> tenantOpt,
    Option<string?> tokenOpt,
    Option<string?> proxyUrlOpt,
    Option<int?> proxyPortOpt,
    Option<string?> proxyUserOpt,
    Option<string?> proxyPassOpt,
    Option<string?> proxyBypassOpt)
{
    var command = new Command("ci-result", "Fetch analysis results for CI");

    var firmwareIdOpt = new Option<Guid>("--firmware-id", "Firmware ID") { IsRequired = true };
    var exitCodeOpt = new Option<int>("--exit-code-on-new-finding", () => 1, "Exit code when new findings are identified");
    var checkIntervalOpt = new Option<int>("--check-interval", () => 60, "Wait time between checking for result");
    var retryCountOpt = new Option<int>("--retry-count", () => 10, "Number of times to retry fetching results due to communication problem");
    var retryWaitOpt = new Option<int>("--retry-wait", () => 60, "Wait time between retries due to communication problem");
    var junitPathOpt = new Option<FileInfo?>("--junit-path", "File to export JUNIT xml");

    command.AddOption(firmwareIdOpt);
    command.AddOption(exitCodeOpt);
    command.AddOption(checkIntervalOpt);
    command.AddOption(retryCountOpt);
    command.AddOption(retryWaitOpt);
    command.AddOption(junitPathOpt);

    command.SetHandler(async ctx =>
        {
            try
            {
                var globals = ReadGlobals(
                    ctx.ParseResult,
                    apiUrlOpt,
                    disableTlsOpt,
                    emailOpt,
                    passwordOpt,
                    tenantOpt,
                    tokenOpt,
                    proxyUrlOpt,
                    proxyPortOpt,
                    proxyUserOpt,
                    proxyPassOpt,
                    proxyBypassOpt);
                var firmwareId = ctx.ParseResult.GetValueForOption(firmwareIdOpt);
                var exitCodeOnNewFinding = ctx.ParseResult.GetValueForOption(exitCodeOpt);
                var checkInterval = ctx.ParseResult.GetValueForOption(checkIntervalOpt);
                var retryCount = ctx.ParseResult.GetValueForOption(retryCountOpt);
                var retryWait = ctx.ParseResult.GetValueForOption(retryWaitOpt);
                var junitPath = ctx.ParseResult.GetValueForOption(junitPathOpt);

                var client = await CreateClientAsync(
                    globals.ApiUrl,
                    globals.DisableTlsVerify,
                    globals.Email,
                    globals.Password,
                    globals.TenantName,
                    globals.Token,
                    globals.ProxyUrl,
                    globals.ProxyPort,
                    globals.ProxyUser,
                    globals.ProxyPassword,
                    globals.ProxyBypass,
                    requireTenant: true,
                    CancellationToken.None);

                var clientAdapter = new OneKeyClientAdapter(client);
                var handler = new ResultHandler(clientAdapter, firmwareId, retryCount, retryWait, checkInterval);
                var result = await handler.GetResultAsync();

                if (junitPath is not null)
                {
                    WriteJUnitXml(result, clientAdapter, firmwareId, junitPath.FullName);
                }

                Environment.ExitCode = result.NewIssues.Count > 0 || result.NewCves.Count > 0
                    ? exitCodeOnNewFinding
                    : 0;
            }
            catch (CliExitException ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = ex.ExitCode;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = 10;
            }
        });

    return command;
}

static GlobalOptions ReadGlobals(
    ParseResult result,
    Option<string> apiUrlOpt,
    Option<bool> disableTlsOpt,
    Option<string?> emailOpt,
    Option<string?> passwordOpt,
    Option<string?> tenantOpt,
    Option<string?> tokenOpt,
    Option<string?> proxyUrlOpt,
    Option<int?> proxyPortOpt,
    Option<string?> proxyUserOpt,
    Option<string?> proxyPassOpt,
    Option<string?> proxyBypassOpt)
{
    return new GlobalOptions(
        result.GetValueForOption(apiUrlOpt)!,
        result.GetValueForOption(disableTlsOpt),
        result.GetValueForOption(emailOpt),
        result.GetValueForOption(passwordOpt),
        result.GetValueForOption(tenantOpt),
        result.GetValueForOption(tokenOpt),
        result.GetValueForOption(proxyUrlOpt),
        result.GetValueForOption(proxyPortOpt),
        result.GetValueForOption(proxyUserOpt),
        result.GetValueForOption(proxyPassOpt),
        result.GetValueForOption(proxyBypassOpt));
}

static async Task<OneKeyClient> CreateClientAsync(
    string apiUrl,
    bool disableTlsVerify,
    string? email,
    string? password,
    string? tenantName,
    string? token,
    string? proxyUrl,
    int? proxyPort,
    string? proxyUser,
    string? proxyPassword,
    string? proxyBypass,
    bool requireTenant,
    CancellationToken ct)
{
    CliAuth.ValidateAuthInputs(email, password, tenantName, token);

    var proxyOptions = BuildProxyOptions(proxyUrl, proxyPort, proxyUser, proxyPassword, proxyBypass);
    var client = OneKeyClient.Create(new Uri(apiUrl), proxyOptions, disableTlsVerify: disableTlsVerify);

    if (!string.IsNullOrWhiteSpace(token))
    {
        await LoginWithTokenAsync(client, token, apiUrl, ct);
        return client;
    }

    await LoginWithEmailAsync(client, email!, password!, tenantName, apiUrl, requireTenant, ct);
    return client;
}

static async Task LoginWithEmailAsync(
    OneKeyClient client,
    string email,
    string password,
    string? tenantName,
    string apiUrl,
    bool requireTenant,
    CancellationToken ct)
{
    try
    {
        await client.LoginAsync(email, password, ct);
    }
    catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
    {
        throw new CliExitException(1, $"Authentication failed on {email} @ {apiUrl}");
    }
    catch (HttpRequestException ex)
    {
        throw new CliExitException(2, $"Error connecting to ONEKEY platform: '{apiUrl}', error: {ex.StatusCode}");
    }

    if (!requireTenant)
    {
        return;
    }

    if (string.IsNullOrWhiteSpace(tenantName))
    {
        throw new CliExitException(
            1,
            "Invalid authentication details, specify email, password and tenant, if token is not specified!");
    }

    Tenant tenant;
    try
    {
        tenant = client.GetTenant(tenantName);
    }
    catch (KeyNotFoundException)
    {
        Console.Error.WriteLine($"Invalid tenant: {tenantName}");
        var tenants = client.GetAllTenants();
        Console.Error.WriteLine("Available tenants:");
        foreach (var t in tenants)
        {
            Console.Error.WriteLine($"- {t.Name} ({t.Id})");
        }
        throw new CliExitException(3, "Tenant not found.");
    }

    await client.UseTenantAsync(tenant, ct);
}

static async Task LoginWithTokenAsync(
    OneKeyClient client,
    string token,
    string apiUrl,
    CancellationToken ct)
{
    try
    {
        await client.UseTokenAsync(token, ct);
    }
    catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
    {
        throw new CliExitException(1, $"Authentication failed with token on {apiUrl}");
    }
    catch (HttpRequestException ex)
    {
        throw new CliExitException(2, $"Error connecting to ONEKEY platform: '{apiUrl}', error: {ex.StatusCode}");
    }
}

static ProxyOptions? BuildProxyOptions(
    string? proxyUrl,
    int? proxyPort,
    string? proxyUser,
    string? proxyPassword,
    string? proxyBypass)
{
    proxyUrl ??= Environment.GetEnvironmentVariable("ONEKEY_PROXY_URL");
    proxyUser ??= Environment.GetEnvironmentVariable("ONEKEY_PROXY_USER");
    proxyPassword ??= Environment.GetEnvironmentVariable("ONEKEY_PROXY_PASSWORD");
    proxyBypass ??= Environment.GetEnvironmentVariable("ONEKEY_PROXY_BYPASS");

    if (proxyPort is null)
    {
        var envPort = Environment.GetEnvironmentVariable("ONEKEY_PROXY_PORT");
        if (int.TryParse(envPort, out var parsedPort))
        {
            proxyPort = parsedPort;
        }
    }

    if (string.IsNullOrWhiteSpace(proxyUrl) && proxyPort is null)
    {
        return null;
    }

    if (string.IsNullOrWhiteSpace(proxyUrl) || proxyPort is null)
    {
        throw new CliExitException(1, "Both --proxy-url and --proxy-port must be provided.");
    }

    return new ProxyOptions(proxyUrl, proxyPort.Value, proxyUser, proxyPassword, proxyBypass);
}

static void WriteJUnitXml(ResultPayload result, IOneKeyClient client, Guid firmwareId, string outputPath)
{
    var settings = new XmlWriterSettings
    {
        Indent = true,
        Encoding = Encoding.UTF8
    };

    using var writer = XmlWriter.Create(outputPath, settings);
    writer.WriteStartDocument();
    writer.WriteStartElement("testsuites");

    WriteIssuesSuite(writer, result.NewIssues, result.DroppedIssues, client, firmwareId);
    WriteCvesSuite(writer, result.NewCves, result.DroppedCves, client, firmwareId);

    writer.WriteEndElement();
    writer.WriteEndDocument();
}

static void WriteIssuesSuite(
    XmlWriter writer,
    List<JsonElement> newIssues,
    List<JsonElement> droppedIssues,
    IOneKeyClient client,
    Guid firmwareId)
{
    writer.WriteStartElement("testsuite");
    writer.WriteAttributeString("name", "ONEKEY identified issues");

    foreach (var issue in newIssues)
    {
        var id = issue.GetProperty("id").GetString() ?? "unknown";
        var type = issue.GetProperty("type").GetString() ?? "unknown";
        var file = issue.GetProperty("file").GetProperty("path").GetString() ?? "unknown";
        var severity = issue.GetProperty("severity").GetString() ?? "unknown";
        var url = UiUrls.FirmwareIssues(client, firmwareId);

        writer.WriteStartElement("testcase");
        writer.WriteAttributeString("name", id);
        writer.WriteAttributeString("classname", $"Issue: {type}");
        writer.WriteAttributeString("file", file);
        writer.WriteStartElement("failure");
        writer.WriteAttributeString("message", "New issue");
        writer.WriteCData($"New issue detected\nURL: {url}\nType: {type}\nSeverity: {severity}\nFile: {file}\n");
        writer.WriteEndElement();
        writer.WriteEndElement();
    }

    foreach (var issue in droppedIssues)
    {
        var id = issue.GetProperty("id").GetString() ?? "unknown";
        var type = issue.GetProperty("type").GetString() ?? "unknown";
        var file = issue.GetProperty("file").GetProperty("path").GetString() ?? "unknown";
        var url = UiUrls.FirmwareIssues(client, firmwareId);

        writer.WriteStartElement("testcase");
        writer.WriteAttributeString("name", id);
        writer.WriteAttributeString("classname", $"Issue: {type}");
        writer.WriteAttributeString("file", file);
        writer.WriteAttributeString("url", url);
        writer.WriteEndElement();
    }

    writer.WriteEndElement();
}

static void WriteCvesSuite(
    XmlWriter writer,
    List<JsonElement> newCves,
    List<string> droppedCves,
    IOneKeyClient client,
    Guid firmwareId)
{
    writer.WriteStartElement("testsuite");
    writer.WriteAttributeString("name", "ONEKEY identified CVE entries");

    foreach (var cve in newCves)
    {
        var id = cve.GetProperty("id").GetString() ?? "unknown";
        var severity = cve.TryGetProperty("severity", out var sevEl) ? sevEl.GetString() : "unknown";
        var description = cve.TryGetProperty("description", out var descEl) ? descEl.GetString() : string.Empty;
        var url = UiUrls.FirmwareCves(client, firmwareId);

        writer.WriteStartElement("testcase");
        writer.WriteAttributeString("name", id);
        writer.WriteAttributeString("classname", "CVE");
        writer.WriteStartElement("failure");
        writer.WriteAttributeString("message", "New CVE");
        writer.WriteCData($"New CVE detected\nURL: {url}\nCVE ID: {id}\nSeverity: {severity}\nDescription: {description}\n");
        writer.WriteEndElement();
        writer.WriteEndElement();
    }

    foreach (var cveId in droppedCves)
    {
        var url = UiUrls.FirmwareCves(client, firmwareId);
        writer.WriteStartElement("testcase");
        writer.WriteAttributeString("name", cveId);
        writer.WriteAttributeString("classname", "CVE");
        writer.WriteAttributeString("url", url);
        writer.WriteEndElement();
    }

    writer.WriteEndElement();
}

sealed record GlobalOptions(
    string ApiUrl,
    bool DisableTlsVerify,
    string? Email,
    string? Password,
    string? TenantName,
    string? Token,
    string? ProxyUrl,
    int? ProxyPort,
    string? ProxyUser,
    string? ProxyPassword,
    string? ProxyBypass);

static class UiUrls
{
    public static string Firmware(IOneKeyClient client, Guid firmwareId)
        => $"https://{client.ApiUrl.Host}/firmwares?firmwareId={firmwareId}";

    public static string FirmwareCompare(IOneKeyClient client, Guid baseId, Guid otherId)
        => $"https://{client.ApiUrl.Host}/firmwares/compare-firmwares?baseFirmwareId={baseId}&otherFirmwareId={otherId}";

    public static string FirmwareIssues(IOneKeyClient client, Guid firmwareId)
        => $"https://{client.ApiUrl.Host}/firmwares/issues?firmwareId={firmwareId}";

    public static string FirmwareCves(IOneKeyClient client, Guid firmwareId)
        => $"https://{client.ApiUrl.Host}/firmwares/cves?firmwareId={firmwareId}";
}

sealed class ResultHandler
{
    private readonly IOneKeyClient _client;
    private readonly Guid _firmwareId;
    private readonly int _retryCount;
    private readonly int _retryWait;
    private readonly int _checkInterval;

    private static readonly string FirmwareStatusQuery = QueryLoader.Load("get_firmware_latest_analysis_state.graphql");
    private static readonly string GetAllFirmwaresQuery = QueryLoader.Load("get_same_product_firmwares.graphql");
    private static readonly string CompareFirmwareQuery = QueryLoader.Load("compare_firmware.graphql");
    private static readonly string LatestIssuesQuery = QueryLoader.Load("get_firmware_latest_results.graphql");

    public ResultHandler(
        IOneKeyClient client,
        Guid firmwareId,
        int retryCount,
        int retryWait,
        int checkInterval)
    {
        _client = client;
        _firmwareId = firmwareId;
        _retryCount = retryCount;
        _retryWait = retryWait;
        _checkInterval = checkInterval;
    }

    public async Task<ResultPayload> GetResultAsync()
    {
        var errorCount = 1;
        while (true)
        {
            try
            {
                return await GetResultInternalAsync();
            }
            catch (HttpRequestException ex)
            {
                if (errorCount <= _retryCount)
                {
                    Console.WriteLine($"Error communicating with ONEKEY platform, retrying; error='{ex}'");
                    await Task.Delay(TimeSpan.FromSeconds(_retryWait * errorCount));
                    errorCount += 1;
                }
                else
                {
                    Console.WriteLine("Too many communication error with ONEKEY platform, failing");
                    throw;
                }
            }
        }
    }

    private async Task<ResultPayload> GetResultInternalAsync()
    {
        await WaitForAnalysisFinishAsync();

        var recentId = await GetRecentFirmwareIdAsync();
        if (recentId is not null)
        {
            Console.WriteLine($"Previous firmware results: {UiUrls.Firmware(_client, recentId.Value)}");
            var res = await _client.QueryAsync(CompareFirmwareQuery, new { @base = recentId.Value, other = _firmwareId });
            var parsed = CiResultParser.ParseCompareFirmware(res);
            var newIssues = parsed.NewIssues;
            var droppedIssues = parsed.DroppedIssues;
            var newCves = parsed.NewCves;
            var droppedCves = parsed.DroppedCves;

            PrintResultSummary(newIssues.Count, droppedIssues.Count, newCves.Count, droppedCves.Count, recentId);

            return new ResultPayload(newIssues, droppedIssues, newCves, droppedCves);
        }

        Console.WriteLine("No previous firmware has been uploaded");
        var latest = await _client.QueryAsync(LatestIssuesQuery, new { id = _firmwareId });
        var latestParsed = CiResultParser.ParseLatestIssues(latest);
        var newIssuesNoPrev = latestParsed.NewIssues;
        var newCvesNoPrev = latestParsed.NewCves;

        PrintResultSummary(newIssuesNoPrev.Count, 0, newCvesNoPrev.Count, 0, null);

        return new ResultPayload(newIssuesNoPrev, new List<JsonElement>(), newCvesNoPrev, new List<string>());
    }

    private void PrintResultSummary(
        int newIssuesCount,
        int droppedIssuesCount,
        int newCvesCount,
        int droppedCvesCount,
        Guid? recentId)
    {
        Console.WriteLine(new string('#', 80));
        Console.WriteLine($"New / dropped issue count: {newIssuesCount} / {droppedIssuesCount}");
        Console.WriteLine($"New / dropped CVE count: {newCvesCount} / {droppedCvesCount}");
        if (recentId is not null && (newIssuesCount > 0 || droppedIssuesCount > 0 || newCvesCount > 0 || droppedCvesCount > 0))
        {
            Console.WriteLine(
                $"Firmware comparison results with previous firmware: {UiUrls.FirmwareCompare(_client, recentId.Value, _firmwareId)}");
        }
        else
        {
            Console.WriteLine("No changes since previous firmware");
        }
    }

    private async Task WaitForAnalysisFinishAsync()
    {
        Console.WriteLine($"Waiting for analysis to finish on firmware: {_firmwareId}");
        while (true)
        {
            try
            {
                await _client.RefreshTenantTokenAsync();
                var res = await _client.QueryAsync(FirmwareStatusQuery, new { id = _firmwareId });
                if (res.GetProperty("firmware").ValueKind == JsonValueKind.Null)
                {
                    Console.WriteLine("Firmware is not yet available, analysis not started yet, waiting.");
                    await Task.Delay(TimeSpan.FromSeconds(_checkInterval));
                    continue;
                }

                var latestAnalysis = res.GetProperty("firmware").GetProperty("latestAnalysis");
                if (latestAnalysis.ValueKind == JsonValueKind.Null)
                {
                    Console.WriteLine("Analysis has not started yet, waiting.");
                    await Task.Delay(TimeSpan.FromSeconds(_checkInterval));
                    continue;
                }

                var state = latestAnalysis.GetProperty("state").GetString();
                if (!string.Equals(state, "DONE", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Firmware analysis still in progress, waiting.");
                    await Task.Delay(TimeSpan.FromSeconds(_checkInterval));
                    continue;
                }

                var result = latestAnalysis.GetProperty("result").GetString();
                if (!string.Equals(result, "COMPLETE", StringComparison.OrdinalIgnoreCase))
                {
                    throw new CliExitException(
                        2,
                        $"Firmware analysis failed, check details: {UiUrls.Firmware(_client, _firmwareId)}");
                }

                Console.WriteLine(
                    $"Firmware analysis finished successfully, results: {UiUrls.Firmware(_client, _firmwareId)}");
                break;
            }
            catch (CliExitException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new CliExitException(10, $"Error fetching results {ex}");
            }
        }
    }

    private async Task<Guid?> GetRecentFirmwareIdAsync()
    {
        var res = await _client.QueryAsync(GetAllFirmwaresQuery, new { id = _firmwareId, firmwareCount = 2 });
        var firmwareIds = CiResultParser.ParseFirmwareTimeline(res);

        if (firmwareIds.Count == 0)
        {
            Console.WriteLine("No previous firmware");
            return null;
        }

        var latestId = firmwareIds[0];
        if (latestId != _firmwareId)
        {
            Console.WriteLine(
                $"Latest firmware upload is not the current firmware, skipping comparison with previous, latest={latestId}");
            return null;
        }

        if (firmwareIds.Count < 2)
        {
            Console.WriteLine("No previous firmware");
            return null;
        }

        return firmwareIds[1];
    }
}

sealed record ResultPayload(
    List<JsonElement> NewIssues,
    List<JsonElement> DroppedIssues,
    List<JsonElement> NewCves,
    List<string> DroppedCves);

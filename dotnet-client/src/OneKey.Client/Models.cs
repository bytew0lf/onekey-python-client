namespace OneKey.Client;

public sealed record Tenant(Guid Id, string Name);

public sealed record FirmwareMetadata(
    string Name,
    string VendorName,
    string ProductName,
    Guid ProductGroupId,
    Guid AnalysisConfigurationId,
    string? Version = null,
    DateTimeOffset? ReleaseDate = null,
    string? Notes = null,
    string? ProductCategory = null
);

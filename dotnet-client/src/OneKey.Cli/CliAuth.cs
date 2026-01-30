namespace OneKey.Cli;

internal static class CliAuth
{
    internal static void ValidateAuthInputs(
        string? email,
        string? password,
        string? tenantName,
        string? token)
    {
        if (!string.IsNullOrWhiteSpace(token) &&
            (!string.IsNullOrWhiteSpace(email) || !string.IsNullOrWhiteSpace(password) || !string.IsNullOrWhiteSpace(tenantName)))
        {
            throw new CliExitException(
                1,
                "Invalid authentication details, either specify token or email/password/tenant, but not both!");
        }

        if (string.IsNullOrWhiteSpace(token) &&
            (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password)))
        {
            throw new CliExitException(
                1,
                "Invalid authentication details, specify email, password and tenant, if token is not specified!");
        }
    }
}

namespace OneKey.Client;

public class ClientError(string message) : Exception(message);

public sealed class NotLoggedIn() : ClientError(
    "You are not logged in yet. Call LoginAsync(email, password) or UseTokenAsync(token)."
);

public sealed class TenantNotSelected() : ClientError(
    "Select a tenant with UseTenantAsync(tenant) or use UseTokenAsync(token)."
);

public sealed class InvalidCaBundle() : ClientError("The CA bundle is invalid or doesn't exist.");

public sealed class InvalidApiToken() : ClientError("The API Token is invalid.");

public sealed class QueryError(string errorsJson) : ClientError(errorsJson);

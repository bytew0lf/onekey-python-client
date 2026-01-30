using System.Security.Claims;
using OneKey.Client;
using Xunit;

namespace OneKey.Client.Tests;

public class ClientTests
{
    [Fact]
    public void ParseTenantsFromClaims_ReturnsTenants()
    {
        var json = "[{\"id\":\"11111111-1111-1111-1111-111111111111\",\"name\":\"Env A\"}," +
                   "{\"id\":\"22222222-2222-2222-2222-222222222222\",\"name\":\"Env B\"}]";
        var claims = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("https://www.onekey.com/tenants", json)
        }));

        var tenants = OneKeyClient.ParseTenantsFromClaims(claims);

        Assert.Equal(2, tenants.Count);
        Assert.True(tenants.ContainsKey("Env A"));
        Assert.True(tenants.ContainsKey("Env B"));
    }

    [Fact]
    public void ParseTenantsFromClaims_HandlesMissingClaim()
    {
        var claims = new ClaimsPrincipal(new ClaimsIdentity());

        var tenants = OneKeyClient.ParseTenantsFromClaims(claims);

        Assert.Empty(tenants);
    }
}

using OneKey.Cli;
using Xunit;

namespace OneKey.Cli.Tests;

public class CliAuthTests
{
    [Fact]
    public void ValidateAuthInputs_ThrowsWhenTokenAndEmailProvided()
    {
        var ex = Assert.Throws<CliExitException>(() =>
            CliAuth.ValidateAuthInputs("user@example.com", "pass", "tenant", "token"));

        Assert.Equal(1, ex.ExitCode);
        Assert.Contains("either specify token or email/password/tenant", ex.Message);
    }

    [Fact]
    public void ValidateAuthInputs_ThrowsWhenMissingPassword()
    {
        var ex = Assert.Throws<CliExitException>(() =>
            CliAuth.ValidateAuthInputs("user@example.com", null, "tenant", null));

        Assert.Equal(1, ex.ExitCode);
        Assert.Contains("specify email, password and tenant", ex.Message);
    }

    [Fact]
    public void ValidateAuthInputs_AllowsTokenOnly()
    {
        CliAuth.ValidateAuthInputs(null, null, null, "token");
    }
}

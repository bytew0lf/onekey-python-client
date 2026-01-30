namespace OneKey.Cli;

internal sealed class CliExitException : Exception
{
    public CliExitException(int exitCode, string message) : base(message)
    {
        ExitCode = exitCode;
    }

    public int ExitCode { get; }
}

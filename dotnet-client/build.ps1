Param(
  [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RootDir

dotnet build OneKey.sln -c $Configuration

dotnet test tests/OneKey.Client.Tests/OneKey.Client.Tests.csproj -c $Configuration

dotnet test tests/OneKey.Cli.Tests/OneKey.Cli.Tests.csproj -c $Configuration

Param(
  [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RootDir

dotnet publish src/OneKey.Cli/OneKey.Cli.csproj `
  -c $Configuration `
  -r win-x64 `
  --self-contained true `
  /p:PublishSingleFile=true `
  /p:IncludeNativeLibrariesForSelfExtract=true `
  -o "$RootDir/publish/win-x64"

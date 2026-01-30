#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT_DIR"

dotnet build OneKey.sln

dotnet test tests/OneKey.Client.Tests/OneKey.Client.Tests.csproj

dotnet test tests/OneKey.Cli.Tests/OneKey.Cli.Tests.csproj

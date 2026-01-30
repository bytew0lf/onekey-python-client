# OneKey .NET Client

This folder contains the unofficial .NET 9 client and CLI port for the ONEKEY API.

License: see `LICENSE` in this directory.

## Quick commands

Build + test:

```bash
./build.sh
```

```powershell
./build.ps1 -Configuration Debug
```

Run tests only:

```bash
./test.sh
```

```powershell
./test.ps1 -Configuration Debug
```

Run the CLI:

```bash
./run-cli.sh --help
```

```powershell
./run-cli.ps1 --help
```

## CLI usage

The CLI supports two authentication modes:

1) Email + password + tenant
2) API token

Use either mode, not both.

### Global options (apply to all commands)

- `--api-url` (default: `https://app.eu.onekey.com/api`)
- `--disable-tls-verify`
- `--email`
- `--password`
- `--tenant`
- `--token`
- `--proxy-url` (host or URL, no port)
- `--proxy-port`
- `--proxy-user`
- `--proxy-password`
- `--proxy-bypass` (comma-separated list)

You can also set proxy values via environment variables:

- `ONEKEY_PROXY_URL`
- `ONEKEY_PROXY_PORT`
- `ONEKEY_PROXY_USER`
- `ONEKEY_PROXY_PASSWORD`
- `ONEKEY_PROXY_BYPASS`

### Examples

List tenants (email/password/tenant auth):

```bash
./run-cli.sh --email "user@example.com" --password "secret" --tenant "My Tenant" list-tenants
```

```powershell
./run-cli.ps1 --email "user@example.com" --password "secret" --tenant "My Tenant" list-tenants
```

List tenants (API token auth):

```bash
./run-cli.sh --token "TENANT_ID/your-token" list-tenants
```

```powershell
./run-cli.ps1 --token "TENANT_ID/your-token" list-tenants
```

Get tenant token (email/password/tenant auth):

```bash
./run-cli.sh --email "user@example.com" --password "secret" --tenant "My Tenant" get-tenant-token
```

```powershell
./run-cli.ps1 --email "user@example.com" --password "secret" --tenant "My Tenant" get-tenant-token
```

Upload firmware:

```bash
./run-cli.sh --email "user@example.com" --password "secret" --tenant "My Tenant" \\
  upload-firmware --vendor "MyVendor" --product "MyProduct" \\
  --product-group "Default" --analysis-configuration "Default" \\
  --version "1.0.0" ./firmware.bin
```

```powershell
./run-cli.ps1 --email "user@example.com" --password "secret" --tenant "My Tenant" `
  upload-firmware --vendor "MyVendor" --product "MyProduct" `
  --product-group "Default" --analysis-configuration "Default" `
  --version "1.0.0" ./firmware.bin
```

Fetch CI results and write JUnit:

```bash
./run-cli.sh --token "TENANT_ID/your-token" \\
  ci-result --firmware-id "11111111-1111-1111-1111-111111111111" \\
  --exit-code-on-new-finding 1 --check-interval 60 --retry-count 10 --retry-wait 60 \\
  --junit-path ./onekey-results.xml
```

```powershell
./run-cli.ps1 --token "TENANT_ID/your-token" `
  ci-result --firmware-id "11111111-1111-1111-1111-111111111111" `
  --exit-code-on-new-finding 1 --check-interval 60 --retry-count 10 --retry-wait 60 `
  --junit-path ./onekey-results.xml
```

Use a proxy:

```bash
./run-cli.sh --token "TENANT_ID/your-token" \\
  --proxy-url "proxy.example.com" --proxy-port 8080 \\
  --proxy-user "proxyuser" --proxy-password "proxypass" \\
  list-tenants
```

```powershell
./run-cli.ps1 --token "TENANT_ID/your-token" `
  --proxy-url "proxy.example.com" --proxy-port 8080 `
  --proxy-user "proxyuser" --proxy-password "proxypass" `
  list-tenants
```

Use a proxy via environment variables:

```bash
export ONEKEY_PROXY_URL="proxy.example.com"
export ONEKEY_PROXY_PORT="8080"
export ONEKEY_PROXY_USER="proxyuser"
export ONEKEY_PROXY_PASSWORD="proxypass"
./run-cli.sh --token "TENANT_ID/your-token" list-tenants
```

```powershell
$env:ONEKEY_PROXY_URL="proxy.example.com"
$env:ONEKEY_PROXY_PORT="8080"
$env:ONEKEY_PROXY_USER="proxyuser"
$env:ONEKEY_PROXY_PASSWORD="proxypass"
./run-cli.ps1 --token "TENANT_ID/your-token" list-tenants
```

## Using published binaries

After publishing, the CLI can be invoked directly from the publish folder.

Linux/macOS:

```bash
./publish/linux-x64/OneKey.Cli --help
./publish/osx-arm64/OneKey.Cli --help
./publish/osx-x64/OneKey.Cli --help
```

Windows (PowerShell):

```powershell
./publish/win-x64/OneKey.Cli.exe --help
```

## Platform notes

macOS Gatekeeper may block unsigned binaries on first run. If this happens, remove the quarantine attribute:

```bash
xattr -dr com.apple.quarantine ./publish/osx-arm64/OneKey.Cli
```

```bash
xattr -dr com.apple.quarantine ./publish/osx-x64/OneKey.Cli
```

## Publish self-contained binaries

Linux x64:

```bash
./publish-linux-x64.sh
```

macOS Apple Silicon:

```bash
./publish-osx-arm64.sh
```

macOS Intel:

```bash
./publish-osx-x64.sh
```

Windows x64:

```powershell
./publish-win-x64.ps1
```

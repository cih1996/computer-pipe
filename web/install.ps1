$ErrorActionPreference = 'Stop'

if (-not $env:PIPE_DOWNLOAD_BASE) { throw 'PIPE_DOWNLOAD_BASE is required' }
if (-not $env:PIPE_NAME) { throw 'PIPE_NAME is required' }
if (-not $env:PIPE_TOKEN) { throw 'PIPE_TOKEN is required' }

$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
switch ($arch.ToUpperInvariant()) {
  'AMD64' { $asset = 'pipe-windows-amd64.exe' }
  'ARM64' { $asset = 'pipe-windows-arm64.exe' }
  default { throw "unsupported Windows architecture: $arch" }
}

$dir = if ($env:PIPE_INSTALL_DIR) { $env:PIPE_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'computer-pipe' }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$binary = Join-Path $dir 'computer-pipe.exe'
$downloadBase = ($env:PIPE_DOWNLOAD_BASE -replace '\\','').TrimEnd('/')
$binaryUrl = $downloadBase + '/' + $asset
$temporaryBinary = Join-Path $dir ("computer-pipe.download." + $PID + ".exe")
$existing = @(Get-Process -Name 'computer-pipe' -ErrorAction SilentlyContinue)
$needsElevation = $false
foreach ($oldProcess in $existing) {
  try {
    Stop-Process -Id $oldProcess.Id -Force -ErrorAction Stop
  } catch {
    $needsElevation = $true
  }
}
if ($needsElevation) {
  $ids = ($existing | ForEach-Object Id) -join ','
  $elevated = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile', '-Command', "Stop-Process -Id $ids -Force")
  if ($elevated.ExitCode -ne 0) { throw "failed to stop the existing computer-pipe process (exit code $($elevated.ExitCode))" }
}
Start-Sleep -Milliseconds 500
$remaining = @(Get-Process -Name 'computer-pipe' -ErrorAction SilentlyContinue)
if ($remaining) { throw 'the existing computer-pipe process is still running; run the installer again after it stops' }
if ($env:PIPE_INSECURE -eq '1' -and (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
  & curl.exe -kfsSL $binaryUrl -o $temporaryBinary
  if ($LASTEXITCODE -ne 0) { throw 'computer-pipe download failed' }
} else {
  Invoke-WebRequest -UseBasicParsing -Uri $binaryUrl -OutFile $temporaryBinary
}
Move-Item -Force -LiteralPath $temporaryBinary -Destination $binary

$args = @('agent', '--name', $env:PIPE_NAME, '--token', $env:PIPE_TOKEN)
if ($env:PIPE_MODE -eq 'direct' -or $env:PIPE_MODE -eq 'lan') {
  $args = @('agent', '--direct', '--token', $env:PIPE_TOKEN)
} elseif ($env:PIPE_MODE -eq 'frps') {
  if (-not $env:PIPE_FRPS_ADDR -or -not $env:PIPE_FRPS_TOKEN -or -not $env:PIPE_FRPS_REMOTE_PORT) { throw 'frps settings are incomplete' }
  $frpsAddress = $env:PIPE_FRPS_ADDR -replace '\\',''
  $args += @('--frps-addr', $frpsAddress, '--frps-token', $env:PIPE_FRPS_TOKEN, '--frps-remote-port', $env:PIPE_FRPS_REMOTE_PORT)
  $frpVersion = if ($env:PIPE_FRP_VERSION) { $env:PIPE_FRP_VERSION } else { '0.72.0' }
  $frpDir = Join-Path $dir ("frp-" + $frpVersion)
  $frpcPath = if ($env:PIPE_FRPC_PATH) { $env:PIPE_FRPC_PATH } else { Join-Path $frpDir 'frpc.exe' }
  if (-not (Test-Path $frpcPath)) {
    New-Item -ItemType Directory -Force -Path $frpDir | Out-Null
    $zip = Join-Path $dir ("frp-" + $frpVersion + '.zip')
    $frpArch = if ($arch.ToUpperInvariant() -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $frpBase = if ($env:PIPE_FRPC_BASE) { $env:PIPE_FRPC_BASE.TrimEnd('/') } else { "https://github.com/fatedier/frp/releases/download/v$frpVersion" }
    $frpUrl = "$frpBase/frp_${frpVersion}_windows_${frpArch}.zip"
    if ($env:PIPE_INSECURE -eq '1' -and (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
      & curl.exe -kfsSL $frpUrl -o $zip
      if ($LASTEXITCODE -ne 0) { throw 'frpc download failed' }
    } else {
      Invoke-WebRequest -UseBasicParsing -Uri $frpUrl -OutFile $zip
    }
    Expand-Archive -Force -Path $zip -DestinationPath $frpDir
    $found = Get-ChildItem -Path $frpDir -Filter frpc.exe -Recurse | Select-Object -First 1
    if (-not $found) { throw 'frpc.exe was not found in the downloaded archive' }
    $frpcPath = $found.FullName
  }
  $args += @('--frpc', $frpcPath)
} else {
  if (-not $env:PIPE_RELAY) { throw 'PIPE_RELAY is required in relay mode' }
  $args += @('--relay', ($env:PIPE_RELAY -replace '\\',''))
}
$listenAddress = if ($env:PIPE_LISTEN) { $env:PIPE_LISTEN } else { '0.0.0.0:17602' }
$args += @('--listen', $listenAddress)
if ($env:PIPE_TLS -eq '1') { $args += '--tls' }
if ($env:PIPE_INSECURE -eq '1') { $args += '--insecure' }
if ($env:PIPE_FRPC_PATH) { $args += @('--frpc', $env:PIPE_FRPC_PATH) }

$stdoutLog = Join-Path $dir 'agent.stdout.log'
$stderrLog = Join-Path $dir 'agent.stderr.log'
$process = Start-Process -FilePath $binary -ArgumentList $args -WorkingDirectory $dir -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
Start-Sleep -Milliseconds 1200
$listenPort = [int](($listenAddress -split ':')[-1])
$listening = Get-NetTCPConnection -LocalPort $listenPort -State Listen -ErrorAction SilentlyContinue
if (-not $listening) {
  $detail = if (Test-Path $stderrLog) { (Get-Content $stderrLog -Raw) } else { '' }
  throw "computer-pipe did not listen on $listenAddress. pid=$($process.Id) error=$detail"
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  $ruleName = 'computer-pipe local API 17602'
  Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $listenPort -Action Allow -Profile Domain,Private | Out-Null
} else {
  Write-Warning 'PowerShell is not elevated, so the Windows firewall rule was not changed. Run the command as Administrator to allow LAN access.'
}
Write-Output "computer-pipe installed: $binary"
Write-Output "agent started"
Write-Output "local API: $listenAddress"
Write-Output "logs: $stdoutLog / $stderrLog"

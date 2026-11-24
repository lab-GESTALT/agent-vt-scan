<#
.SYNOPSIS
  双引擎文件体检：VirusTotal 情报 + 本地 Kaspersky 扫描。

.PARAMETER Path
  待扫描文件的绝对或相对路径。

.PARAMETER Engine
  vt | kav | both，默认 both。

.PARAMETER Upload
  哈希未命中时是否上传文件到 VirusTotal。默认不上传。

.PARAMETER Proxy
  可选 HTTP 代理，例如 http://127.0.0.1:10808。

.EXAMPLE
  .\scan.ps1 -Path .\download.zip -Engine both
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [ValidateSet('vt', 'kav', 'both')][string]$Engine = 'both',
  [switch]$Upload,
  [string]$Proxy
)

$ErrorActionPreference = 'Stop'

function Get-ApiKey {
  if ($env:VTCLI_APIKEY) { return $env:VTCLI_APIKEY.Trim() }
  $candidates = @()
  if ($env:VT_SCAN_KEYFILE) { $candidates += $env:VT_SCAN_KEYFILE }
  $candidates += (Join-Path $HOME '.vt\api.key')
  $candidates += (Join-Path $HOME '.vt.toml')
  foreach ($f in $candidates) {
    if ($f -and (Test-Path $f)) {
      $text = (Get-Content $f -Raw).Trim()
      $m = [regex]::Match($text, '^apikey\s*=\s*"?([A-Za-z0-9]{32,})"?')
      if ($m.Success) { return $m.Groups[1].Value }
      if ($text -match '^[A-Za-z0-9]{32,}$') { return $text }
    }
  }
  return $null
}

function Invoke-VtJson {
  param([string]$Uri, [hashtable]$Headers, [string]$Method = 'GET', $Body)
  $args = @{ Uri = $Uri; Method = $Method; Headers = $Headers; TimeoutSec = 60; UseBasicParsing = $true }
  if ($Proxy) { $args.Proxy = $Proxy }
  if ($Body) { $args.Body = $Body; $args.ContentType = 'application/json' }
  return Invoke-RestMethod @args
}

function Get-VtResult {
  param([string]$Hash, [string]$FilePath)
  $key = Get-ApiKey
  if (-not $key) { return @{ status = 'error'; message = 'VTCLI_APIKEY 未设置，且本地密钥文件不存在' } }
  $headers = @{ 'x-apikey' = $key }

  try {
    $r = Invoke-VtJson -Uri "https://www.virustotal.com/api/v3/files/$Hash" -Headers $headers
    $s = $r.data.attributes.last_analysis_stats
    return @{
      status    = 'found'
      malicious = [int]$s.malicious
      suspicious = [int]$s.suspicious
      total     = [int]$s.malicious + [int]$s.undetected + [int]$s.harmless + [int]$s.suspicious
      name      = $r.data.attributes.meaningful_name
    }
  } catch {
    $code = $null
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    if ($code -eq 404) {
      if (-not $Upload) { return @{ status = 'not_found'; message = 'VT 无此哈希记录，未上传' } }
      try {
        $form = @{ file = Get-Item $FilePath }
        $up = Invoke-VtJson -Uri 'https://www.virustotal.com/api/v3/files' -Headers $headers -Method 'POST' -Body $form
        Start-Sleep -Seconds 20
        $analysis = Invoke-VtJson -Uri ("https://www.virustotal.com/api/v3/analyses/" + $up.data.id) -Headers $headers
        $s2 = $analysis.data.attributes.stats
        return @{ status = 'uploaded'; malicious = [int]$s2.malicious; suspicious = [int]$s2.suspicious; total = [int]$s2.malicious + [int]$s2.undetected; name = '' }
      } catch {
        return @{ status = 'error'; message = '上传或查询失败：' + $_.Exception.Message }
      }
    }
    if ($code -eq 401) { return @{ status = 'error'; message = 'VT 密钥无效（401）' } }
    if ($code -eq 429) { return @{ status = 'error'; message = 'VT 配额用尽（429）' } }
    return @{ status = 'error'; message = $_.Exception.Message }
  }
}

function Get-AvpPath {
  $roots = @('C:\Program Files (x86)\Kaspersky Lab', 'C:\Program Files\Kaspersky Lab')
  foreach ($root in $roots) {
    if (-not (Test-Path $root)) { continue }
    $hit = Get-ChildItem $root -Recurse -Filter 'avp.com' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.FullName }
  }
  return $null
}

function Get-KavResult {
  param([string]$FilePath)
  $avp = Get-AvpPath
  if (-not $avp) { return @{ status = 'error'; message = '找不到 avp.com，请确认已安装 Kaspersky' } }

  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("vt-scan-" + [guid]::NewGuid().ToString('N') + '.txt')
  try {
    & $avp SCAN "$FilePath" /R:"$tmp" /RA:"$tmp" 2>&1 | Out-Null
    if (-not (Test-Path $tmp)) { return @{ status = 'error'; message = '未生成扫描报告' } }
    $text = Get-Content $tmp -Raw
    $num = {
      param($label)
      $m = [regex]::Match($text, ";\s*$label\s*:\s*(\d+)")
      if ($m.Success) { return [int]$m.Groups[1].Value }
      return 0
    }
    return @{
      status   = 'scanned'
      detected = (& $num 'Total detected')
      ok       = (& $num 'Total OK')
      errors   = (& $num 'Errors')
    }
  } finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  }
}

# ---- 主流程 ----

if (-not (Test-Path $Path)) {
  @{ path = $Path; verdict = 'error'; message = '文件不存在' } | ConvertTo-Json -Depth 5
  exit 2
}

$item = Get-Item $Path
$hash = (Get-FileHash -Path $item.FullName -Algorithm SHA256).Hash.ToLower()

$out = @{
  path   = $item.FullName
  size   = $item.Length
  sha256 = $hash
  engine = $Engine
}

if ($Engine -in @('vt', 'both')) { $out.vt = Get-VtResult -Hash $hash -FilePath $item.FullName }
if ($Engine -in @('kav', 'both')) { $out.kav = Get-KavResult -FilePath $item.FullName }

$vtMal = 0; $vtFound = $false; $vtErr = $false
if ($out.vt) {
  if ($out.vt.status -in @('found', 'uploaded')) { $vtFound = $true; $vtMal = [int]$out.vt.malicious }
  elseif ($out.vt.status -eq 'error') { $vtErr = $true }
}
$kavDet = 0; $kavErr = $false
if ($out.kav) {
  if ($out.kav.status -eq 'scanned') { $kavDet = [int]$out.kav.detected } else { $kavErr = $true }
}

$verdict = 'clean'
if ($kavDet -gt 0) { $verdict = 'malicious' }
elseif ($vtFound -and $vtMal -ge 3) { $verdict = 'malicious' }
elseif ($vtFound -and $vtMal -ge 1) { $verdict = 'suspicious' }
elseif ($vtErr -or $kavErr) { $verdict = 'error' }
elseif (-not $vtFound) { $verdict = 'unknown' }

$out.verdict = $verdict
$out | ConvertTo-Json -Depth 6

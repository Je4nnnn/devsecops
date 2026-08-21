param(
    [ValidateSet("Pull", "Build")]
    [string]$Mode = "Pull",
    [switch]$EnableHttps
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

function New-RandomBytes([int]$Count) {
    $bytes = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return $bytes
}

function New-HexSecret([int]$Count) {
    return -join ((New-RandomBytes $Count) | ForEach-Object { $_.ToString("x2") })
}

function New-UrlSafeBase64([int]$Count) {
    return [Convert]::ToBase64String((New-RandomBytes $Count)).Replace("+", "-").Replace("/", "_")
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker no esta disponible. Instale e inicie Docker Desktop."
}
& docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Se requiere Docker Compose v2." }

if (-not (Test-Path ".env")) {
    $content = [IO.File]::ReadAllText((Join-Path $ProjectDir ".env.example"))
    $adminPassword = New-UrlSafeBase64 18
    $content = $content.Replace("REEMPLAZAR_POSTGRES_PASSWORD", (New-HexSecret 24))
    $content = $content.Replace("REEMPLAZAR_ADMIN_PASSWORD", $adminPassword)
    $content = $content.Replace("REEMPLAZAR_JWT_SECRET", (New-HexSecret 48))
    $content = $content.Replace("REEMPLAZAR_ENCRYPTION_KEY", (New-UrlSafeBase64 32))
    [IO.File]::WriteAllText((Join-Path $ProjectDir ".env"), $content, (New-Object Text.UTF8Encoding($false)))
    Write-Host "Se creo .env con secretos aleatorios."
    Write-Host "Usuario inicial: admin"
    Write-Host "Contrasena inicial: $adminPassword"
    Write-Host "Guardela ahora; no se volvera a mostrar."
}

if (Select-String -Path ".env" -Pattern "REEMPLAZAR_" -Quiet) {
    throw ".env contiene valores REEMPLAZAR_. Eliminelo para regenerarlo o complete los valores."
}

$composeArgs = @("compose", "--env-file", ".env", "-f", "docker-compose.yml")
if ($EnableHttps) {
    $sslDir = Join-Path $ProjectDir "nginx\ssl"
    New-Item -ItemType Directory -Force -Path $sslDir | Out-Null
    if (-not (Test-Path (Join-Path $sslDir "nginx-selfsigned.crt"))) {
        & docker run --rm --mount "type=bind,source=$sslDir,target=/certs" alpine/openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /certs/nginx-selfsigned.key -out /certs/nginx-selfsigned.crt -subj "/C=CL/O=DevSecOps/CN=localhost"
        if ($LASTEXITCODE -ne 0) { throw "No se pudo generar el certificado HTTPS." }
    }
    $composeArgs += @("-f", "docker-compose.tls.yml")
}

& docker @composeArgs config --quiet
if ($LASTEXITCODE -ne 0) { throw "La configuracion Docker Compose no es valida." }

if ($Mode -eq "Build") {
    $previousPullPolicy = $env:APP_PULL_POLICY
    try {
        $env:APP_PULL_POLICY = "build"
        & docker @composeArgs up -d --build
    } finally {
        $env:APP_PULL_POLICY = $previousPullPolicy
    }
} else {
    & docker @composeArgs pull
    if ($LASTEXITCODE -ne 0) { throw "No se pudieron descargar las imagenes." }
    & docker @composeArgs up -d --no-build
}
if ($LASTEXITCODE -ne 0) { throw "No se pudo iniciar la aplicacion." }

Write-Host ""
Write-Host "Aplicacion disponible en http://localhost:18080"
if ($EnableHttps) { Write-Host "HTTPS disponible en https://localhost:18443" }
Write-Host "Estado: docker compose --env-file .env ps"

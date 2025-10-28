# Gera um keystore PKCS12 de desenvolvimento para a aplicação
# Requisitos: Java (keytool) disponível no PATH
# Uso: execute em Powershell na raiz do projeto
#    .\scripts\generate-dev-keystore.ps1 -Alias securemessaging -Password changeit

param(
    [string]$Alias = "securemessaging",
    [string]$Password = "changeit",
    [int]$ValidityDays = 3650
)

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

# Resolver caminho do keystore relactivo ao diretório do script (mais robusto que usar CWD)
$keystoreDirPath = Join-Path -Path $scriptRoot -ChildPath "..\src\main\resources"
$keystoreDir = Resolve-Path $keystoreDirPath -ErrorAction SilentlyContinue
if (-not $keystoreDir) {
    # Tentar caminho relactivo à raiz do repositório como fallback
    $fallback = Resolve-Path "..\..\secure-messaging-backend\src\main\resources" -ErrorAction SilentlyContinue
    if ($fallback) { $keystoreDir = $fallback } else { $keystoreDir = Resolve-Path $keystoreDirPath -ErrorAction Stop }
}

$keystorePath = Join-Path -Path $keystoreDir -ChildPath "keystore.p12"

Write-Host "Destino do keystore: $keystorePath"

if (Test-Path $keystorePath) {
    Write-Host "Arquivo já existe. Removendo..."
    Remove-Item $keystorePath -Force
}

# Verificar se keytool está disponível
$kt = Get-Command keytool -ErrorAction SilentlyContinue
if (-not $kt) {
    Write-Host "ERROR: 'keytool' não encontrado no PATH. Instale um JDK (por exemplo Temurin/OpenJDK) e garanta que 'keytool' esteja acessível." -ForegroundColor Red
    Write-Host "Exemplo: instalar Temurin JDK e reiniciar o terminal. Em Windows, verifique se C:\Program Files\Java\...\bin está no PATH." -ForegroundColor Yellow
    exit 1
}

$dn = "CN=SecureMessagingDev, OU=Dev, O=SecureMessaging, L=Local, ST=Local, C=US"

Write-Host "Gerando keystore PKCS12 (alias=$Alias, validity=$ValidityDays days)..."

# Construir argumentos de forma segura
$args = @(
    '-genkeypair',
    '-alias', $Alias,
    '-keyalg', 'RSA',
    '-keysize', '1024',
    '-dname', $dn,
    '-keypass', $Password,
    '-keystore', $keystorePath,
    '-storepass', $Password,
    '-storetype', 'PKCS12',
    '-validity', [string]$ValidityDays
)

& keytool @args

if ($LASTEXITCODE -eq 0) {
    Write-Host "Keystore gerado com sucesso em: $keystorePath" -ForegroundColor Green
}
else {
    Write-Host "Falha ao gerar keystore. ExitCode: $LASTEXITCODE" -ForegroundColor Red
}

Write-Host "Se preferir, você pode gerar um keystore usando OpenSSL/keytool externamente e colocá-lo em src/main/resources/keystore.p12"

#!/usr/bin/env pwsh
param(
    [Parameter(Mandatory = $true)]
    [string]$Image
)

$ErrorActionPreference = "Stop"
$suffix = Get-Random -Minimum 100000 -Maximum 999999
$name = "vault-guardian-single-$suffix"
$label = "vault-guardian.validation=$suffix"

function Invoke-Docker {
    param([Parameter(Mandatory = $true)][string[]]$DockerArguments)
    & docker @DockerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($DockerArguments -join ' ') falló"
    }
}

try {
    $runArguments = @(
        "run", "-d", "--name", $name, "--label", $label,
        "--user", "0:0", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "128",
        "--tmpfs", "/tmp:rw,size=256m,mode=1777",
        "--tmpfs", "/state:rw,size=64m,mode=0700",
        "--tmpfs", "/instances:rw,size=64m,mode=0700",
        "--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock",
        "--env", "VG_DOCKER_SOCKET=/var/run/docker.sock",
        "--env", "VG_ALLOW_INSECURE_HTTP=true",
        $Image
    )
    Invoke-Docker -DockerArguments $runArguments | Out-Null

    $healthy = $false
    # La primera comprobación puede tardar más cuando una imagen ARM64 se valida
    # mediante QEMU en un servidor AMD64. El contenedor mantiene los mismos límites
    # de salud; el laboratorio sólo amplía su ventana de observación.
    foreach ($attempt in 1..90) {
        $status = docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' $name
        if ($status -eq "healthy") {
            $healthy = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $healthy) {
        Invoke-Docker -DockerArguments @("logs", $name)
        throw "el contenedor único no quedó saludable"
    }

    $matches = @(docker ps -a --filter "label=$label" --format '{{.Names}}')
    if ($matches.Count -ne 1 -or $matches[0] -ne $name) {
        throw "la aplicación creó más de un contenedor propio"
    }

    $inspect = docker inspect $name | ConvertFrom-Json
    if ($inspect[0].Config.User -ne "0:0") {
        throw "el proceso no usa el usuario requerido para el socket Docker"
    }
    if (-not $inspect[0].HostConfig.ReadonlyRootfs) {
        throw "el rootfs debe ser de sólo lectura"
    }
    if ($inspect[0].HostConfig.CapDrop -notcontains "ALL") {
        throw "faltan las restricciones de capabilities"
    }
    $socketMounts = @($inspect[0].Mounts | Where-Object {
        $_.Destination -eq "/var/run/docker.sock"
    })
    if ($socketMounts.Count -ne 1) {
        throw "docker.sock debe montarse exactamente una vez"
    }
    $secretMounts = @($inspect[0].Mounts | Where-Object {
        $_.Destination -like "/run/secrets/*"
    })
    if ($secretMounts.Count -ne 0) {
        throw "una instalación nueva no debe montar ficheros de secretos"
    }

    Invoke-Docker -DockerArguments @(
        "exec", $name, "python", "-c",
        "from docker_api import DockerClient; DockerClient('/var/run/docker.sock').ping()"
    )
    Invoke-Docker -DockerArguments @(
        "exec", $name, "test", "-s", "/state/secrets/replication-token"
    )
    $authStatus = docker exec $name python -c `
        "import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:6062/api/v1/auth/status'))))"
    if (($authStatus | ConvertFrom-Json).requires_replication_secret) {
        throw "el primer arranque sigue exigiendo un secreto en la plantilla"
    }
    $setupResult = docker exec $name python -c `
        "import json,urllib.request; payload={'username':'owner','display_name':'Owner','allow_insecure_portal':True,'password':'Owner-Lab-Password-882','password_confirmation':'Owner-Lab-Password-882'}; req=urllib.request.Request('http://127.0.0.1:6062/api/v1/auth/setup',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST'); res=urllib.request.urlopen(req); print(json.dumps({'status':res.status,'cookie':res.headers.get('Set-Cookie','')}))"
    $setupData = $setupResult | ConvertFrom-Json
    if ($setupData.status -ne 201 -or $setupData.cookie -match 'Secure') {
        throw "la elección HTTP del asistente no controló la cookie inicial"
    }
    Invoke-Docker -DockerArguments @(
        "exec", $name, "python", "-c",
        "import json; assert json.load(open('/state/portal-access.json'))['allow_insecure'] is True"
    )
    $version = docker exec $name python -c `
        "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:6062/api/health'))['version'])"
    if (-not $version) {
        throw "la API no anunció versión"
    }
}
finally {
    docker rm -f $name 2>$null | Out-Null
}

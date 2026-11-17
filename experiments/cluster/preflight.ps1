# Read-only Kubernetes client and node preflight. Does not print kubeconfig data.
[CmdletBinding()]
param(
    [string]$Kubectl = 'kubectl'
)

$ErrorActionPreference = 'Stop'

$kubectlCommand = Get-Command -Name $Kubectl -ErrorAction SilentlyContinue
if (-not $kubectlCommand) {
    throw "kubectl was not found. Install a version compatible with the target cluster and retry."
}

function Invoke-KubectlJson {
    param([string[]]$Arguments)
    $result = & $kubectlCommand.Source @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl $($Arguments -join ' ') failed: $($result -join ' ')"
    }
    return (($result -join "`n") | ConvertFrom-Json)
}

$currentContext = (& $kubectlCommand.Source config current-context 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "No usable current kubectl context: $currentContext"
}

$version = Invoke-KubectlJson -Arguments @('version', '-o', 'json')
$nodeList = Invoke-KubectlJson -Arguments @('get', 'nodes', '-o', 'json')

$nodes = @($nodeList.items | ForEach-Object {
    $ready = @($_.status.conditions | Where-Object { $_.type -eq 'Ready' } | Select-Object -Last 1)
    [ordered]@{
        name = $_.metadata.name
        ready = if ($ready.Count) { $ready[0].status } else { 'Unknown' }
        os = $_.status.nodeInfo.operatingSystem
        architecture = $_.status.nodeInfo.architecture
        kernel = $_.status.nodeInfo.kernelVersion
        runtime = $_.status.nodeInfo.containerRuntimeVersion
        kubelet = $_.status.nodeInfo.kubeletVersion
    }
})

$permissionChecks = @(
    @('create', 'namespaces'),
    @('create', 'daemonsets', '--namespace=default'),
    @('create', 'clusterroles'),
    @('create', 'clusterrolebindings')
)
$permissions = foreach ($check in $permissionChecks) {
    $answer = (& $kubectlCommand.Source auth can-i @check 2>&1) -join "`n"
    [ordered]@{
        action = $check -join ' '
        allowed = if ($LASTEXITCODE -eq 0) { $answer.Trim() } else { 'unknown' }
    }
}

[ordered]@{
    checkedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    context = $currentContext.Trim()
    clientVersion = $version.clientVersion.gitVersion
    serverVersion = $version.serverVersion.gitVersion
    nodes = $nodes
    permissions = @($permissions)
    note = 'Read-only API preflight. Audit policy, provider export, eBPF capability, and source fields require separate tests.'
} | ConvertTo-Json -Depth 8

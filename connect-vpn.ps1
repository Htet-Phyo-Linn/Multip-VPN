#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [string]$SingBoxPath = "",
    [string[]]$CustomerSubnets = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)

# Forward to the universal dynamic script
& "$PSScriptRoot\connect-hiddify.ps1" @PSBoundParameters

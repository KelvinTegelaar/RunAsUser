function Invoke-AsCurrentUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock,
        [Parameter(Mandatory = $false)]
        [switch]$NoWait
    )
    if (!("RunAsUser.ProcessExtensions" -as [type])) {
        Add-Type -TypeDefinition $script:source -Language CSharp
    }
    $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
    $privs = whoami /priv /fo csv | ConvertFrom-Csv | Where-Object { $_.'Privilege Name' -eq 'SeDelegateSessionUserImpersonatePrivilege' }
    if ($privs.State -eq "Disabled") {
        Write-Error -Message "Not running with correct privilege. You must run this script as system or have the SeDelegateSessionUserImpersonatePrivilege token."
        return
    }
    else {
        try {
            # Use the same PowerShell executable as the one that invoked the function
            $pwshPath = (Get-Process -Id $pid).Path
            if ($NoWait) { $ProcWaitTime = 1 } else { $ProcWaitTime = -1 }
           [RunAsUser.ProcessExtensions]::StartProcessAsCurrentUser(
                $pwshPath, "`"$pwshPath`" -ExecutionPolicy Bypass -Window Normal -EncodedCommand $($encodedcommand)",
                (Split-Path $pwshPath -Parent), $false,$ProcWaitTime)
        } catch {
            Write-Error -Message "Could not execute as currently logged on user: $($_.Exception.Message)" -Exception $_.Exception
            return
        }
    }
}
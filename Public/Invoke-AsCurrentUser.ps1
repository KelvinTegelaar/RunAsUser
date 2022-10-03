function Invoke-AsCurrentUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock,
        [Parameter(Mandatory = $false)]
        [switch]$NoWait,
        [Parameter(Mandatory = $false)]
        [switch]$UseWindowsPowerShell,
        [Parameter(Mandatory = $false)]
        [switch]$UseMicrosoftPowerShell,
        [Parameter(Mandatory = $false)]
        [switch]$NonElevatedSession,
        [Parameter(Mandatory = $false)]
        [switch]$Visible,
        [Parameter(Mandatory = $false)]
        [switch]$CacheToDisk,
        [Parameter(Mandatory = $false)]
        [switch]$CaptureOutput
    )
    if (!("RunAsUser.ProcessExtensions" -as [type])) {
        Add-Type -TypeDefinition $script:source -Language CSharp
    }
    if ($CacheToDisk) {
        $ScriptGuid = new-guid
        $null = New-item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Value $ScriptBlock -Force
        $pwshcommand = "-ExecutionPolicy Bypass -Window Normal -file `"$($ENV:TEMP)\$($ScriptGuid).ps1`""
    }
    else {
        $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
        $pwshcommand = "-ExecutionPolicy Bypass -Window Normal -EncodedCommand $($encodedcommand)"
    }
    $OSLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion
    if ($OSLevel -lt 6.2) { $MaxLength = 8190 } else { $MaxLength = 32767 }
    if ($encodedcommand.length -gt $MaxLength -and $CacheToDisk -eq $false) {
        Write-Error -Message "The encoded script is longer than the command line parameter limit. Please execute the script with the -CacheToDisk option."
        return
    }
    if ($UseMicrosoftPowerShell -and -not (Test-Path -Path "$env:ProgramFiles\PowerShell\7\pwsh.exe"))
    {
        Write-Error -Message "Not able to find Microsoft PowerShell v7 (pwsh.exe). Ensure that it is installed on this system"
        return
    }
    $privs = whoami /priv /fo csv | ConvertFrom-Csv | Where-Object { $_.'Privilege Name' -eq 'SeDelegateSessionUserImpersonatePrivilege' -or $_.'Nom de privilège' -eq 'SeDelegateSessionUserImpersonatePrivilege'}
    if (!$privs -or $privs.State -eq "Disabled") {
        Write-Error -Message "Not running with correct privilege. You must run this script as system or have the SeDelegateSessionUserImpersonatePrivilege token."
        return
    }
    else {
        try {
            # Use the same PowerShell executable as the one that invoked the function, Unless -UseWindowsPowerShell or -UseMicrosoftPowerShell is defined.
            $pwshPath = if ($UseWindowsPowerShell) { "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe" } 
            elseif ($UseMicrosoftPowerShell) { "$($env:ProgramFiles)\PowerShell\7\pwsh.exe" }
            else { (Get-Process -Id $pid).Path }
            
            if ($NoWait) { $ProcWaitTime = 1 } else { $ProcWaitTime = -1 }
            if ($NonElevatedSession) { $RunAsAdmin = $false } else { $RunAsAdmin = $true }
            [RunAsUser.ProcessExtensions]::StartProcessAsCurrentUser(
                $pwshPath, "`"$pwshPath`" $pwshcommand",
                (Split-Path $pwshPath -Parent), $Visible, $ProcWaitTime, $RunAsAdmin, $CaptureOutput)
            if ($CacheToDisk) { $null = remove-item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Force }
        }
        catch {
            Write-Error -Message "Could not execute as currently logged on user: $($_.Exception.Message)" -Exception $_.Exception
            return
        }
    }
}

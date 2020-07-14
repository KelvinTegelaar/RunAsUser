function Invoke-AsCurrentUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock
    )
    if (!("murrayju.ProcessExtensions.ProcessExtensions" -as [type])) {
        Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $script:source -Language CSharp
    }
    $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
    $privs = whoami /priv /fo csv | ConvertFrom-Csv | Where-Object { $_.'Privilege Name' -eq 'SeDelegateSessionUserImpersonatePrivilege' }
    if ($privs.State -eq "Disabled") {
        Throw [System.Exception] "Not running with correct privilege. You must run this script as system or have the SeDelegateSessionUserImpersonatePrivilege token."
    }
    else {
        [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser("C:\Windows\System32\WindowsPowershell\v1.0\Powershell.exe", "-bypassexecutionpolicy -Window Normal -EncodedCommand $($encodedcommand)", "C:\Windows\System32\WindowsPowershell\v1.0", $false) | Out-Null
    }
}
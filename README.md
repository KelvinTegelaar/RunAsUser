# RunAsUser Module

This module has been created to have the ability to run scripts under the current user session while the application executing this script only has SYSTEM access. This is especially useful when performing tasks from RMM(Remote Monitoring and Management) systems that do not have the abilty to execute monitoring components in user-space.

This script was originally based on [Murrayju](https://github.com/murrayju/CreateProcessAsUser) his work with CreateProcessAsUser, but has been pratically rewritten by [jborean93](https://github.com/jborean93) to support elevation.

# Installation instructions

This module has been published to the PowerShell Gallery. Use the following command to install:

    install-module RunAsUser

# Usage

To execute a script under the current user you'll need to run the script as SYSTEM using your RMM or other methods. To execute the script run the following command

    $scriptblock = { "Hello world" | out-file "C:\Temp\HelloWorld.txt" }
    invoke-ascurrentuser -scriptblock $scriptblock

The script will run, store a file with the results in C:\Temp\Helloworld.txt that you can pick up with another PowerShell command such as get-content. The command will wait until the execution of the command is finished. If you do not wish to wait for the command to finish you can use the -NoWait parameter.

    $scriptblock = { "Hello world" | out-file "C:\Temp\HelloWorld.txt" }
    invoke-ascurrentuser -scriptblock $scriptblock -NoWait

If you want to use the results of the output immediately, you can use the -CaptureOutput switch. This switch captures all output as plain-text. This means you'll have to convert this to a PowerShell Object yourself if you wish to use one:

    $scriptblock = { $PSVersiontable | Convertto-json }
    $JSON = invoke-ascurrentuser -scriptblock $scriptblock -CaptureOutput
    $JSON | ConvertFrom-Json

For longer scripts, that go over the limit of the command line cache, you can use the option -CacheToDisk. This will write the script to the $ENV:TEMP folder, and delete when execution has been done.

    $scriptblock = { SUPERLONGSCRIPTHERE }
    invoke-ascurrentuser -scriptblock $scriptblock -NoWait -CacheToDisk

At times the launching PowerShell version does not match the version you want the script to run under, some RMM systems initiate PowerShell scripts under their own executable. To prevent issues with this, use the "UseWindowsPowerShell" switch:

    $scriptblock = { "Hello world" | out-file "C:\Temp\HelloWorld.txt" }
    invoke-ascurrentuser -scriptblock $scriptblock -UseWindowsPowerShell

Sometimes you need to run an application that does not elevate itself, for this use the -NonElevatedSession switch:

    $scriptblock = { "Hello world" | out-file "C:\Temp\HelloWorld.txt" }
    invoke-ascurrentuser -NonElevatedSession -scriptblock $scriptblock

When you want to capture the output of your script invoked as the user then use the -CaptureOutput switch:
$scriptblock = { "Hello world" }
invoke-ascurrentuser -scriptblock $scriptblock -CaptureOutput

If you are executing in a context that results in a "Win32ErrorCode 5" access denied you may need to set the -Breakaway switch. 
The -Breakaway switch will start the process with CREATE_BREAKAWAY_FROM_JOB which starts the process outside any [job]https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects the caller may be in.

**Examples:**

To get the OneDrive files in the currently logged on user profile:

    $scriptblock = {
    $IniFiles = Get-ChildItem "$ENV:LOCALAPPDATA\Microsoft\OneDrive\settings\Business1" -Filter 'ClientPolicy*' -ErrorAction SilentlyContinue

    if (!$IniFiles) {
        write-host 'No Onedrive configuration files found. Stopping script.'
        exit 1
    }

    $SyncedLibraries = foreach ($inifile in $IniFiles) {
        $IniContent = get-content $inifile.fullname -Encoding Unicode
        [PSCustomObject]@{
            'Item Count' = ($IniContent | Where-Object { $_ -like 'ItemCount*' }) -split '= ' | Select-Object -last 1
            'Site Name'  = ($IniContent | Where-Object { $_ -like 'SiteTitle*' }) -split '= ' | Select-Object -last 1
            'Site URL'   = ($IniContent | Where-Object { $_ -like 'DavUrlNamespace*' }) -split '= ' | Select-Object -last 1
        }
    }
    $SyncedLibraries | ConvertTo-Json | Out-File 'C:\programdata\Microsoft OneDrive\OneDriveLibraries.txt'
    }
    Invoke-ascurrentuser -scriptblock $scriptblock
    $SyncedLibraries = (get-content "C:\programdata\Microsoft OneDrive\OneDriveLibraries.txt" | convertfrom-json)
    if (($SyncedLibraries.'Item count' | Measure-Object -Sum).sum -gt '280000') {
    write-host "Unhealthy - Currently syncing more than 280k files. Please investigate."
    $SyncedLibraries
    }
    else {
    write-host "Healthy - Syncing less than 280k files."
    }

As this script demonstrates, all user variables are the one of the current logged on user, instead of the SYSTEM account. You can also use this to browse the HCKU registry tree, or any files or shares to which only the user has access

Would run the start-sleep command for 60 seconds, but allow you to directly continue other tasks.

# Contributions

Feel free to send pull requests or fill out issues when you encounter them. I'm also completely open to adding direct maintainers/contributors and working together! :)

# Future plans

Version 1.8 includes all things I required for myself, if you need a feature, shoot me a feature request :)

- [x] Allow running scripts impersonating the currently logged on user
- [x] Allow running scripts impersonating the currently logged on user, with elevated token if the user is also a local administrator.
- [x] Allow running scripts impersonating the currently logged on user, with option to select if elevation is used or not.

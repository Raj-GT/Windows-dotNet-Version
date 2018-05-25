#Windows-dotNet-Version
*PowerShell script that generates a report of all .NET Framework versions installed on remote machines

The script will return a list of .NET Framework versions installed on a machine by filtering HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\. The script utilises WinRM to enumerate data from remote machines.

The following parameters are accepted by the script.
*Server
Single hostname or textfile with multiple hosts. When this parameter is omitted the script will run against the localhost. This parameter supports pipeline input.

*Credential
Administrator credentials for the servers to allow remote powershell access. This parameter is mandatory for scanning remote machines.

*Verbose
Print verbose information.

The script will return the following string objects - Hostname, Framework, Version, Release
In addition, a list of failed machines are returned inside $failed global variable.

EXAMPLES
    To get .NET Framework information from the localhost
    PS C:\>Get-dotNETversion.ps1

    To get .NET Framework information from a remote server
    PS C:\>Get-dotNETversion.ps1 -Server MyServer1 -Credential DOMAIN\Administrator

    To get .NET Framework information from a list of servers
    PS C:\>Get-dotNETversion.ps1 -Server MyServerList.txt -Credential DOMAIN\Administrator

    To get .NET Framework information for objects in the pipeline
    PS C:\>"server1","server2" | Get-dotNETversion.ps1 -Credential DOMAIN\Administrator
<#
.SYNOPSIS
    List versions of .NET Frameworks installed
    
.DESCRIPTION
    List versions of .NET Frameworks installed on a machine by reading from the registry keys. The script utilises WinRM to enumerate data from remote machines.
  
.PARAMETER Server
    Single hostname or textfile with multiple hosts to retrieve .NET versions information from. When this parameter is omitted the script will run against the localhost.

.PARAMETER Credential
    Administrator credentials for the servers to allow remote powershell access.
    
.EXAMPLE
    To get the .NET Framework information from the localhost
    PS C:\>Get-dotNETversion.ps1

.EXAMPLE
    To get the .NET Framework information from a remote server
    PS C:\>Get-dotNETversion.ps1 -Server MyServer1 -Credential DOMAIN\Administrator
    
.EXAMPLE
    To get the .NET Framework information from a list of servers
    PS C:\>Get-dotNETversion.ps1 -Server MyServerList.txt -Credential DOMAIN\Administrator

.INPUTS
    System.String, System.Management.Automation.PSCredential

.OUTPUTS
    System.String. Returns the following string objects - Hostname, Framework, Version, Release
    In addition, a list of failed hosts are returned inside $failed global variable

.NOTES    
    Version:    1.0
    Author:     Nimal Raj
    Revisions:  20/05/2018      Initial draft (1.0)

.LINK
    https://github.com/Raj-GT/Windows-dotNet-Version  
#>

#Requires -Version 3.0

#--------------------------------------------------------[Parameters]-------------------------------------------------------
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][Alias('Cn', 'PSComputerName','Servers','Computer')][String[]]$Server,
    [Parameter(Mandatory=$false)][Alias('Creds','Admin','User')][PSCredential] $Credential
)

Begin { # Start of Begin
#---------------------------------------------------------[Modules]---------------------------------------------------------

#--------------------------------------------------------[Variables]--------------------------------------------------------
$script:regkey = "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\"
$script:creds = $Credential
$global:failed =@()
$usage = @'
.\Get-dotNETversion.ps1 -server <hostname or list.txt> -Credential <admin credentials>

'@

#--------------------------------------------------------[Functions]--------------------------------------------------------
Function ReadNetVersion ($node) {
    $results = @()
    Write-Verbose -Message "Processing $node"

    # Read from local registry if scanning localhost
    If ($node -eq $env:computername) { 
        Write-Verbose -Message "Reading [$($node)]$($script:regkey)"
        Try { $keydump = Get-ChildItem "$script:regkey" -Recurse -ErrorAction Stop| Get-ItemProperty -Name Version,Release -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^[vCF]'} | Sort-Object Version}
        Catch { Write-Host "ERROR: $($Error[0])" -ForegroundColor Red; Exit }
    }

    # Try remote PowerShell and failback to remote registry
    Else {
        Write-Verbose -Message "Reading [$($node)]$($script:regkey)"
        Try { $keydump = Invoke-Command -ComputerName $node -Credential $script:creds -ScriptBlock { Get-ChildItem "$using:regkey" -Recurse | Get-ItemProperty -Name Version,Release -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^[vCF]'} | Sort-Object Version } -ErrorAction Stop }
        Catch { Write-Host "ERROR: $($Error[0])" -ForegroundColor Red; $global:failed += $node; Return }
    }
    
    # Hopefully should have data in $keydump now, but just in case...
    If (!($keydump)) { Write-Host "ERROR: No usable data returned by $($node)" -ForegroundColor Red; $global:failed += $node; Return }
 
    # Let's parse the data and build our ResultObject
    $i = 0
    While ($i -lt $keydump.Count) {
        $ResultObject = New-Object System.Object 
        $ResultObject | Add-member -Name Hostname -Type NoteProperty -Value $node
        $ResultObject | Add-member -Name Framework -Type NoteProperty -Value ((Split-Path $keydump.PSPath[$i] -NoQualifier).replace((Convert-Path "$script:regkey"),""))
        $ResultObject | Add-member -Name Version -Type NoteProperty -Value ($keydump[$i] | get-ItemPropertyValue -Name Version)
        If ($keydump[$i] | get-ItemProperty -Name Release -ErrorAction SilentlyContinue) { 
            $ResultObject | Add-member -Name Release -Type NoteProperty -Value (FindRelease($keydump[$i] | get-ItemPropertyValue -Name Release))
            }
        Else {
            $ResultObject | Add-member -Name Release -Type NoteProperty -Value "N/A"
        }   
        $results += $ResultObject
    $i = $i+1
    }  
return($results)
}

Function FindRelease ($release) {
    # Check and update as new releases are added...
    # https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
        Switch ($release) {
		    "378389" {$release = ".NET Framework 4.5";break}
		    "378675" {$release = ".NET Framework 4.5.1";break}
		    "378758" {$release = ".NET Framework 4.5.1";break}
		    "379893" {$release = ".NET Framework 4.5.2";break}
		    "393295" {$release = ".NET Framework 4.6";break}
		    "393297" {$release = ".NET Framework 4.6";break}
		    "394254" {$release = ".NET Framework 4.6.1";break}
		    "394271" {$release = ".NET Framework 4.6.1";break}
		    "394802" {$release = ".NET Framework 4.6.2";break}
		    "394806" {$release = ".NET Framework 4.6.2";break}
		    "460798" {$release = ".NET Framework 4.7";break}
		    "460805" {$release = ".NET Framework 4.7";break}
		    "461308" {$release = ".NET Framework 4.7.1";break}
		    "461310" {$release = ".NET Framework 4.7.1";break}
		    "461808" {$release = ".NET Framework 4.7.2";break}
		    "461814" {$release = ".NET Framework 4.7.2";break}
		    default {}
		}
return($release)
}
} # End of Begin

#--------------------------------------------------------[Execution]--------------------------------------------------------
Process {
    # Validate credential argument - mandatory when a servername or list is specified
    If (($server) -AND !($credential)) { Write-Host "ERROR: Credential is mandatory to scan remote servers." -ForegroundColor Red; Exit }
    
    # Print usage when called without arguments and proceed to output local machine
    If (!($server)) {
        Write-Host "USAGE: " -ForegroundColor Yellow -NoNewline
        Write-Host "$usage" -ForegroundColor Green
        $server = $env:computername
    }
    
    # Validate server argument and create list of servers to scan
    If ($server -match '.txt$') {
        Write-Verbose -Message "Reading content from file $server" 
        Try { $server = Get-Content -Path $server -ErrorAction Stop }
        Catch { Write-Host "ERROR: Unable to read file $server. Check file path and permissions and try again." -ForegroundColor Red; Exit }
	}

    # Main loop
    ForEach ($node in $server) { ReadNetVersion ($node) }
} # End of Process

#---------------------------------------------------------[Cleanup]---------------------------------------------------------
End {
    If ($failed.Count -gt 0) { Write-Host ""; Write-Warning -Message "Errors encountered while scanning some hosts; Check `$failed global variable for a list." }
}
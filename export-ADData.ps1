<#
 .SYNOPSIS
  Exports users, groups, and computers from Active Directory.
 
 .DESCRIPTION
  Exports users, groups, and computers from Active Directory to CSV files.
  Version: 0.8.0
 
 .PARAMETER DNPath
  (Alias -p) Mandatory. Mutually exclusive with -DNPrefix and -DCDepth. 
  Base of the Domain hierarchy from which you want to retrieve objects. Its 
  argument must be in DistinguishedName form like "DC=mydomain,DC=local" or 
  "OU=sales,DC=mydomain,DC=local". This parameter is much preferable than 
  its alternative -DNPrefix (below) for accuracy.
 
 .PARAMETER DNPrefix
  (Alias -d) Alternative method to -DNPath, and mutually exclusive with it. 
  Its argument must be in dotted format. For example: "unit.mydomain.local" 
  which is converted internally to DistinguishedName(=DNPath) 
  "OU=unit,DC=mydomain,DC=local".
 
 .PARAMETER DCDepth
  Optional. Can be used with -DNPrefix. Mutually exclusive with -DNPath. 
  In calculation of the DNPath, we assume the last 2 elements are DC 
  per default. If it is not what you expect, specify depth count of DC 
  with this. e.g., when -DNPrefix dept.unit.mydomain.local, then
   DCDepth 2: DNPath becomes OU=dept,OU=unit,DC=mydomain,DC=local
   DCDepth 3: DNPath becomes OU=dept,DC=unit,DC=mydomain,DC=local
 
 .PARAMETER OutPath
  (Alias -o) Optional. Folder path where you want to save output CSV files.
  Path selection dialog will prompt you to choose, if omitted.
 
 .PARAMETER Computer
  (Alias -comp) Optional. Export Computers only. Users and Groups are not
  processed.
 
 .PARAMETER ExcludeSystemObject
  (Alias -nosys) Optional. Exclude System objects such as 'Administrator(s)', 
  'Guest(s)', 'Domain Users' and trusted 'DOMAIN$'.
 
 .EXAMPLE
   # Export AD Users and Groups from the Domain root to CSV files in "C:\ADExport", excluding system objects
   .\export-ADData.ps1 -DNPath "DC=mydomain,DC=local" -OutPath "C:\ADExport" -ExcludeSystemObject
 
 .EXAMPLE
   # Export AD Users and Groups, specifying a specific hierarchy base.
   .\export-ADData.ps1 -DNPath "OU=unit,DC=mydomain,DC=local" -OutPath "C:\ADExport"

 .EXAMPLE
   # Export AD Computers from the domain root, making the script prompt for output folder via dialog
   .\export-ADData.ps1 -DNPath "DC=mydomain,DC=local" -Computer
#>
[CmdletBinding()]
param(
    [Parameter()]
    [Alias("p")]
    [string]$DNPath,

    [Parameter()]
    [Alias("d")]
    [string]$DNPrefix,

    [Parameter()]
    [int]$DCDepth = 2,

    [Parameter()]
    [Alias("o")]
    [string]$OutPath,

    [Parameter()]
    [Alias("comp")]
    [switch]$Computer,

    [Parameter()]
    [Alias("nosys")]
    [switch]$ExcludeSystemObject
)

begin {
    Import-Module ActiveDirectory -ErrorAction Stop

    # Arguments validation
    if ($PSBoundParameters.Count -eq 0) {
        Get-Help $MyInvocation.InvocationName
        exit
    }

    if (-not $PSBoundParameters.ContainsKey('DNPath')) {
        if ($PSBoundParameters.ContainsKey('DCDepth') -and -not $PSBoundParameters.ContainsKey('DNPrefix')) {
            throw "Error: -DNPrefix must be specified when using -DCDepth."
        }
        if (-not $PSBoundParameters.ContainsKey('DNPrefix')) {
            throw "Error: One of -DNPath or -DNPrefix is required."
        }
    }

    if ($PSBoundParameters.ContainsKey('DNPath') -and ($PSBoundParameters.ContainsKey('DNPrefix') -or $PSBoundParameters.ContainsKey('DCDepth'))) {
        throw "Error: -DNPath cannot be used together with -DNPrefix or -DCDepth."
    }
}

process {

    $scriptdir = Split-Path -Path $myInvocation.MyCommand.Path -Parent

    # Folder selection dialog
    function Get-Folder {
        Add-Type -AssemblyName System.Windows.Forms
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowser.Description = "Select the output folder"
        $folderBrowser.SelectedPath = $scriptdir
        if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $selectedPath = $folderBrowser.SelectedPath
            return $selectedPath
        }
        return ""
    }

    # Generate DN path from DN prefix
    function ConvertPrefixToDNPath {
        param (
            [string]$prefix,
            [int]$DCDepth
        )
        $domainParts = $prefix.Split('.')
        if ($domainParts.Count -lt 2) {
            Write-Error "Invalid prefix format: Expected at least two domain components (e.g., mydomain.local)"
            exit 1
        }
        if ($DCDepth -lt 1 -or $DCDepth -gt $domainParts.Count) {
            Write-Error "Invalid DCDepth: It must be at least 1 and at most the total number of domain components."
            exit 1
        }

        $DNPath = ""

        # Assume DC are the last DCDepth elements
        $dcParts = $domainParts[-$DCDepth..-1]

        # Assume the shallower elements are OU
        $ouParts = $domainParts[0..($domainParts.Count - $DCDepth - 1)]

        foreach ($ou in [array]::Reverse($ouParts)) {
            $DNPath += "OU=$ou,"
        }

        foreach ($dc in $dcParts) {
            $DNPath += "DC=$dc,"
        }

        return $DNPath.TrimEnd(',')
    }

    # Determine output folder path
    function Select-OutputFolderPath {
        $outputFolderPath = ""
        if (-not $OutPath) {
            $outputFolderPath = Get-Folder
        } else {
            $outputFolderPath = $OutPath
        }
        if (-not $outputFolderPath) {
            Write-Error "Output folder path is not specified"
            exit 1
        }
        return $outputFolderPath
    }

    # Check existence of the DN Path on the AD
    function Check-DNPathExistence {
        param ([string]$DNPath)

        # Validate DNPath format
        if ($DNPath -notmatch '^(CN|OU|DC)=[^,]+(,(CN|OU|DC)=[^,]+)*$') {
            Write-Error "Invalid DN format: $DNPath"
            return $false
        }

        # Check if DNPath exists in AD
        try {
            $exists = [adsi]::Exists("LDAP://$DNPath")
        } catch {
            return $false
        }
        return $exists
    }

    #
    ## Main
    #

    # Determine DNPath based on argument combination
    if ($PSBoundParameters.ContainsKey('DNPrefix')) {
        if ($DCDepth -lt 2) {
            Write-Error "Invalid DCDepth: $DCDepth. It must be 2 or greater"
            exit 1
        }

        $DNPath = ConvertPrefixToDNPath -prefix $DNPrefix -DCDepth $DCDepth
        if (-not $DNPath) {
            Write-Error "Error occurred while converting DNPrefix to DNPath"
            exit 1
        }
    }

    if (-not (Check-DNPathExistence -DNPath $DNPath)) {
        Write-Error "Invalid or non-existent DNPath: $DNPath"
        exit 1
    }

    write-host "DN Path = $DNPath"

    $outputFolderPath = Select-OutputFolderPath

    if (-not $DNPrefix) {
        $dnParts = $DNPath -split ',' | ForEach-Object { $_ -replace '^(OU=|DC=)', '' }
        if ($dnParts.Count -eq 0) {
            Write-Error "Failed to extract domain name from DNPath: $DNPath"
            exit 1
        }
        $domain = ($dnParts -join '_')
    } else {
        $domain = $DNPrefix.Replace('.', '_')
    }

    # Export Computers
    if ($Computer) {
        $computerOutputFilePath = $outputFolderPath + "\Computers_" + $domain + ".csv"
        Write-Host "Computer Output File Path = $computerOutputFilePath"

        # Properties to export for computers
        $computerExtraProps = "MemberOf", "ManagedBy", "*"

        # Specific system computer objects to exclude
        # You may extend $excludedComputers if necessary.
        # Critical system objects are dealt with by $ExcludeSystemObject parameter later on.
        $excludedComputers = @()  

        Get-ADComputer -Filter * -Properties $computerExtraProps -SearchBase "$DNPath" |
          Where-Object {
            if ($ExcludeSystemObject) {
                if ($_.isCriticalSystemObject -eq "TRUE" -or $_.sAMAccountName -in $excludedComputers) {
                    Write-Host "Excluded System Computer: $($_.sAMAccountName)"
                    return $false
                } else {
                    return $true
                }
            } else {
                return $true
            }
          } |
          Select-Object @{Name="MemberOf"; Expression={$_.MemberOf -join ";"}}, * -ExcludeProperty MemberOf |
            Export-Csv -Path $computerOutputFilePath -Encoding UTF8 -NoTypeInformation

        Write-Host "Exported AD Computers to $computerOutputFilePath"

        exit
    }
    # ..else, process Users and Groups

    # Export Users
    $userOutputFilePath = $outputFolderPath + "\Users_" + $domain + ".csv"
    write-host "User Output File Path = $userOutputFilePath"

    # Additional user properties we want to include in output
    $userExtraProps = "MemberOf", "EmailAddress", "HomePhone", "MobilePhone", "OfficePhone", "Title", "Department", "Manager", "LockedOut", "*"

    # Specific system user objects to exclude
    $excludedUsers = @("SUPPORT_388945a0")

    Get-ADUser -Filter * -Properties $userExtraProps -SearchBase "$DNPath" | 
      Where-Object {
        if ($ExcludeSystemObject) {
            if ($_.isCriticalSystemObject -eq "TRUE" -or $_.sAMAccountName -match '\$$' -or $_.sAMAccountName -in $excludedUsers) {
                Write-Host "Excluded System User: $($_.sAMAccountName)"
                return $false
            } else {
                return $true
            }
        } else {
            return $true
        }
      } | 
      Select-Object @{Name="MemberOf"; Expression={$_.MemberOf -join ";"}}, `
                    @{Name="Manager"; Expression={ if ($_.Manager) { (Get-ADUser -Identity $_.Manager).DistinguishedName } else { $null } }}, `
                    * -ExcludeProperty MemberOf, Manager | 
        Export-Csv -Path $userOutputFilePath -Encoding UTF8 -NoTypeInformation
        Write-Host "Exported AD Users to $userOutputFilePath"

    # Export Groups
    $groupOutputFilePath = $outputFolderPath + "\Groups_" + $domain + ".csv"
    write-host "Group Output File Path = $groupOutputFilePath"

    # Additional group properties we want to include in output
    $groupExtraProps = "MemberOf", "ManagedBy", "*"

    # Specific system group objects to exclude
    $excludedGroups = @("DnsAdmins", "DnsUpdateProxy", "HelpServicesGroup", "TelnetClients", "WINS Users",
                        "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins",
                        "Account Operators", "Server Operators", "Backup Operators", "Print Operators",
                        "Replicator", "Cert Publishers")

    Get-ADGroup -Filter * -Properties $groupExtraProps -SearchBase "$DNPath" | 
      Where-Object {
        if ($ExcludeSystemObject) {
            if ($_.isCriticalSystemObject -eq "TRUE" -or $_.sAMAccountName -in $excludedGroups) {
                Write-Host "Excluded System Group: $($_.sAMAccountName)"
                return $false
            } else {
                return $true
            }
        } else {
            return $true 
        }
      } | 
      Select-Object @{Name="MemberOf"; Expression={$_.MemberOf -join ";"}}, * -ExcludeProperty MemberOf |
        Export-Csv -Path $groupOutputFilePath -Encoding UTF8 -NoTypeInformation
        Write-Host "Exported AD Groups to $groupOutputFilePath"

# End of process
}

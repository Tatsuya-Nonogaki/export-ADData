<#
 .SYNOPSIS
  Test ConvertDNBase function.
 #>
[CmdletBinding()]
param(
)

begin {

    $TestDN = "CN=通関部,OU=通関部,DC=EDP-NTDM01,DC=local"
  # $TestDN = "CN=新営業第１部,CN=Users,DC=EDP-NTDM01,DC=local"
    $DNPath = "DC=mytestrealm,DC=local"

    $scriptdir = Split-Path -Path $myInvocation.MyCommand.Path -Parent
    $LogFilePath = "$scriptdir\convertDNBasetest.log"

    # Destination OU of users those originally belonged to CN=Users,<domainroot>.
    # "OU=$ImportOUName,$DNPath" will be created if it doesn't exist.
    $ImportOUName = "ImportUsers"

    function Write-Log {
        param (
            [string]$Message
        )
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$Timestamp - $Message" | Out-File -Append -FilePath $LogFilePath
    }

}

process {

    # Translate destination OU path from new object DN and DNPath
    function ConvertDNBase {
        param (
            [string]$oldDN,
            [string]$newDNPath,
            [switch]$CreateOUIfNotExists
        )

        # Obtain leading OU part
        $dnParts = $oldDN -split ","
        $ouParts = $dnParts | Where-Object { $_ -match "^OU=" }

        if ($ouParts) {
            $importTargetOU = "$($ouParts -join ","),$newDNPath"

            if ($CreateOUIfNotExists) {
                $ouList = $importTargetOU -split ","
                $currentPath = $newDNPath

                for ($i = ($ouList.Count - 1); $i -ge 0; $i--) {
                    if ($ouList[$i] -match "^OU=") {
                        $currentPath = "$ouList[$i],$currentPath"

                      # if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$currentPath'" -ErrorAction SilentlyContinue)) {
                            $ouName = $ouList[$i] -replace "^OU=", ""
                            $cmdstring = "New-ADOrganizationalUnit -Name $ouName -Path " + $($currentPath -replace ",$($ouList[$i])$") + " -ProtectedFromAccidentalDeletion `$false -ErrorAction Stop"
                            $cmdstring | Write-Host
                          # New-ADOrganizationalUnit -Name $ouName -Path ($currentPath -replace ",$ouList[$i]$") -ProtectedFromAccidentalDeletion $false
                            Write-Host "Created OU: $currentPath"
                            Write-Log "OU Created: DistinguishedName=$currentPath"
                      # }
                    }
                }
            }
            return $importTargetOU
        }
        elseif ($oldDN -match "^CN=.*?,CN=Users,") {
            $importTargetOU = "OU=$ImportOUName,$newDNPath"

            if ($CreateOUIfNotExists) {
              # if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$importTargetOU'" -ErrorAction SilentlyContinue)) {
                    New-ADOrganizationalUnit -Name $ImportOUName -Path $newDNPath -ErrorAction Stop
                    Write-Host "Created default Import OU: $importTargetOU"
                    Write-Log "OU Created: DistinguishedName=$importTargetOU"
              # }
            }

            Write-Host "Redirected CN=Users object `"$($dnParts[0])`" to: $importTargetOU"
            return $importTargetOU
        }
        else {
            Write-Host "No OU found in DN: $oldDN. Assigning default path: $newDNPath" -ForegroundColor Yellow
            return $newDNPath
        }
    }

    $ouPath = ConvertDNBase -oldDN $TestDN -newDNPath $DNPath -CreateOUIfNotExists

    Write-Host "ouPath = $ouPath"
    Write-Log "ouPath = $ouPath"

# End of process
}

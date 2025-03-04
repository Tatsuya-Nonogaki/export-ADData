<#
 .SYNOPSIS
  Imports group and users into Active Directory.
 
 .DESCRIPTION
  Imports group and users into Active Directory from CSV files.
  You can accomplish import of user only, group only, or both at a time.
  Version: 0.7.8a
 
 .PARAMETER DNPrefix
  (Alias -d) Mandatory. Mutually exclusive with DNPath. 
  Domain component into which you want import objects. 
  For example: "unit.mydomain.local" which is converted to 
  DistinguishedName(DNPath) "OU=unit,DC=mydomain,DC=local" internally.
  IMPORTANT: Target DN structure must exist on the destination AD before import.
 
 .PARAMETER DCDepth
  Optional. Mutually exclusive with DNPath. 
  In calculation of the DNPath, we assume the last 2 elements are DC 
  per default. If it is not what you expect, specify depth count of 
  DC with this. e.g., when -DNPath dept.unit.mydomain.local, then
   DCDepth 2: DNPath becomes OU=dept,OU=unit,DC=mydomain,DC=local
   DCDepth 3: DNPath becomes OU=dept,DC=unit,DC=mydomain,DC=local
  -DCDepth 4: DNPath becomes DC=dept,DC=unit,DC=mydomain,DC=local
 
 .PARAMETER DNPath
  (Alias -p) Optional. Mutually exclusive with DNPrefix and DCDepth. 
  Instead of specifying DNPrefix (optionally with DCDepth), you can 
  explicitly specify it in DistinguishedName format. This is preferable 
  for accuracy, if you are familiar with DN expression of AD components.
 
 .PARAMETER User
  (Alias -u) Operates in user import mode. If -UserFile (below)
  is specified, this switch is implied and can be omitted.
 
 .PARAMETER UserFile
  (Alias -uf) Optional. Path of input user CSV file. Path selection
  dialog will ask you if omitted despite -User switch is set.
  Note: If you want to register password to any users, make a copy of 
  the whole CSV file, add "Password" column to it, which is missing from 
  the original, and put password in plain text. Password is required to 
  set Enable flag of the account.
 
 .PARAMETER Group
  (Alias -g) Operates in group import mode. If -GroupFile (below)
  is specified, this switch is implied and can be omitted.
 
 .PARAMETER GroupFile
  (Alias -gf) Optional. Path of input group CSV file. Path selection
  dialog will ask you if omitted despite -Group switch is set.
 
 .PARAMETER IncludeSystemObject
  Optional. Import also users and groups which are critical system object, 
  such as: Administrator(s), Domain Admins and COMPUTER$ and trusted 
  DOMAIN$. This is usually dangerous and leads to AD system break down.
 
 .PARAMETER NewUPNSuffix
  Optional. New UserPrincipalName suffix to use for conversion. If not provided, 
  script will convert UPN based on DNPath.
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
    [Alias("u")]
    [switch]$User,

    [Parameter()]
    [Alias("uf")]
    [string]$UserFile,

    [Parameter()]
    [Alias("g")]
    [switch]$Group,

    [Parameter()]
    [Alias("gf")]
    [string]$GroupFile,

    [Parameter()]
    [switch]$IncludeSystemObject,

    [Parameter()]
    [string]$NewUPNSuffix
)

begin {
    Import-Module ActiveDirectory -ErrorAction Stop

    $scriptdir = Split-Path -Path $myInvocation.MyCommand.Path -Parent
    $LogFilePath = "$scriptdir\import-ADData.log"

    function Write-Log {
        param (
            [string]$Message
        )
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$Timestamp - $Message" | Out-File -Append -FilePath $LogFilePath
    }

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

    if (-not ($PSBoundParameters.ContainsKey('User') -or $PSBoundParameters.ContainsKey('UserFile') -or `
              $PSBoundParameters.ContainsKey('Group') -or $PSBoundParameters.ContainsKey('GroupFile'))) {
        throw "Error: At least one of -User, -UserFile, -Group, or -GroupFile must be specified."
    }
}

process {

    # File selection dialog
    function Select-Input-File {
        param (
            [string]$type
        )
        if ($type -eq "user") {
            $req = "user CSV file"
        } elseif ($type -eq "group") {
            $req = "group CSV file"
        }
        Add-Type -AssemblyName System.Windows.Forms
        $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog
        $fileBrowser.Title = "Select the $req"
        $fileBrowser.Filter = "CSV Files|*.csv|All Files|*.*"
        $fileBrowser.InitialDirectory = $scriptdir

        if ($fileBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            return $fileBrowser.FileName
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

    # Check existence of the DN Path on the AD
    function Check-DNPathExistence {
        param ([string]$DNPath)

        # Validate DNPath format
        if ($DNPath -notmatch "^(CN|OU|DC)=[^,]+(,(CN|OU|DC)=[^,]+)*$") {
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

    # Convert old DistinguishedName to new DN
    function Get-NewDN {
        param (
            [string]$originalDN,
            [string]$DNPath
        )

        if (-not $originalDN) {
            return ""
        }

        # Get whole CN=,CN=.. portion, everything before OU or DC in other words
        if ($originalDN -match "^(CN=[^,]+(?:,CN=[^,]+)*)") {
            $relativeDN = $matches[1]
        } else {
            Write-Host "Warning: Could not parse DN for $originalDN, using original DN" -ForegroundColor Yellow
            Write-Log "Get-NewDN : Could not parse DN for $originalDN, using original DN"
            $relativeDN = $originalDN
        }

        return "${relativeDN},$DNPath"
    }

    # Return translated parent path of the given object and create OUs if they don't exist
    function ConvertDNBase {
        param (
            [string]$oldDN,
            [string]$newDNPath,
            [switch]$CreateOUIfNotExists
        )

        # Obtain leading OU part
        $dnParts = $oldDN -split ","
        $ouParts = $dnParts | Where-Object { $_ -match "^OU=" }
        $newDNPathHasOU = if ($newDNPath -match '^OU=') { $true }

        if ($ouParts) {
            $importTargetOU = "$($ouParts -join ","),$newDNPath"

            Write-Log "debug :: importTargetOU = $importTargetOU"
            if ($CreateOUIfNotExists) {
                $ouList = $importTargetOU -split ",\s*" | Where-Object { $_ -match "^OU=" }
                [array]::Reverse($ouList)
                $previousOUBase = ""

                # Create parent OUs from parent to child
                foreach ($ou in $ouList) {
                    $ou = $ou.Trim()
                    Write-Log "debug :: processing ou = $ou"
                    $ouName = $ou -replace "^OU=", ""

                    if ($previousOUBase) {
                        $currentOUBase = $previousOUBase
                    } else {
                        # Remove preceding non-DC components from DNPath
                        $currentOUBase = $newDNPath -replace '^(OU=[^,]+,)*', ''
                    }

                    Write-Log "debug :: currentOUBase = $currentOUBase"

                    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '${ou},$currentOUBase'" -ErrorAction SilentlyContinue)) {
                        try {
                            if (($currentOUBase -eq $newDNPath) -and -not $newDNPathHasOU) {
                                New-ADOrganizationalUnit -Name $ouName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                                Write-Log "New-ADOrganizationalUnit -Name $ouName -ProtectedFromAccidentalDeletion `$false"
                            } else {
                                New-ADOrganizationalUnit -Name $ouName -Path $currentOUBase -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                                Write-Log "New-ADOrganizationalUnit -Name $ouName -Path $currentOUBase -ProtectedFromAccidentalDeletion `$false"
                            }

                            Write-Host "OU Created: ${ou},$currentOUBase"
                            Write-Log "OU Created: ${ou},$currentOUBase"
                        } catch {
                            Write-Error "Failed to create OU ${ou},$currentOUBase"
                            Write-Log "Failed to create OU: ${ou},$currentOUBase - $_"
                        }
                    } else {
                        Write-Log "OU: DistinguishedName=${ou},$currentOUBase already exists, skipping creation"
                    }
                    $previousOUBase = "OU=${ouName},$currentOUBase"
                }
            }
            return $importTargetOU
        }
        elseif ($oldDN -match "^CN=.*?,CN=Users,DC=") {
            if ($newDNPathHasOU) {
                # Place directly under the specified DNPath without intermediate CN=Users
                $importTargetOU = $newDNPath
                Write-Log "Redirected CN=Users object: $oldDN to: $importTargetOU"

                if ($CreateOUIfNotExists) {
                    $ouList = $newDNPath -split ",\s*" | Where-Object { $_ -match "^OU=" }
                    [array]::Reverse($ouList)
                    $previousOUBase = ""

                    foreach ($ou in $ouList) {
                        $ou = $ou.Trim()
                        Write-Log "debug :: processing ou = $ou"
                        $ouName = $ou -replace "^OU=", ""

                        if ($previousOUBase) {
                            $currentOUBase = $previousOUBase
                        } else {
                            $currentOUBase = $newDNPath -replace '^(OU=[^,]+,)*', ''
                        }

                        Write-Log "debug :: currentOUBase = $currentOUBase"

                        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '${ou},$currentOUBase'" -ErrorAction SilentlyContinue)) {
                            try {
                                if ($currentOUBase -eq $newDNPath) {
                                    New-ADOrganizationalUnit -Name $ouName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                                    Write-Log "New-ADOrganizationalUnit -Name $ouName -ProtectedFromAccidentalDeletion `$false"
                                } else {
                                    New-ADOrganizationalUnit -Name $ouName -Path $currentOUBase -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                                    Write-Log "New-ADOrganizationalUnit -Name $ouName -Path $currentOUBase -ProtectedFromAccidentalDeletion `$false"
                                }

                                Write-Host "OU Created: ${ou},$currentOUBase"
                                Write-Log "OU Created: ${ou},$currentOUBase"
                            } catch {
                                Write-Error "Failed to create OU ${ou},$currentOUBase"
                                Write-Log "Failed to create OU: ${ou},$currentOUBase - $_"
                            }
                        } else {
                            Write-Log "OU: DistinguishedName=${ou},$currentOUBase already exists, skipping creation"
                        }
                        $previousOUBase = "OU=${ouName},$currentOUBase"
                    }
                }
                return $importTargetOU
            } else {
                $importTargetOU = "CN=Users," + ($newDNPath -replace '^(OU=[^,]+,)*', '')
                Write-Log "Redirected CN=Users object: $oldDN to: $importTargetOU"
                return $importTargetOU
            }
        }
        else {
            Write-Host "No OU found in DN: $oldDN. Assigning default path: $newDNPath" -ForegroundColor Yellow
            Write-Log "No OU found in DN: $oldDN. Assigning default path: $newDNPath"
            return $newDNPath
        }
    }

    # Import AD objects from the CSV file
    function Import-ADObject {
        param (
            [string]$filePath,
            [string]$objectClass
        )

        if ($objectClass -eq "user") {
            Import-Csv -Path $filePath | 
              Where-Object {
                # Exclude system user objects
                if ($IncludeSystemObject) {
                    return $true 
                } else {
                    if ($_.isCriticalSystemObject -eq "TRUE" -or $_.sAMAccountName -match '\$$') {
                        Write-Host "Excluded System User: $($_.sAMAccountName)"
                        Write-Log "Excluded System User: sAMAccountName=$($_.sAMAccountName)"
                        return $false
                    } else {
                        return $true
                    }
                }
              } | 
                ForEach-Object {
                    $objectProps = $_
                    $sAMAccountName = $_.sAMAccountName

                    # Check existence of the user
                    $userExists = Get-ADUser -Filter "SamAccountName -eq '$sAMAccountName'" -ErrorAction SilentlyContinue

                    if (-not $userExists) {
                        # Construct parameters for New-ADUser

                        $ouPath = ConvertDNBase -oldDN $_.DistinguishedName -newDNPath $DNPath -CreateOUIfNotExists
                        $managerDN = if ($_.Manager -ne "") { Get-NewDN -originalDN $_.Manager -DNPath $DNPath } else { $null }

                        # Convert UserPrincipalName to new suffix
                        $upnParts = $_.UserPrincipalName -split "@"
                        $upnPrefix = $upnParts[0]
                        $upnSuffix = if ($PSBoundParameters.ContainsKey('NewUPNSuffix')) { $NewUPNSuffix } else { $DNPath -replace "OU=.*?,", "" -replace "DC=", "" -replace ",", "." }
                        $newUserPrincipalName = "${upnPrefix}@${upnSuffix}"

                        $newUserParams = @{
                            Name              = $_.Name
                            DisplayName       = $_.DisplayName
                            SamAccountName    = $sAMAccountName
                            Description       = $_.Description
                            UserPrincipalName = $newUserPrincipalName
                            GivenName         = $_.GivenName
                            Surname           = $_.Surname
                            Manager           = $managerDN
                        }

                        Try {
                            if ($ouPath -match "^CN=Users,DC=") {
                                New-ADUser @newUserParams -ErrorAction Stop
                                Write-Log "New-ADUser `@newUserParams"
                            } else {
                                New-ADUser @newUserParams -Path $ouPath -ErrorAction Stop
                                Write-Log "New-ADUser `@newUserParams -Path $ouPath"
                            }
                        } Catch {
                            Write-Error "Failed to create user ${sAMAccountName}: $_"
                            Write-Log "Failed to create user: sAMAccountName=$sAMAccountName - $_"
                        }

                        $createdUser = Get-ADUser -Filter "SamAccountName -eq '$sAMAccountName'" -Properties DistinguishedName
                        if ($createdUser) {
                            Write-Host "User Created DistinguishedName=$($createdUser.DistinguishedName)"
                            Write-Log "User Created: sAMAccountName=$sAMAccountName, DistinguishedName=$($createdUser.DistinguishedName)"
                        }

                        # Set additional properties using Set-ADUser
                        $additionalProperties = @{
                            ProfilePath   = $_.ProfilePath
                            ScriptPath    = $_.ScriptPath
                            Company       = $_.Company
                            Department    = $_.Department
                            Title         = $_.Title
                            Office        = $_.Office
                            OfficePhone   = $_.OfficePhone
                            EmailAddress  = $_.EmailAddress
                            StreetAddress = $_.StreetAddress
                            City          = $_.City
                            State         = $_.State
                            Country       = $_.Country
                            PostalCode    = $_.PostalCode
                            MobilePhone   = $_.MobilePhone
                            HomePhone     = $_.HomePhone
                            Fax           = $_.Fax
                            Pager         = $_.Pager
                        }

                        foreach ($property in $additionalProperties.Keys) {
                            if ($additionalProperties[$property] -ne $null -and $additionalProperties[$property] -ne "") {
                                $params = @{
                                    Identity = $sAMAccountName
                                }
                                $params[$property] = $additionalProperties[$property]
                                Try {
                                    Set-ADUser @params
                                    Write-Host "  => Property $property set for user: $sAMAccountName"
                                    Write-Log "Property $property set for user: sAMAccountName=$sAMAccountName"
                                } Catch {
                                    Write-Host "Warning: Failed to set property $property for user ${sAMAccountName}" -ForegroundColor Yellow
                                    Write-Log "Failed to set property $property for user: sAMAccountName=$sAMAccountName - $_"
                                }
                            }
                        }

                        # Set password if the CSV provides Password
                        if ($_.PSObject.Properties.Name -contains "Password" -and $_.Password -ne "") {
                            try {
                                $securePassword = ConvertTo-SecureString -String $_.Password -AsPlainText -Force
                                Set-ADAccountPassword -Identity $sAMAccountName -NewPassword $securePassword -Reset
                                Write-Host "  => Password set for user: $sAMAccountName"
                                Write-Log "Password set for user: sAMAccountName=$sAMAccountName"
                            } catch {
                                Write-Error "Failed to set password for user ${sAMAccountName}: $_"
                                Write-Log "Failed to set password for user: sAMAccountName=$sAMAccountName - $_"
                            }
                        }

                        # Set "userAccountControl" property related special control bits
                        try {
                            $userFlags = [int]$_.userAccountControl

                            if ($userFlags -band 0x80000) {                  # MustChangePassword
                                Set-ADUser -Identity $sAMAccountName -ChangePasswordAtLogon $true
                                Write-Host "  => MustChangePassword applied: ${sAMAccountName}"
                                Write-Log "MustChangePassword applied: sAMAccountName=${sAMAccountName}"
                            }
                            if ($userFlags -band 0x40) {                     # CannotChangePassword
                                $user = Get-ADUser -Identity $sAMAccountName
                                Set-ACL -Path "AD:\$($user.DistinguishedName)" -AclObject (Get-ACL -Path "AD:\$($user.DistinguishedName)" | ForEach-Object { $_.Access | Where-Object { $_.ObjectType -eq [guid]"00299570-246d-11d0-a768-00aa006e0529" } })
                                Write-Host "  => CannotChangePassword applied: ${sAMAccountName}"
                                Write-Log "CannotChangePassword applied: sAMAccountName=${sAMAccountName}"
                            }
                            if ($userFlags -band 0x10000) {                  # PasswordNeverExpires
                                Set-ADUser -Identity $sAMAccountName -PasswordNeverExpires $true
                                Write-Host "  => PasswordNeverExpires applied: ${sAMAccountName}"
                                Write-Log "PasswordNeverExpires applied: sAMAccountName=${sAMAccountName}"
                            }

                            # Enable or disable the account only if the password is set
                            if ($userFlags -band 2) {
                                Disable-ADAccount -Identity $sAMAccountName
                                Write-Host "  => Account disabled: ${sAMAccountName}"
                                Write-Log "Account disabled: sAMAccountName=${sAMAccountName}"
                            } else {
                                if ($_.PSObject.Properties.Name -contains "Password" -and $_.Password -ne "") {
                                    Enable-ADAccount -Identity $sAMAccountName
                                    Write-Host "  => Account enabled: ${sAMAccountName}"
                                    Write-Log "Account enabled: sAMAccountName=${sAMAccountName}"
                                } else {
                                    Write-Host "Warning: Cannot enable account ${sAMAccountName} as no password is set" -ForegroundColor Yellow
                                    Write-Log "Cannot enable account ${sAMAccountName} as no password is set"
                                }
                            }
                        } catch {
                            Write-Error "Failed to set userAccountControl flags for user ${sAMAccountName}: $_"
                            Write-Log "Failed to set userAccountControl flags for user ${sAMAccountName}: $_"
                        }

                        # Add this user to groups
                        $memberOfGroups = $_.MemberOf -split ';'
                        foreach ($group in $memberOfGroups) {
                            if ($group -ne "") {
                                try {
                                    $newDN = Get-NewDN -originalDN $group -DNPath $DNPath

                                    Add-ADGroupMember -Identity $newDN -Members $($createdUser.DistinguishedName)
                                    Write-Host "Added user $sAMAccountName to group: $newDN"
                                    Write-Log "User: sAMAccountName=$sAMAccountName added to group: $newDN"
                                } catch {
                                    Write-Host "Failed to add user $sAMAccountName to group $newDN. Error: $_" -ForegroundColor Red
                                    Write-Log "Failed to add user sAMAccountName=$sAMAccountName to group: $newDN - $_"
                                }
                            }
                        }
                    } else {
                        Write-Host "User $sAMAccountName already exists; skipping import"
                        Write-Log "User Skipped (Already Exists): sAMAccountName=$sAMAccountName"
                    }
                }

        } elseif ($objectClass -eq "group") {
            $excludedGroups = @("DnsAdmins", "DnsUpdateProxy", "HelpServicesGroup", "TelnetClients", "WINS Users",
                                "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins",
                                "Account Operators", "Server Operators", "Backup Operators", "Print Operators",
                                "Replicator", "Cert Publishers")

            # Import and sort groups by the total character length of MemberOf property
            $groups = Import-Csv -Path $filePath | 
                      Where-Object {
                        if ($IncludeSystemObject) {
                            return $true 
                        } else {
                            if ($_.isCriticalSystemObject -eq "TRUE" -or $_.sAMAccountName -in $excludedGroups) {
                                Write-Host "Excluded System Group: $($_.sAMAccountName)"
                                Write-Log "Excluded System Group: sAMAccountName=$($_.sAMAccountName)"
                                return $false
                            } else {
                                return $true
                            }
                        }
                      } | Sort-Object { $_.MemberOf.Length }

            foreach ($group in $groups) {
                $objectProps = $group
                $sAMAccountName = $group.sAMAccountName

                # Check existence of the group
                $groupExists = Get-ADGroup -Filter "SamAccountName -eq '$sAMAccountName'" -ErrorAction SilentlyContinue

                if (-not $groupExists) {
                    # Construct parameters for New-ADGroup

                    $ouPath = ConvertDNBase -oldDN $group.DistinguishedName -newDNPath $DNPath -CreateOUIfNotExists
                    $NewManagedBy = Get-NewDN -originalDN $group.ManagedBy -DNPath $DNPath

                    $newGroupParams = @{
                        Name           = $group.Name    # or $group.CN
                        SamAccountName = $sAMAccountName
                        Description    = $group.Description
                        # ManagedBy    = $NewManagedBy   # produces error when DN missing on new AD
                        GroupCategory  = "Security" # modified later if necessary
                        GroupScope     = "Global"   # modified later if necessary
                        # Define other properties here if needed
                    }

                    # Determine GroupCategory based on CSV values
                    if ($group.groupType -band 0x80000000) {
                        $newGroupParams.GroupCategory = "Security"
                    } else {
                        $newGroupParams.GroupCategory = "Distribution"
                    }

                    # Determine GroupScope based on CSV values
                    if ($group.groupType -band 0x2) {
                        $newGroupParams.GroupScope = "Global"
                    } elseif ($group.groupType -band 0x4) {
                        $newGroupParams.GroupScope = "DomainLocal"
                    } elseif ($group.groupType -band 0x8) {
                        $newGroupParams.GroupScope = "Universal"
                    }

                    Try {
                        if ($ouPath -match "^CN=Users,DC=") {
                            New-ADGroup @newGroupParams -ErrorAction Stop
                            Write-Log "New-ADGroup `@newGroupParams"
                        } else {
                            New-ADGroup @newGroupParams -Path $ouPath -ErrorAction Stop
                            Write-Log "New-ADGroup `@newGroupParams -Path $ouPath"
                        }
                    } Catch {
                        Write-Error "Failed to create group ${sAMAccountName}: $_"
                        Write-Log "Failed to create group: sAMAccountName=$sAMAccountName - $_"
                    }

                    $createdGroup = Get-ADGroup -Filter "SamAccountName -eq '$sAMAccountName'" -Properties DistinguishedName
                    if ($createdGroup) {
                        Write-Host "Group Created DistinguishedName=$($createdGroup.DistinguishedName)"
                        Write-Log "Group Created: sAMAccountName=$sAMAccountName, DistinguishedName=$($createdGroup.DistinguishedName)"
                    }

                    # Add this group to parent groups
                    $memberOfGroups = $group.MemberOf -split ';'
                    foreach ($parentGroup in $memberOfGroups) {
                        if ($parentGroup -ne "") {
                            try {
                                $newDN = Get-NewDN -originalDN $parentGroup -DNPath $DNPath

                                Add-ADGroupMember -Identity $newDN -Members $($createdGroup.DistinguishedName)
                                Write-Host "Added group $sAMAccountName to parent group: $newDN"
                                Write-Log "Group: sAMAccountName=$sAMAccountName added to group: $newDN"
                            } catch {
                                Write-Host "Failed to add group $sAMAccountName to group $newDN. Error: $_" -ForegroundColor Red
                                Write-Log "Failed to add group sAMAccountName=$sAMAccountName to group: $newDN - $_"
                            }
                        }
                    }
                } else {
                    Write-Host "Group $sAMAccountName already exists; skipping import"
                    Write-Log "Group Skipped (Already Exists): sAMAccountName=$sAMAccountName"
                }
            }
        }
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

    Write-Host "Target DN Path: $DNPath"

    # Group data import
    if ($Group -or $GroupFile) {
        # Select the group file if not specified
        if (-not $GroupFile) {
            $GroupFile = Select-Input-File -type "group"
        }
        if (-not (Test-Path $GroupFile)) {
            Write-Error "Specified GroupFile does not exist"
            exit 1
        }
        Write-Host "Group File Path: $GroupFile"
        Import-ADObject -filePath $GroupFile -objectClass "group"
    }

    # User data import
    if ($User -or $UserFile) {
        # Select the user file if not specified
        if (-not $UserFile) {
            $UserFile = Select-Input-File -type "user"
        }
        if (-not (Test-Path $UserFile)) {
            Write-Error "Specified UserFile does not exist"
            exit 1
        }
        Write-Host "User File Path: $UserFile"
        Import-ADObject -filePath $UserFile -objectClass "user"
    }

# End of process
}

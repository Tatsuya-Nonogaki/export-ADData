<#
 .SYNOPSIS
  Imports group and users into Active Directory.

 .DESCRIPTION
  Imports group and users into Active Directory from CSV files.
  You can accomplish import of user only, group only, or both at a time.
  Version: 0.7.4a

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
  the original, and put password in plain text.

 .PARAMETER Group
  (Alias -g) Operates in group import mode. If -GroupFile (below)
  is specified, this switch is implied and can be omitted.

 .PARAMETER GroupFile
  (Alias -gf) Optional. Path of input group CSV file. Path selection
  dialog will ask you if omitted despite -Group switch is set.

 .PARAMETER IncludeSystemObject
  Optional. Import also users and groups which are critical system object, 
  such as: Administrator(s), Domain Admins and COMPUTER$ and trusted 
  DOMAIN$. This is usually dangerous and leads to AD system beak down.
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
    [switch]$IncludeSystemObject
)

begin {
    Import-Module ActiveDirectory -ErrorAction Stop

    $scriptdir = Split-Path -Path $myInvocation.MyCommand.Path -Parent
    $LogFilePath = "$scriptdir\import-ADData.log"

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

        # Assume the shalower elements are OU
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

    # Convert old DistinguishedName to new DN, based on DNPrefix argument
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
            $relativeDN = $originalDN
        }

        return "$relativeDN,$DNPath"
    }

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

                        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$currentPath'" -ErrorAction SilentlyContinue)) {
                            $ouName = $ouList[$i] -replace "^OU=", ""
                            New-ADOrganizationalUnit -Name $ouName -Path ($currentPath -replace ",$ouList[$i]$") -ProtectedFromAccidentalDeletion $false
                            Write-Host "Created OU: $currentPath"
                            Write-Log "OU Created: DistinguishedName=$currentPath"
                        }
                    }
                }
            }
            return $importTargetOU
        }
        elseif ($oldDN -match "^CN=.*?,CN=Users,") {
            $importTargetOU = "OU=$ImportOUName,$newDNPath"
    
            if ($CreateOUIfNotExists) {
                if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$importTargetOU'" -ErrorAction SilentlyContinue)) {
                    New-ADOrganizationalUnit -Name $ImportOUName -Path $newDNPath -ErrorAction Stop
                    Write-Host "Created default Import OU: $importTargetOU"
                    Write-Log "OU Created: DistinguishedName=$importTargetOU"
                }
            }
    
            Write-Host "Redirected CN=Users object `"$($dnParts[0])`" to: $importTargetOU"
            return $importTargetOU
        }
        else {
            Write-Host "No OU found in DN: $oldDN. Assigning default path: $newDNPath" -ForegroundColor Yellow
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

                        $newUserParams = @{
                            Name              = $_.Name
                            DisplayName       = $_.DisplayName
                            SamAccountName    = $sAMAccountName
                            Description       = $_.Description
                            Path              = $ouPath
                            UserPrincipalName = $_.UserPrincipalName
                            GivenName         = $_.GivenName
                            Surname           = $_.Surname
                            Department        = $_.Department
                            Title             = $_.Title
                            Manager           = $managerDN
                            # Define EmailAddress or other properties here if needed
                        }

                        $excludedProperties = @("objectClass", "sAMAccountName", "Password", "Enabled", "userAccountControl", 
                               "LockedOut", "PasswordNeverExpires", "CannotChangePassword", "PasswordNotRequired")

                        Try {
                            New-ADUser @newUserParams -ErrorAction Stop

                            $createdUser = Get-ADUser -Filter "SamAccountName -eq '$sAMAccountName'" -Properties DistinguishedName
                            if ($createdUser) {
                                Write-Log "User Created: sAMAccountName=$sAMAccountName, DistinguishedName=$($createdUser.DistinguishedName)"
                            } else {
                                Write-Log "User Created: sAMAccountName=$sAMAccountName - (Failed to retrieve DN)"
                            }

                            # Add properties except password related
                            $setUserProps = @{}
                            foreach ($key in $objectProps.PSObject.Properties.Name) {
                                if ($null -ne $objectProps.$key -and $key -notin $excludedProperties) {
                                    $setUserProps[$key] = $objectProps.$key
                                }
                            }
                            if ($setUserProps.Count -gt 0) {
                                Set-ADUser -Identity $sAMAccountName @setUserProps -ErrorAction Stop
                            }

                            # Set "userAccountControl" propertiy related special control bits
                            try {
                                $userFlags = [int]$_.userAccountControl

                                if ($userFlags -band 0x80000) {                  # MustChangePassword
                                    Set-ADUser -Identity $sAMAccountName -ChangePasswordAtLogon $true
                                    Write-Host "  => MustChangePassword applied: $sAMAccountName"
                                    Write-Log "MustChangePassword applied: sAMAccountName=$sAMAccountName"
                                }
                                if ($userFlags -band 0x40) {                     # CannotChangePassword
                                    $user = Get-ADUser -Identity $sAMAccountName
                                    Set-ACL -Path "AD:\$($user.DistinguishedName)" -AclObject (Get-ACL -Path "AD:\$($user.DistinguishedName)" | ForEach-Object { $_.Access | Where-Object { $_.ObjectType -eq "Self" } } | ForEach-Object { $_.AccessControlType = "Deny"; $_ })
                                    Write-Host "  => CannotChangePassword applied: $sAMAccountName"
                                    Write-Log "CannotChangePassword applied: sAMAccountName=$sAMAccountName"
                                }
                                if ($userFlags -band 0x10000) {                  # PasswordNeverExpires
                                    Set-ADUser -Identity $sAMAccountName -PasswordNeverExpires $true
                                    Write-Host "  => PasswordNeverExpires applied: $sAMAccountName"
                                    Write-Log "PasswordNeverExpires applied: sAMAccountName=$sAMAccountName"
                                }

                                # Enable or disable the account
                                if ($userFlags -band 2) {
                                    Disable-ADAccount -Identity $sAMAccountName
                                    Write-Host "  => Account disabled: $sAMAccountName"
                                    Write-Log "Account disabled: sAMAccountName=$sAMAccountName"
                                } else {
                                    Enable-ADAccount -Identity $sAMAccountName
                                    Write-Host "  => Account enabled: $sAMAccountName"
                                    Write-Log "Account enabled: sAMAccountName=$sAMAccountName"
                                }
                            } catch {
                                Write-Error "Failed to set userAccountControl flags for user $sAMAccountName: $_"
                                Write-Log "Failed to set userAccountControl flags for user $sAMAccountName: $_"
                            }

                            # Set password if the CSV provides Password
                            if ($_.PSObject.Properties.Name -contains "Password" -and $_.Password -ne "") {
                                try {
                                    $securePassword = ConvertTo-SecureString -String $_.Password -AsPlainText -Force
                                    Set-ADAccountPassword -Identity $sAMAccountName -NewPassword $securePassword -Reset
                                    Write-Host "  => Password set for user: $sAMAccountName"
                                    Write-Log "Password set for user: sAMAccountName=$sAMAccountName"
                                } catch {
                                    Write-Error "Failed to set password for user $sAMAccountName: $_"
                                    Write-Log "Failed to set password for user: sAMAccountName=$sAMAccountName - $_"
                                }
                            } else {
                                Write-Host "  => No password provided for user: $sAMAccountName, skipping password setup"
                            }

                            # Add this user to groups
                            $memberOfGroups = $_.MemberOf -split ';'
                            foreach ($group in $memberOfGroups) {
                                if ($group -ne "") {
                                    try {
                                        $newDN = Get-NewDN -originalDN $group -DNPath $DNPath
                                        Add-ADGroupMember -Identity $newDN -Members $($createdGroup.DistinguishedName)
                                        Write-Host "Added user $sAMAccountName to group: $newDN"
                                        Write-Log "User: sAMAccountName=$sAMAccountName added to group: $newDN"
                                    } catch {
                                        Write-Host "Failed to add user $sAMAccountName to group $newDN. Error: $_" -ForegroundColor Red
                                        Write-Log "Failed to add user sAMAccountName=$sAMAccountName to group: $newDN - $_"
                                    }
                                }
                            }
                            Write-Host "Imported user: $sAMAccountName"
                        } Catch {
                            Write-Error "Failed to import user $sAMAccountName: $_"
                            Write-Log "Failed to create user: sAMAccountName=$sAMAccountName - $_"
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

            Import-Csv -Path $filePath | 
              Where-Object {
                # Exclude system group objects
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
              } | 
                ForEach-Object {
                    $objectProps = $_
                    $sAMAccountName = $_.sAMAccountName

                    # Check existence of the group
                    $groupExists = Get-ADGroup -Filter "SamAccountName -eq '$sAMAccountName'" -ErrorAction SilentlyContinue

                    if (-not $groupExists) {
                        # Construct parameters for New-ADGroup

                        $ouPath = ConvertDNBase -oldDN $_.DistinguishedName -newDNPath $DNPath -CreateOUIfNotExists
                        $NewManagedBy = Get-NewDN -originalDN $_.ManagedBy -DNPath $DNPath

                        $newGroupParams = @{
                            Name           = $_.Name    # or $_.CN
                            SamAccountName = $sAMAccountName
                            Description    = $_.Description
                            Path           = $ouPath
                          # ManagedBy      = $NewManagedBy   # produces error when DN missing on new AD
                            GroupCategory  = "Security" # modified later if necessary
                            GroupScope     = "Global"   # modified later if necessary
                        }

                        # Determine GroupCategory based on CSV values
                        if ($_.groupType -band 0x80000000) {
                            $newGroupParams.GroupCategory = "Security"
                        } else {
                            $newGroupParams.GroupCategory = "Distribution"
                        }

                        # Determine GroupScope based on CSV values
                        if ($_.groupType -band 0x2) {
                            $newGroupParams.GroupScope = "Global"
                        } elseif ($_.groupType -band 0x4) {
                            $newGroupParams.GroupScope = "DomainLocal"
                        } elseif ($_.groupType -band 0x8) {
                            $newGroupParams.GroupScope = "Universal"
                        }

                        Try {
                            New-ADGroup @newGroupParams -ErrorAction Stop

                            $createdGroup = Get-ADGroup -Filter "SamAccountName -eq '$sAMAccountName'" -Properties DistinguishedName
                            if ($createdGroup) {
                                Write-Log "Group Created: sAMAccountName=$sAMAccountName, DistinguishedName=$($createdGroup.DistinguishedName)"
                            } else {
                                Write-Log "Group Created: sAMAccountName=$sAMAccountName - (Failed to retrieve DN)"
                            }

                            # Add this group to parent groups
                            $memberOfGroups = $_.MemberOf -split ';'
                            foreach ($group in $memberOfGroups) {
                                if ($group -ne "") {
                                    try {
                                        $newDN = Get-NewDN -originalDN $group -DNPath $DNPath
                                        Add-ADGroupMember -Identity $newDN -Members $($createdGroup.DistinguishedName)
                                        Write-Host "Added group $sAMAccountName to parent group: $newDN"
                                        Write-Log "Group: sAMAccountName=$sAMAccountName added to group: $newDN"
                                    } catch {
                                        Write-Host "Failed to add group $sAMAccountName to group $newDN. Error: $_" -ForegroundColor Red
                                        Write-Log "Failed to add group sAMAccountName=$sAMAccountName to group: $newDN - $_"
                                    }
                                }
                            }
                            Write-Host "Imported group: $sAMAccountName"
                        } Catch {
                            Write-Error "Failed to import group $sAMAccountName: $_"
                            Write-Log "Failed to create group: sAMAccountName=$sAMAccountName - $_"
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

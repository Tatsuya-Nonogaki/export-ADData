<#
 .SYNOPSIS
  Imports users and groups into Active Directory.

 .DESCRIPTION
  Imports users and groups into Active Directory from CSV files.
  Supports advanced scenarios such as domain migration, OU reorganization, flattening 
  OU hierarchies by trimming OUs, and more.
  Automatically creates missing intermediate OUs as needed.
  Special options allow for placing users/groups with no OU or in the 'Users' 
  container directly under the domain root, or for importing objects as-is.
  
  Version: 0.9.5

 .PARAMETER DNPath
  (Alias -p) Mandatory. Mutually exclusive with -DNPrefix and -DCDepth.
  The target base DN for import (e.g., "DC=mydomain,DC=local" or "OU=branch,DC=mydomain,DC=local").
  Preferred over -DNPrefix for accuracy.
  IMPORTANT: The base DN object must exist in the destination AD prior to import.

 .PARAMETER DNPrefix
  (Alias -d) Alternative to -DNPath. Mutually exclusive.
  Dotted format (e.g., "unit.mydomain.local"), converted internally to DNPath.

 .PARAMETER DCDepth
  Optional. Used only with -DNPrefix. How many trailing elements are treated as DC 
  components (default: 2).

 .PARAMETER User
  (Alias -u) Operates in user import mode. Implied if -UserFile is specified.

 .PARAMETER UserFile
  (Alias -uf) Path to user CSV file. 
  If omitted with -User, a file selection dialog prompts you.

  Note: To register password to any users, make a copy of the whole CSV file, 
  add a "Password" column, and put password in plain text. Do note that Password 
  is required to restore the "Enabled" flag of the account.

 .PARAMETER Group
  (Alias -g) Operates in group import mode. Implied if -GroupFile is specified.

 .PARAMETER GroupFile
  (Alias -gf) Path to group CSV file. If omitted with -Group, a file selection 
  dialog prompts you.

 .PARAMETER NoClassCheck
  By default, this script automatically checks that all records in the input file 
  have an 'ObjectClass' matching the selected import mode (user or group), before 
  importing anything. This switch disables the check, thus allowing you to import 
  files that are missing the column, or that contain mixed or incorrect types.
  Only use this if you know what you are doing.

 .PARAMETER IncludeSystemObject
  Optional. Import also critical system users/groups and trusted DOMAIN$ (normally 
  dangerous for regular environments).

 .PARAMETER NewUPNSuffix
  Optional. Specify a new UserPrincipalName suffix for imported users. Defaults to 
  value derived from -DNPath.

 .PARAMETER NoProtectNewOU
  Optional. If set, newly created OUs will not be protected from accidental deletion.

  .PARAMETER TrimOU
  Optional. The list of OU names is matched against the rightmost (nearest to domain 
  root) OU components of each object's DN. If all components match in exact order, 
  they are trimmed.
  It accepts a comma-separated list of OU names (without 'OU=' prefix). Only plain 
  OU names are allowed.
  Reserved words (ou, cn, dc, users, =) are not permitted (case-insensitive match).
  Always enclose multiple names in quotes, e.g. -TrimOU "deeper,sales".
  For full details and examples, see the README.

 .PARAMETER NoUsersContainer
  Optional. Place users/groups with no OU, or in the 'Users' container, directly under 
  the domain root (DC=...) instead of the default CN=Users container.
  Mutually exclusive with -NoForceUsersContainer.

 .PARAMETER NoForceUsersContainer
  Optional. Import objects as their DN dictates: if the DN is directly under the 
  domain root, import as is; if under Users container, import as is.
  Mutually exclusive with -NoUsersContainer.

 .EXAMPLE
  # Import AD Groups from CSV to a new domain, excluding system objects
  .\import-ADData.ps1 -DNPath "DC=newdomain,DC=local" -GroupFile ".\Groups_olddomain_local.csv"

 .EXAMPLE
  # Import AD Users from CSV to an OU on a domain, using a file dialog
  .\import-ADData.ps1 -DNPath "OU=osaka,DC=newdomain,DC=local" -User

 .EXAMPLE
  # Import AD Users and Groups, using default (safe) policy: OU objects without OU go onto CN=Users
  .\import-ADData.ps1 -DNPath "DC=domain,DC=local" -UserFile "Users.csv" -GroupFile "Groups.csv"

 .EXAMPLE
  # Import users, trimming OUs "deeper" and "sales" from the domain-root side.
  # For example, if the source DN is:
  #   CN=foo,OU=deeper,OU=sales,DC=olddomain,DC=local
  # then -TrimOU "deeper,sales" will result in:
  #   CN=foo,DC=domain,DC=local
  .\import-ADData.ps1 -DNPath "DC=domain,DC=local" -UserFile "Users_deeper_sales_domain_local.csv" -TrimOU "deeper,sales" -NoUsersContainer
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
    [switch]$NoClassCheck,

    [Parameter()]
    [Alias("gf")]
    [string]$GroupFile,

    [Parameter()]
    [switch]$IncludeSystemObject,

    [Parameter()]
    [string]$NewUPNSuffix,

    [Parameter()]
    [switch]$NoProtectNewOU,

    [Parameter()]
    [string]$TrimOU,

    [Parameter()]
    [switch]$NoUsersContainer,

    [Parameter()]
    [switch]$NoForceUsersContainer
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
        "$Timestamp - $Message" | Out-File -Append -FilePath $LogFilePath -Encoding UTF8
    }

    # Arguments validation
    if ($PSBoundParameters.Count -eq 0) {
        Get-Help $MyInvocation.InvocationName
        exit
    }

    # Mutually exclusive: NoUsersContainer and NoForceUsersContainer
    if ($NoUsersContainer -and $NoForceUsersContainer) {
        throw "Error: -NoUsersContainer and -NoForceUsersContainer are mutually exclusive. Please specify only one."
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

    # User and Group related parameter checks
    if ($PSBoundParameters.ContainsKey('UserFile')) { $User = $true }
    if ($PSBoundParameters.ContainsKey('GroupFile')) { $Group = $true }

    if (-not ($User -or $Group)) {
        throw "Error: At least one of -User, -UserFile, -Group, or -GroupFile must be specified."
    }

    if ($User -and $Group) {
        throw "Error: You cannot specify both User mode (-User and/or -UserFile) and Group mode (-Group and/or -GroupFile) at the same time. Please specify only one."
    }

    if ($User -and $PSBoundParameters.ContainsKey('GroupFile')) {
        throw "Error: Option mismatch: -GroupFile cannot be used with User mode (-User or -UserFile)."
    }
    if ($Group -and $PSBoundParameters.ContainsKey('UserFile')) {
        throw "Error: Option mismatch: -UserFile cannot be used with Group mode (-Group or -GroupFile)."
    }

    # UPN suffix sanity check
    if ($PSBoundParameters.ContainsKey('NewUPNSuffix')) {
        $upnPattern = '^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$'
        if ($NewUPNSuffix -eq '' -or $NewUPNSuffix -notmatch $upnPattern) {
            $msg = "Error: -NewUPNSuffix must be a non-empty domain-style string (e.g. 'company.local', 'example.com'), containing only letters, digits, dots and hyphens, and have at least one dot."
            Write-Host $msg -ForegroundColor Red
            Write-Log $msg
            throw $msg
        }
    }

    # Determine protection option for new OUs
    if ($NoProtectNewOU) {
        $newOUcommonOpts = @{ ProtectedFromAccidentalDeletion = $false }
    } else {
        $newOUcommonOpts = @{ ProtectedFromAccidentalDeletion = $true }
    }

    # TrimOU parsing and validation
    $TrimOUList = @()
    if ($PSBoundParameters.ContainsKey('TrimOU')) {
        $reservedWords = @('ou', 'cn', 'dc', 'users', '=')
        $TrimOUList = $TrimOU -split ',' | ForEach-Object { $_.Trim() }
        $trimCount = $TrimOUList.Count

        if ($TrimOUList -and $trimCount -gt 0) {
            $invalid = $TrimOUList | Where-Object {
                ($_ -eq '') -or ($reservedWords -contains $_.ToLower()) -or ($_.Contains('='))
            }

            if ($invalid.Count -gt 0) {
                $msg = "Error: -TrimOU may only contain valid OU names (no reserved words or empty values). Invalid entries: " + ($invalid -join ', ')
                Write-Host $msg -ForegroundColor Red
                Write-Log $msg
                throw $msg
            }
          # Write-Log "debug :: Normalized TrimOU: $($TrimOUList -join ',')"
        }
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

    # Check if this records are of the expected class (i.e., user or group)
    function Test-ObjectClassColumn {
        param (
            [array]$CsvRows,
            [string]$ExpectClass,
            [switch]$NoClassCheck
        )

        if ($NoClassCheck) { return } # Skip check if requested
        if ($CsvRows.Count -eq 0) { return } # Nothing to check

        # 1. Check column exists
        if (-not ($CsvRows[0].PSObject.Properties.Name -contains 'ObjectClass')) {
            throw "Error: The input file is missing the 'ObjectClass' column. To override this check, use -NoClassCheck."
        }

        # 2. Check all values match expected class
        $mismatches = $CsvRows | Where-Object { $_.ObjectClass -ne $ExpectClass }
        if ($mismatches.Count -gt 0) {
            $firstFew = $mismatches | Select-Object -First 3
            $sampleInfo = $firstFew | ForEach-Object { 
                "sAMAccountName=$($_.sAMAccountName), ObjectClass=$($_.ObjectClass)"
            }
            $msg = @"
Error: ObjectClass mismatch detected in input file. $($mismatches.Count) records do not match the expected class '$ExpectClass'.
Showing first 3 mismatches:
$($sampleInfo -join "`n")
Review your CSV. To override this check, use -NoClassCheck.)
"@
            throw $msg
        }
    }

    # Convert old object DistinguishedName to new DN
    function Get-NewDN {
        param (
            [string]$originalDN,
            [string]$DNPath
        )

        if (-not $originalDN) {
            return ""
        }

        if ($originalDN -match '^\s*(CN=[^,]+)') {
            $cnPart = $matches[1]
        }
        $ouPath = ConvertDNBase -oldDN $originalDN -newDNPath $DNPath

        if ($cnPart) {
            Write-Log "debug :: Get-NewDN : return ${cnPart},$ouPath"
            return "${cnPart},$ouPath"
        } else {
            Write-Log "Warning: Get-NewDN : originalDN has no CN part"
            return $ouPath
        }
    }

    # Calculate new target DN to place the given DistinguishedName of the object on
    function ConvertDNBase {
        param (
            [string]$oldDN,
            [string]$newDNPath,
            [switch]$CreateOUIfNotExists
        )

        # --- 1. Parse and split original DN into arrays ---
        $dnParts = $oldDN -split "," | ForEach-Object { $_.Trim() }
        $cnPart = $dnParts | Where-Object { $_ -match "^CN=" }
        $ouParts = @()
        foreach ($part in $dnParts) {
            if ($part -match "^OU=") {
                $ouParts += $part
            }
        }

        # --- 2. Remove the deepest OUs from ouParts array according to '-TrimOU' argument ---
      # Write-Log "debug :: ConvertDNBase :: original oldDN: '$oldDN'"
        Write-Log "debug :: ConvertDNBase :: original ouParts: $($ouParts -join '|')"
        if ($ouParts.Count -gt 0 -and $ouParts[0].Length -le 2) {
            Write-Log "Error: Detected malformed ouParts: $($ouParts -join '|')"
            throw "TrimOU error: ouParts appears malformed (likely split into characters). Check your CSV DN format and delimiter."
        }

        if ($TrimOUList -and $trimCount -gt 0) {
            $ouNames = $ouParts | ForEach-Object { ($_ -replace '^OU=', '').Trim() }

            if ($ouNames.Count -ge $trimCount) {
                $ouNamesRev = @($ouNames)[-1..0]          # reversed order (rightmost first)
                $TrimOUListRev = @($TrimOUList)[-1..0]    # reversed order (rightmost first)
                $match = $true
                for ($i = 0; $i -lt $trimCount; $i++) {
                    if ($ouNamesRev[$i].ToString().ToLower() -ne $TrimOUListRev[$i].ToString().ToLower()) {
                        $match = $false
                        break
                    }
                }
                if ($match) {
                    # Remove the last $trimCount elements (rightmost OUs), but if nothing remains, set to empty array
                    if ($ouParts.Count - $trimCount - 1 -ge 0) {
                        $ouParts = $ouParts[0..($ouParts.Count - $trimCount - 1)]
                    } else {
                        $ouParts = @()
                    }
                }
            }
            Write-Log "debug :: ConvertDNBase :: ouParts after TrimOU: $($ouParts -join ',')"
        }

        # --- 3. Compose the new DN path ---
        $hasOUs = $ouParts.Count -gt 0
        $baseDC = $newDNPath -replace '^(OU=[^,]+,)*', ''

        # --- 3-A. In case any OUs remain ---
        if ($hasOUs) {
            $importTargetOU = ($ouParts -join ',') + "," + $newDNPath

            # Optionally create OUs if requested
            if ($CreateOUIfNotExists) {
                $ouList = $ouParts
                [array]::Reverse($ouList)
                $previousOUBase = $newDNPath

                foreach ($ou in $ouList) {
                    $ou = $ou.Trim()
                  # Write-Log "debug :: processing ou: $ou"
                    $ouName = $ou -replace "^OU=", ""
                    # Check if OU exists, create if not
                    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '${ou},$previousOUBase'" -ErrorAction SilentlyContinue)) {
                        Write-Log "Creating required OU: ${ou},$previousOUBase"
                        try {
                            Write-Log "New-ADOrganizationalUnit -Name $ouName -Path $previousOUBase @newOUcommonOpts (ProtectedFromAccidentalDeletion=$($newOUcommonOpts.ProtectedFromAccidentalDeletion))"
                            New-ADOrganizationalUnit -Name $ouName -Path $previousOUBase @newOUcommonOpts -ErrorAction Stop
                            Write-Host "OU Created: ${ou},$previousOUBase"
                            Write-Log "OU Created: ${ou},$previousOUBase"
                        } catch {
                            Write-Error "Failed to create OU ${ou},$previousOUBase"
                            Write-Log "Failed to create OU: ${ou},$previousOUBase - $_"
                        }
                    }
                    $previousOUBase = "${ou},$previousOUBase"
                }
            }
            return $importTargetOU
        }

        # --- 3-B. In case no OUs remain: only CN and DC ---
        $isUsersContainer = $oldDN -match "^CN=.*?,CN=Users,DC="
        $importBaseHasOU = $newDNPath -match '^OU='

        if ($NoUsersContainer) {
            # Always place at domain base (strip Users container)
            return $newDNPath
        }
        elseif ($NoForceUsersContainer) {
            # Place as-is: if Users container, keep; else domain base
            if ($isUsersContainer) {
                # If import base has OU, ignore CN=Users (place in OU); else, keep Users container
                if ($importBaseHasOU) {
                    return $newDNPath
                } else {
                    return "CN=Users," + $baseDC
                }
            } else {
                return $newDNPath
            }
        }
        else {
            # Default: If import base has OU, place in that OU; else, in CN=Users
            if ($importBaseHasOU) {
                return $newDNPath
            } else {
                return "CN=Users," + $baseDC
            }
        }
    }

    # Import AD objects from the CSV file
    function Import-ADObject {
        param (
            [string]$filePath,
            [string]$objectClass
        )

        if ($objectClass -eq "user") {
            $excludedUsers = @("SUPPORT_388945a0")

            $users = Import-Csv -Path $filePath | Where-Object {
                if ($IncludeSystemObject) {
                    return $true
                } else {
                    if ($_.isCriticalSystemObject -eq "TRUE" -or $_.sAMAccountName -match '\$$' -or $_.sAMAccountName -in $excludedUsers) {
                        Write-Host "Excluded System User: $($_.sAMAccountName)"
                        Write-Log "Excluded System User: sAMAccountName=$($_.sAMAccountName)"
                        return $false
                    } else {
                        return $true
                    }
                }
            }

            # Ensure this records are of AD Users
            Test-ObjectClassColumn -CsvRows $users -ExpectClass 'user' -NoClassCheck:$NoClassCheck

            foreach ($usr in $users) {
                $sAMAccountName = $usr.sAMAccountName

                # Check existence of the user
                $userExists = Get-ADUser -Filter "SamAccountName -eq '$sAMAccountName'" -ErrorAction SilentlyContinue

                if (-not $userExists) {
                    # Construct parameters for New-ADUser
                    Write-Host "Processing user sAMAccountName=`"$sAMAccountName`""
                    Write-Log "Processing user sAMAccountName=`"$sAMAccountName`""

                    $ouPath = ConvertDNBase -oldDN $usr.DistinguishedName -newDNPath $DNPath -CreateOUIfNotExists
                    $managerDN = if ($usr.Manager -ne "") { Get-NewDN -originalDN $usr.Manager -DNPath $DNPath } else { $null }

                    $newUserParams = @{
                        Name           = $usr.Name
                        DisplayName    = $usr.DisplayName
                        SamAccountName = $sAMAccountName
                        Description    = $usr.Description
                        GivenName      = $usr.GivenName
                        Surname        = $usr.Surname
                        Manager        = $managerDN
                    }

                    Try {
                        if ($ouPath -match '^CN=Users,DC=') {
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
                        ProfilePath      = $usr.ProfilePath
                        ScriptPath       = $usr.ScriptPath
                        Company          = $usr.Company
                        Department       = $usr.Department
                        Title            = $usr.Title
                        Office           = $usr.Office
                        OfficePhone      = $usr.OfficePhone
                        EmailAddress     = $usr.EmailAddress
                        StreetAddress    = $usr.StreetAddress
                        City             = $usr.City
                        State            = $usr.State
                        Country          = $usr.Country
                        PostalCode       = $usr.PostalCode
                        MobilePhone      = $usr.MobilePhone
                        HomePhone        = $usr.HomePhone
                        Fax              = $usr.Fax
                        Pager            = $usr.Pager
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

                    if ($usr.UserPrincipalName -ne "") {
                        # Convert UserPrincipalName to new suffix
                        $upnParts = $usr.UserPrincipalName -split "@"
                        $upnPrefix = $upnParts[0]
                        if ($PSBoundParameters.ContainsKey('NewUPNSuffix')) {
                            $upnSuffix =  $NewUPNSuffix
                        } else {
                            $upnSuffix = $DNPath -replace '^(OU=[^,]+,)*', '' -replace 'DC=', '' -replace ',', '.'
                        }
                        $newUserPrincipalName = "${upnPrefix}@${upnSuffix}"

                        try {
                            Set-ADUser -Identity $sAMAccountName -UserPrincipalName $newUserPrincipalName
                            Write-Host "  => UserPrincipalName set for user: $sAMAccountName"
                            Write-Log "UserPrincipalName `"$newUserPrincipalName`" set for user: sAMAccountName=$sAMAccountName"
                        } catch {
                            Write-Host "Warning: Failed to set UserPrincipalName for user ${sAMAccountName}" -ForegroundColor Yellow
                            Write-Log "Failed to set UserPrincipalName `"$newUserPrincipalName`" for user: sAMAccountName=$sAMAccountName - $_"
                        }
                    }

                    # Set password if the CSV provides Password
                    if ($usr.PSObject.Properties.Name -contains "Password" -and $usr.Password -ne "") {
                        try {
                            $securePassword = ConvertTo-SecureString -String $usr.Password -AsPlainText -Force
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
                        $userFlags = [int]$usr.userAccountControl

                        if ($userFlags -band 0x80000) {                  # MustChangePassword
                            Set-ADUser -Identity $sAMAccountName -ChangePasswordAtLogon $true
                            Write-Host "  => MustChangePassword applied: ${sAMAccountName}"
                            Write-Log "MustChangePassword applied: sAMAccountName=${sAMAccountName}"
                        }
                        if ($userFlags -band 0x40) {                     # CannotChangePassword
                            $user = Get-ADUser -Identity $sAMAccountName
                            Set-ACL -Path "AD:\$($user.DistinguishedName)" -AclObject (Get-ACL -Path "AD:\$($user.DistinguishedName)" | ForEach-Object { $usr.Access | Where-Object { $usr.ObjectType -eq [Guid]::Parse("4c164200-20c0-11d0-a768-00aa006e0529") -and $usr.ActiveDirectoryRights -eq "ExtendedRight" -and $usr.AccessControlType -eq "Deny" } })
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
                            if ($usr.PSObject.Properties.Name -contains "Password" -and $usr.Password -ne "") {
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
                    $memberOfGroups = $usr.MemberOf -split ';'
                    foreach ($mgrp in $memberOfGroups) {
                        if ($mgrp -ne "") {
                            try {
                                $newDN = Get-NewDN -originalDN $mgrp -DNPath $DNPath

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

            # Ensure this records are of AD Groups
            Test-ObjectClassColumn -CsvRows $groups -ExpectClass 'group' -NoClassCheck:$NoClassCheck

            foreach ($grp in $groups) {
                $sAMAccountName = $grp.sAMAccountName

                # Check existence of the group
                $groupExists = Get-ADGroup -Filter "SamAccountName -eq '$sAMAccountName'" -ErrorAction SilentlyContinue

                if (-not $groupExists) {
                    # Construct parameters for New-ADGroup
                    Write-Host "Processing group sAMAccountName=`"$sAMAccountName`""
                    Write-Log "Processing group sAMAccountName=`"$sAMAccountName`""

                    $ouPath = ConvertDNBase -oldDN $grp.DistinguishedName -newDNPath $DNPath -CreateOUIfNotExists
                    $NewManagedBy = Get-NewDN -originalDN $grp.ManagedBy -DNPath $DNPath

                    $newGroupParams = @{
                        Name           = $grp.Name    # or $grp.CN
                        SamAccountName = $sAMAccountName
                        Description    = $grp.Description
                        # ManagedBy    = $NewManagedBy   # produces error when DN missing on new AD
                        GroupCategory  = "Security" # modified later if necessary
                        GroupScope     = "Global"   # modified later if necessary
                        # Define other properties here if needed
                    }

                    # Determine GroupCategory based on CSV values
                    if ($grp.groupType -band 0x80000000) {
                        $newGroupParams.GroupCategory = "Security"
                    } else {
                        $newGroupParams.GroupCategory = "Distribution"
                    }

                    # Determine GroupScope based on CSV values
                    if ($grp.groupType -band 0x2) {
                        $newGroupParams.GroupScope = "Global"
                    } elseif ($grp.groupType -band 0x4) {
                        $newGroupParams.GroupScope = "DomainLocal"
                    } elseif ($grp.groupType -band 0x8) {
                        $newGroupParams.GroupScope = "Universal"
                    }

                    Try {
                        if ($ouPath -match '^CN=Users,DC=') {
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
                    $memberOfGroups = $grp.MemberOf -split ';'
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
    Write-Log "Target DN Path: $DNPath"

    if ($PSBoundParameters.ContainsKey('TrimOU') -and $TrimOUList.Count -gt 0) {
        $trimMsg = "Option: 'TrimOU' specified: " + ($TrimOUList -join ', ')
        Write-Host $trimMsg
        Write-Log $trimMsg
    }
    if ($NoUsersContainer) {
        Write-Host "Option: 'NoUsersContainer' enabled"
        Write-Log  "Option: 'NoUsersContainer' enabled"
    }
    if ($NoForceUsersContainer) {
        Write-Host "Option: 'NoForceUsersContainer' enabled"
        Write-Log  "Option: 'NoForceUsersContainer' enabled"
    }
    if ($PSBoundParameters.ContainsKey('NewUPNSuffix')) {
        $upnMsg = "Option: 'NewUPNSuffix' specified: $NewUPNSuffix"
        Write-Host $upnMsg
        Write-Log $upnMsg
    }

    # Group data import
    if ($Group) {
        # Select the group file if not specified
        if (-not $GroupFile) {
            $GroupFile = Select-Input-File -type "group"
        }
        if (-not (Test-Path $GroupFile)) {
            Write-Error "Specified GroupFile does not exist"
            exit 1
        }

        # Warn if looks like a user file
        $groupFileName = Split-Path $GroupFile -Leaf
        if ($groupFileName -match '(?i)(^|[._ -])user([._ -]|s|$)') {
            Write-Host "Warning: The group file name implies it is a user data file." -ForegroundColor Yellow
            $resp = Read-Host "Continue anyway? [Y]/N"
            if ($resp -and $resp -match '^(n|no)$') {
                Write-Host "Aborted by user." -ForegroundColor Yellow
                exit 1
            }
        }

        Write-Host "Group File Path: $GroupFile"
        Write-Log "Group File Path: $GroupFile"
        Import-ADObject -filePath $GroupFile -objectClass "group"
    }

    # User data import
    if ($User) {
        # Select the user file if not specified
        if (-not $UserFile) {
            $UserFile = Select-Input-File -type "user"
        }
        if (-not (Test-Path $UserFile)) {
            Write-Error "Specified UserFile does not exist"
            exit 1
        }

        # Warn if looks like a group file
        $userFileName = Split-Path $UserFile -Leaf
        if ($userFileName -match '(?i)(^|[._ -])group([._ -]|s|$)') {
            Write-Host "Warning: The user file name implies it is a group data file." -ForegroundColor Yellow
            $resp = Read-Host "Continue anyway? [Y]/N"
            if ($resp -and $resp -match '^(n|no)$') {
                Write-Host "Aborted by user." -ForegroundColor Yellow
                exit 1
            }
        }

        Write-Host "User File Path: $UserFile"
        Write-Log "User File Path: $UserFile"
        Import-ADObject -filePath $UserFile -objectClass "user"
    }

# End of process
}

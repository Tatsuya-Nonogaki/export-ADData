<#
 .SYNOPSIS
  Imports users, groups, and computers into Active Directory.

 .DESCRIPTION
  Imports users, groups, and computers into Active Directory from CSV files.
  Supports advanced scenarios such as domain migration, OU reorganization, flattening 
  OU hierarchies by trimming OUs, and more.
  Automatically creates missing intermediate OUs as needed.
  Special options allow for placing users/groups/computers with no OU or in the 
  "default" container defined in AD ('CN=Users', 'CN=Computers'), directly under the 
  domain root, or for importing objects as-is.
  
  Version: 1.0.6

 .PARAMETER DNPath
  (Alias -p) Mandatory. Mutually exclusive with -DNPrefix and -DCDepth.
  The target base DN for import (e.g., "DC=mydomain,DC=local" or "OU=branch,DC=mydomain,DC=local").
  Preferred over -DNPrefix for accuracy.
  IMPORTANT: The base DN object (e.g., the specified OU or domain root) must exist 
  in the destination AD prior to import. This script does NOT create the *base* OU 
  specified in -DNPath; it will only create sub-OUs as needed.

 .PARAMETER DNPrefix
  (Alias -d) Alternative to -DNPath. Mutually exclusive.
  Dotted format (e.g., "unit.mydomain.local"), converted internally to DNPath.

 .PARAMETER DCDepth
  Optional. Used only with -DNPrefix. How many trailing elements are treated as DC 
  components (default: 2).

 .PARAMETER User
  (Alias -u) Operates in user import mode. Can be omitted if -UserFile is specified.

 .PARAMETER UserFile
  (Alias -uf) Path to user CSV file. 
  If omitted with -User, a file selection dialog prompts you.

  Note: To register password to any users, make a copy of the whole CSV file, 
  add a "Password" column, and put password in plain text. Do note that Password 
  is required to restore the "Enabled" flag of the account.

  Note: CSV columns related to userAccountControl / password policy (CCP/CPL/PNE)

  Some password-policy-related settings are normally encoded in the integer
  "userAccountControl" bit field. To make imports safer and easier, this script
  supports per-property CSV columns and applies a normalization policy to avoid
  contradictory combinations.

  Currently recognized columns:
   - "CannotChangePassword" (CCP): Controls whether the user can change their password.
     The column is included by default in the raw CSV produced by export-ADData.ps1.
     This script applies CCP=TRUE to AD (best-effort) when requested. CCP=FALSE is not
     actively forced and is left to the destination AD defaults/policies.
   - "ChangePasswordAtLogon" (CPL): Controls "User must change password at next logon".
     Add this column if needed.
     When set to TRUE, a password in the "Password" column is required to enforce it.
   - "PasswordNeverExpires" (PNE): Controls the "Password never expires" setting.
     The column is included by default in the raw CSV produced by export-ADData.ps1.

  Boolean parsing rules (applies to all columns listed above):
   - Acceptable values: TRUE, YES, or 1 (case-insensitive) to enable;
     FALSE, NO, or 0 to disable.
   - If the column exists and contains a valid boolean value, it takes precedence
     over the corresponding userAccountControl bit (when applicable).
   - If the column exists but its value is non-blank and cannot be parsed as a
     boolean, the script logs a warning and treats it as unknown for that column.

  Fallback rules when the dedicated column is missing or invalid:
   - For CPL and PNE, the script may fall back to userAccountControl bits, but only
     explicitly applies the TRUE (bit set) case. The FALSE (bit not set) case is
     left to the destination AD defaults/policies unless the CSV explicitly sets
     the property to FALSE via the column.
   - For CCP, the script does NOT fall back to userAccountControl bit 0x40, because
     "CannotChangePassword" is ACL-based and the bit is not a reliable indicator.
   - Note: even when a TRUE value is determined (from column or fallback), the
     normalization or safety policy may still skip applying it, resulting in an
     effective FALSE outcome.

  IMPORTANT: The "CannotChangePassword" column must be present in the User CSV.
   - This column is included by export-ADData.ps1 by default. Do not delete the column.
   - You may edit its values if you intentionally want to change the CCP setting to be
     imported to the destination AD. Note that CCP has the highest priority in the
     normalization/conflict-resolution policy (CCP > CPL > PNE). Changing CCP may change
     how conflicts are resolved and can affect the final results of both
     ChangePasswordAtLogon and PasswordNeverExpires.

  Normalization policy (priority order: CCP > CPL > PNE):
   - If CCP=TRUE and CPL=TRUE are both requested, CPL is skipped (CCP wins).
   - If CPL=TRUE and PNE=TRUE are both requested, PNE is skipped (CPL wins).

  Safety check on the destination AD before applying PNE=TRUE:
   - This script checks the destination account state (pwdLastSet) and skips
     PasswordNeverExpires=TRUE if the account is effectively in "must change password
     at next logon" state, or if that state cannot be verified.

 .PARAMETER Group
  (Alias -g) Operates in group import mode. Can be omitted if -GroupFile is specified.

  Note: GroupCategory and GroupScope handling in Group Imports
  These properties are normally sourced from the "groupType" column. However, recalculating 
  the hexadecimal integer for "groupType" can be cumbersome when modifications are required.
  To simplify this process, you may leave "groupType" blank or prefix its value with a 
  hash ("#"). In these cases, the script will use the string columns "GroupCategory" and 
  "GroupScope" instead.

 .PARAMETER GroupFile
  (Alias -gf) Path to group CSV file. If omitted with -Group, a file selection 
  dialog prompts you.

 .PARAMETER Computer
  (Alias -c) Operates in computer import mode. Can be omitted if -ComputerFile is specified.

 .PARAMETER ComputerFile
  (Alias -cf) Path to computer CSV file. If omitted with -Computer, a file selection 
  dialog prompts you.

 .PARAMETER FixGroup
  Optional. Operates in a post-import fixup mode for existing groups (distinct from 
  -User and -Group import modes). 
  Currently, this mode registers the ManagedBy attribute for groups, using the same 
  GroupFile as in the import step. This must be run after users and groups have 
  already been imported, since ManagedBy references are typically user accounts.
  Mutually exclusive with other modes (-User/-Group/-computer). Requires -GroupFile 
  (or prompts if omitted).
  Use the same advanced options (-TrimOU, -NoDefaultContainer, -NoForceDefaultContainer) 
  as in your previous imports.
  This mode does not create or remove any groups or users; it only updates ManagedBy 
  for existing groups.

 .PARAMETER NoClassCheck
  By default, this script automatically checks that all records in the input file 
  have an 'ObjectClass' matching the selected import mode (user/group/computer), before 
  importing anything. This switch disables the check, thus allowing you to import 
  files that are missing the column, or that contain mixed or incorrect types.
  Only use this if you know what you are doing.

 .PARAMETER IncludeSystemObject
  Optional. Import also critical system users/groups/computers and trusted DOMAIN$ 
  (normally dangerous for regular environments).

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
  Reserved words (ou, cn, dc, users, computers, =) are not permitted (case-insensitive match).
  Always enclose multiple names in quotes, e.g. -TrimOU "deeper,sales".
  For full details and examples, see the README.

 .PARAMETER NoDefaultContainer
  If specified, the account that would otherwise be created in the "default" container 
  are instead created directly under the domain root (DC=...). By AD's default, the 
  container is 'Users' (CN=Users,DC=...) for user and group, and 'Computers' for computer. 
  This option also affects cases where -TrimOU causes the object to be relocated to the 
  domain root.
  This parameter is mutually exclusive with -NoForceDefaultContainer.

 .PARAMETER NoForceDefaultContainer
  If specified, objects are imported exactly as their DN dictates: if the objects 
  are directly under the domain root in the source, they are imported there; if they 
  are under the "default" container (see NoDefaultContainer), they remain in destinations 
  "default" container. This option also affects cases where -TrimOU causes the object 
  to be relocated to the domain root. 
  This parameter is mutually exclusive with -NoDefaultContainer.

 .EXAMPLE
  # Import AD Groups from CSV to a new domain, excluding system objects
  .\import-ADData.ps1 -DNPath "DC=newdomain,DC=local" -GroupFile ".\Groups_olddomain_local.csv"

 .EXAMPLE
  # Import AD Users from CSV to an OU on a domain, using a file dialog
  .\import-ADData.ps1 -DNPath "OU=osaka,DC=newdomain,DC=local" -User
  # NOTE: You must create the *base* OU "osaka" in the destination AD before running the import, if it does not already exist.

 .EXAMPLE
  # Import AD Computers from CSV
  .\import-ADData.ps1 -DNPath "DC=domain,DC=local" -ComputerFile "C:\Exp\Computers_olddomain_local.csv"

 .EXAMPLE
  # Import users, trimming OUs "deeper" and "sales" from the domain-root side.
  # For example, if the source DN is:
  #   CN=foo,OU=deeper,OU=sales,DC=olddomain,DC=local
  # then -TrimOU "deeper,sales" will result in:
  #   CN=foo,DC=domain,DC=local
  .\import-ADData.ps1 -DNPath "DC=domain,DC=local" -UserFile "Users_deeper_sales_domain_local.csv" -TrimOU "deeper,sales" -NoDefaultContainer

 .EXAMPLE
  # Register ManagedBy property for Groups after importing Groups and Users.
  .\import-ADData.ps1 -DNPath "DC=newdomain,DC=local" -GroupFile ".\Groups_olddomain_local.csv"
  .\import-ADData.ps1 -DNPath "DC=newdomain,DC=local" -UserFile ".\Users_olddomain_local.csv"
  .\import-ADData.ps1 -DNPath "DC=newdomain,DC=local" -FixGroup -GroupFile ".\Groups_olddomain_local.csv"
  # You must use exactly the same advanced options (if applicable: -TrimOU, -NoDefaultContainer, -NoForceDefaultContainer) for all runs in this sequence to avoid DN path translation mismatches.
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
    [Alias("c")]
    [switch]$Computer,

    [Parameter()]
    [Alias("cf")]
    [string]$ComputerFile,

    [Parameter()]
    [switch]$FixGroup,

    [Parameter()]
    [switch]$NoClassCheck,

    [Parameter()]
    [switch]$IncludeSystemObject,

    [Parameter()]
    [string]$NewUPNSuffix,

    [Parameter()]
    [switch]$NoProtectNewOU,

    [Parameter()]
    [string]$TrimOU,

    [Parameter()]
    [switch]$NoDefaultContainer,

    [Parameter()]
    [switch]$NoForceDefaultContainer
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

    # Resolve Default Container name
    function Get-DefaultContainerName {
        param(
            [string]$Want
        )

        if ($Want) {
            switch ($Want.ToLower()) {
                "user"      { return "Users" }
                "group"     { return "Users" }
                "fixgroup"  { return "Users" }
                "computer"  { return "Computers" }
                default     { return "Users" }
            }
        }
        elseif ($wantFixGroup)   { return "Users" }
        elseif ($wantUser)       { return "Users" }
        elseif ($wantGroup)      { return "Users" }
        elseif ($wantComputer)   { return "Computers" }
        else                     { return "Users" }
    }

    # Arguments validation
    if ($PSBoundParameters.Count -eq 0) {
        Get-Help $MyInvocation.InvocationName
        exit
    }

    # Mutually exclusive: NoDefaultContainer and NoForceDefaultContainer
    if ($NoDefaultContainer -and $NoForceDefaultContainer) {
        throw "Error: -NoDefaultContainer and -NoForceDefaultContainer are mutually exclusive. Please specify only one."
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

    # Main mode parameters and mutual exclution checks
    if ($PSBoundParameters.ContainsKey('UserFile')) {
        if (-not $UserFile -or $UserFile.Trim() -eq "") {
            Write-Host "Error: -UserFile was specified but is blank or whitespace." -ForegroundColor Red
            exit 2
        }
    }
    if ($PSBoundParameters.ContainsKey('GroupFile')) {
        if (-not $GroupFile -or $GroupFile.Trim() -eq "") {
            Write-Host "Error: -GroupFile was specified but is blank or whitespace." -ForegroundColor Red
            exit 2
        }
    }
    if ($PSBoundParameters.ContainsKey('ComputerFile')) {
        if (-not $ComputerFile -or $ComputerFile.Trim() -eq "") {
            Write-Host "Error: -ComputerFile was specified but is blank or whitespace." -ForegroundColor Red
            exit 2
        }
    }

    # Main mode parameters and mutual exclusion checks
    $userMode = $false
    $groupMode = $false
    $computerMode = $false
    $fixGroupMode = $false

    $wantUser = $User -or $PSBoundParameters.ContainsKey('UserFile')
    $wantGroup = $Group -or $PSBoundParameters.ContainsKey('GroupFile')
    $wantComputer = $Computer -or $PSBoundParameters.ContainsKey('ComputerFile')
    $wantFixGroup = $FixGroup

    if ($wantFixGroup) {
        if ($wantUser -or $wantGroup -or $wantComputer) {
            Write-Host "Error: -FixGroup cannot be combined with -User, -Group, or -Computer modes." -ForegroundColor Red
            exit 2
        }
        $fixGroupMode = $true
    }
    elseif (($wantUser + $wantGroup + $wantComputer) -gt 1) {
        Write-Host "Error: Specify only one of User mode (-User, -UserFile), Group mode (-Group, -GroupFile), or Computer mode (-Computer, -ComputerFile)." -ForegroundColor Red
        exit 2
    }
    elseif ($wantUser) {
        $userMode = $true
    }
    elseif ($wantGroup) {
        $groupMode = $true
    }
    elseif ($wantComputer) {
        $computerMode = $true
    }
    else {
        Write-Host "Error: At least one of -User (-UserFile), -Group (-GroupFile), -Computer (-ComputerFile), or -FixGroup must be specified." -ForegroundColor Red
        exit 2
    }

    $DefaultContainerName = Get-DefaultContainerName

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
        $reservedWords = @('ou', 'cn', 'dc', 'users', 'computers', '=')
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

    # Critical system accounts baseline (tunable point for programmers).
    # These arrays are used to:
    # - exclude objects from import (unless -IncludeSystemObject is specified)
    #   (Copied into $excluded* in Import-ADObject(), where you can extend the lists with
    #   environment-specific entries if needed)
    # - resolve MemberOf for system groups without OU translation (by DN lookup on destination AD)

    $systemUsers = @(
        "SUPPORT_388945a0",
        "TsInternetUser"
    )

    # Groups that are strongly expected to live directly under CN=Builtin or CN=Users
    # (location is effectively fixed)
    $systemGroupsStrong = @(
        "Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators",
        "Replicator",
        "Remote Desktop Users"
    )

    # System groups that may exist under an OU as well (location is not strictly fixed)
    $systemGroupsWeak = @(
        "DnsAdmins",
        "DnsUpdateProxy",
        "HelpServicesGroup",
        "TelnetClients",
        "WINS Users",
        "Cert Publishers"
    )

    # System computer accounts to exclude (usually leave empty; extend only when needed)
    $systemComputers = @()

    # Cache for Group DN lookup by sAMAccountName (key: sam, value: DistinguishedName or "")
    $groupDnBySamCache = @{}
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
        } elseif ($type -eq "computer") {
            $req = "computer CSV file"
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

    function FileName-WrongType-Warn {
        param (
            [string]$FilePath,
            [string]$MyType
        )
        $AllTypes = @("user", "group", "computer")
        $OtherTypes = $AllTypes | Where-Object { $_ -ne $MyType }
        $fileName = Split-Path $FilePath -Leaf

        foreach ($other in $OtherTypes) {
            if ($fileName -match "(?i)(^|[._ -])$($other)([._ -]|s|$)") {
                Write-Host "Warning: The file name implies it is a $other data file, not '$MyType'." -ForegroundColor Yellow
                $resp = Read-Host "Continue anyway? [Y]/N"
                if ($resp -and $resp -match '^(n|no)$') {
                    Write-Host "Aborted by user." -ForegroundColor Yellow
                    return $true
                }
                # Warn only once
                break
            }
        }
        return $false
    }

    # Generate DN path from DN prefix
    function ConvertPrefixToDNPath {
        param (
            [string]$prefix,
            [int]$depth
        )

        $domainParts = $prefix.Split('.')
        if ($domainParts.Count -lt 2) {
            Write-Error "Invalid prefix format: Expected at least two domain components (e.g., mydomain.local)"
            exit 1
        }
        if ($depth -lt 1 -or $depth -gt $domainParts.Count) {
            Write-Error "Invalid DCDepth: It must be at least 1 and at most the total number of domain components."
            exit 1
        }

        $dnForm = ""

        # Assume DC are the last depth elements
        $dcParts = $domainParts[-$depth..-1]

        # Assume the shallower elements are OU
        $ouEnd = $domainParts.Count - $DCDepth - 1
        if ($ouEnd -ge 0) {
            $ouParts = $domainParts[0..$ouEnd]
        } else {
            $ouParts = @()
        }
        if ($ouParts -is [string]) { $ouParts = @($ouParts) }

        [array]::Reverse($ouParts)
        foreach ($ou in $ouParts) {
            $dnForm += "OU=$ou,"
        }

        foreach ($dc in $dcParts) {
            $dnForm += "DC=$dc,"
        }

        return $dnForm.TrimEnd(',')
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
            [string]$DNPath,
            [string]$DefaultContainer = $DefaultContainerName
        )

        if (-not $originalDN) {
            return ""
        }

        if ($originalDN -match '^\s*(CN=[^,]+)') {
            $cnPart = $matches[1]
        }
        $ouPath = ConvertDNBase -oldDN $originalDN -newDNPath $DNPath
        $ouPath = ConvertDNBase -oldDN $originalDN -newDNPath $DNPath -DefaultContainer $DefaultContainer

        if ($cnPart) {
           # Write-Log "debug :: Get-NewDN : return ${cnPart},$ouPath"
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
            [string]$DefaultContainer = $DefaultContainerName,
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
      # Write-Log "debug :: ConvertDNBase :: original ouParts: $($ouParts -join '|')"
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
        $isDefaultContainer = $oldDN -match "^CN=.*?,CN=$($DefaultContainer),DC="
        $importBaseHasOU = $newDNPath -match '^OU='

        if ($NoDefaultContainer) {
            # Always place at domain base (strip default container)
            return $newDNPath
        }
        elseif ($NoForceDefaultContainer) {
            # Place as-is: if default container, keep; else domain base
            if ($isDefaultContainer) {
                # If import base has OU, ignore default container (place in OU); else, keep default container
                if ($importBaseHasOU) {
                    return $newDNPath
                } else {
                    return "CN=$DefaultContainer," + $baseDC
                }
            } else {
                return $newDNPath
            }
        }
        else {
            # Default: If import base has OU, place in that OU; else, in CN=DefaultContainer
            if ($importBaseHasOU) {
                return $newDNPath
            } else {
                return "CN=$DefaultContainer," + $baseDC
            }
        }
    }

    # Resolve a group DN on the destination AD from a sAMAccountName by a Get-ADGroup query.
    # It uses an in-memory cache to avoid repeated lookups, including negative results.
    function Get-DNBySam {
        param(
            [string]$SamAccountName
        )

        if (-not $SamAccountName -or $SamAccountName.Trim() -eq "") { return "" }

        $sam = $SamAccountName.Trim()

        if ($script:groupDnBySamCache.ContainsKey($sam)) {
            return $script:groupDnBySamCache[$sam]
        }

        $grp = Get-ADGroup -Identity $sam -Properties DistinguishedName -ErrorAction SilentlyContinue

        $dn = ""
        if ($grp -and $grp.DistinguishedName) {
            $dn = $grp.DistinguishedName
        }

        # Update cache to avoid repeated lookups (including negative cache "" too)
        $script:groupDnBySamCache[$sam] = $dn
        return $dn
    }

    # Convert an original MemberOf group DN into the destination DN:
    # - if it is a known system group, resolve it directly on the destination AD via Get-DNBySam function
    # - otherwise translate the DN/OU path normally with Get-NewDN.
    function Get-NewMemberOfDN {
        param(
            [string]$OriginalGroupDN,
            [string]$DNPath,
            [string[]]$SystemGroupSams
        )

        if (-not $OriginalGroupDN -or $OriginalGroupDN.Trim() -eq "") { return "" }

        # Extract CN=xxx from MemberOf DN; in this script policy, treat it as sAMAccountName.
        $sam = ""
        if ($OriginalGroupDN -match '^\s*CN=([^,]+)') {
            $sam = $matches[1]
        }

        # If system group: resolve on destination AD by sAMAccountName (no OU translation)
        if ($sam -and $SystemGroupSams -and ($sam -in $SystemGroupSams)) {
            return (Get-DNBySam -SamAccountName $sam)
        }

        # Otherwise: normal OU/DN translation
        return (Get-NewDN -originalDN $OriginalGroupDN -DNPath $DNPath)
    }

    # Normalize CSV value positive/negative to $null, $true, or $false
    function To-Bool($val) {
        if ($null -eq $val) { return $null }
        $str = $val.ToString().Trim().ToLower()
        if ($str -eq "true" -or $str -eq "yes" -or $str -eq "1") { return $true }
        if ($str -eq "false" -or $str -eq "no" -or $str -eq "0") { return $false }
        return $null
    }

    # Check whether ChangePasswordAtLogon is effectively TRUE for an existing AD user.
    # Returns $true when pwdLastSet is 0 (ChangePasswordAtLogon is effectively set).
    # Returns $false when pwdLastSet is non-zero (ChangePasswordAtLogon is not set).
    # Returns $null when the AD user cannot be retrieved or the property is unavailable.
    function IsChangePasswordAtLogonEffective {
        param(
            [string]$SamAccountName
        )
        try {
            $adUser = Get-ADUser -Identity $SamAccountName -Properties pwdLastSet -ErrorAction Stop
            if ($null -eq $adUser) { return $null }
            # pwdLastSet == 0 means ChangePasswordAtLogon is effectively TRUE
            if ($adUser.pwdLastSet -eq 0) { return $true }
            return $false
        } catch {
            return $null
        }
    }

    # Check CSV column name duplication
    function Assert-NoDuplicateCsvColumns {
        param(
            [string]$Path
        )

        $headerLine = Get-Content -Path $Path -TotalCount 1
        $cols = $headerLine -split ',' | ForEach-Object { $_.Trim().Trim('"') }

        $dupCols =
            $cols |
            Where-Object { $_ -ne "" } |
            Group-Object { $_.ToLower() } |
            Where-Object { $_.Count -gt 1 } |
            ForEach-Object { $_.Group[0] }   # keep original spelling (first occurrence)

        if ($dupCols.Count -gt 0) {
            $dupList = ($dupCols | ForEach-Object { "'$_'" }) -join ", "
            $msg = "Error: Duplicate column name(s) found in CSV header: $dupList"
            Write-Host $msg -ForegroundColor Red
            Write-Log $msg
            exit 2
        }
    }

    # Import AD objects from the CSV file
    function Import-ADObject {
        param (
            [string]$filePath,
            [string]$objectClass
        )

        # System groups list used for MemberOf resolution (Strong+Weak)
        $systemGroupSams = @(@($systemGroupsStrong) + @($systemGroupsWeak))

        # Build excluded lists from baseline (copy for local editability)
        $excludedUsers     = @($systemUsers)
        $excludedGroups    = @($systemGroupSams)
        $excludedComputers = @($systemComputers)

        # You can additionally exclude specific accounts by extending the arrays like below:
        #   $excludedUsers     += @("SpecialAdmin", "BusManager")
        #   $excludedGroups    += @("SpecialGroup1", "SpecialGroup2")
        #   $excludedComputers += @("SPECIALPC01$", "SPECIALPC02$")

        if ($objectClass -eq "user") {
            # Check column duplication
            Assert-NoDuplicateCsvColumns -Path $filePath

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

                    # Set only required properties for 'New-ADUser' here; move all others to '$additionalProperties'
                    $newUserParams = @{
                        Name           = $usr.Name
                        SamAccountName = $sAMAccountName
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
                        Write-Log "User Created: sAMAccountName=${sAMAccountName}, DistinguishedName=$($createdUser.DistinguishedName)"
                    } else {
                        Write-Host "User creation failed for ${sAMAccountName}; skipping further property setting." -ForegroundColor Red
                        Write-Log "User creation failed for sAMAccountName=${sAMAccountName}; skipping further property setting."
                        continue
                    }

                    # Set additional properties using Set-ADUser
                    $additionalProperties = @{
                        DisplayName      = $usr.DisplayName
                        Description      = $usr.Description
                        GivenName        = $usr.GivenName
                        Surname          = $usr.Surname
                        Manager          = $managerDN
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
                        # Define other properties here if needed
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
                                Write-Log "Failed to set property $property for user: sAMAccountName=$sAMAccountName, ${property}='$($additionalProperties[$property])' - $_"
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
                    $IsPasswordSet = $false
                    if ($usr.PSObject.Properties.Name -contains "Password" -and $usr.Password -ne "") {
                        try {
                            $securePassword = ConvertTo-SecureString -String $usr.Password -AsPlainText -Force
                            Set-ADAccountPassword -Identity $createdUser.DistinguishedName -NewPassword $securePassword -Reset
                            $IsPasswordSet = $true
                            Write-Host "  => Password set for user: $sAMAccountName"
                            Write-Log "Password set for user: sAMAccountName=$sAMAccountName"
                        } catch {
                            Write-Error "Failed to set password for user ${sAMAccountName}: $_"
                            Write-Log "Failed to set password for user: sAMAccountName=$sAMAccountName - $_"
                        }
                    }

                    # Set "userAccountControl" property related special control bits - Enabling account and set ChangePasswordAtLogon=True require a successfully set password
                    $userFlags = [int]$usr.userAccountControl

                    # ----------------------------------------------------------------
                    # CCP/CPL/PNE normalization block (policy order: CCP > CPL > PNE)
                    # CCP = CannotChangePassword, CPL = ChangePasswordAtLogon,
                    # PNE = PasswordNeverExpires
                    # ----------------------------------------------------------------

                    # --- CPL (ChangePasswordAtLogon): dedicated column or UAC bit 0x80000 fallback ---
                    $cplColExists = $usr.PSObject.Properties.Name -contains "ChangePasswordAtLogon"
                    if ($cplColExists) {
                        $cplRawValue  = $usr.ChangePasswordAtLogon
                        $cplWanted    = To-Bool $cplRawValue   # CPL: parsed boolean or $null when invalid/blank
                    } else {
                        $cplRawValue = $cplWanted = $null
                    }

                    # Warn when dedicated column exists but has a non-blank invalid value (fall back to UAC bit).
                    if ($cplColExists -and $cplRawValue -ne $null -and $cplRawValue.ToString().Trim() -ne "" -and $cplWanted -eq $null) {
                        $warn = "Warning: ChangePasswordAtLogon column value is not a valid boolean for user: $sAMAccountName (value='$cplRawValue'). Falling back to userAccountControl (0x80000)"
                        Write-Host $warn -ForegroundColor Yellow
                        Write-Log $warn
                    }

                    # Determine CPL source and apply fallback.
                    $cplSource = "none"  # "column" | "userAccountControl" | "none"
                    if ($cplColExists -and $null -ne $cplWanted) {
                        $cplSource = "column"
                    }
                    # Fallback: UAC bit 0x80000; only applies TRUE (FALSE is left to AD defaults unless column says FALSE).
                    if ((-not $cplColExists -or $cplWanted -eq $null) -and ($userFlags -band 0x80000)) {
                        $cplWanted = $true
                        $cplSource = "userAccountControl"
                    }

                    # --- CCP (CannotChangePassword): dedicated column only (no UAC fallback) ---
                    $ccpColExists = $usr.PSObject.Properties.Name -contains "CannotChangePassword"
                    $ccpKnown     = $false   # CCP = CannotChangePassword: whether ccpWanted is a valid known value
                    $ccpMissing   = $false   # CCP: column is absent from the CSV
                    $ccpInvalid   = $false   # CCP: column is present but blank or has an invalid value
                    $ccpRawValue  = $null
                    $ccpWanted    = $null    # CCP = CannotChangePassword: parsed boolean or $null when unknown

                    if (-not $ccpColExists) {
                        $ccpMissing = $true
                    } else {
                        $ccpRawValue = $usr.CannotChangePassword
                        $ccpWanted   = To-Bool $ccpRawValue
                        if ($ccpWanted -eq $null) {
                            $ccpInvalid = $true
                            # Warn only when a non-blank value failed to parse (blank is silently treated as unknown).
                            if ($ccpRawValue -ne $null -and $ccpRawValue.ToString().Trim() -ne "") {
                                $warn = "Warning: CannotChangePassword column value is not a valid boolean for user: $sAMAccountName (value='$ccpRawValue'). Treating as unknown."
                                Write-Host $warn -ForegroundColor Yellow
                                Write-Log  $warn
                            }
                        } else {
                            $ccpKnown = $true
                        }
                    }
                    # NOTE: We intentionally do NOT use userAccountControl (0x40) as fallback for CCP.
                    #       CCP is ACL-based; UAC bit is not a reliable indicator in practice.

                    # --- PNE (PasswordNeverExpires): dedicated column or UAC bit 0x10000 fallback ---
                    $pneColExists = $usr.PSObject.Properties.Name -contains "PasswordNeverExpires"
                    if ($pneColExists) {
                        $pneRawValue  = $usr.PasswordNeverExpires
                        $pneWanted    = To-Bool $pneRawValue   # PNE: parsed boolean or $null when invalid/blank
                    } else {
                        $pneRawValue = $pneWanted = $null
                    }

                    # Warn when dedicated column exists but has a non-blank invalid value (fall back to UAC bit).
                    if ($pneColExists -and $pneRawValue -ne $null -and $pneRawValue.ToString().Trim() -ne "" -and $pneWanted -eq $null) {
                        $warn = "Warning: PasswordNeverExpires column value is not a valid boolean for user: $sAMAccountName (value='$pneRawValue'). Falling back to userAccountControl (0x10000)"
                        Write-Host $warn -ForegroundColor Yellow
                        Write-Log $warn
                    }

                    # Determine PNE source and apply fallback.
                    $pneSource = "none"  # "column" | "userAccountControl" | "none"
                    if ($pneColExists -and $null -ne $pneWanted) {
                        $pneSource = "column"
                    }
                    # Fallback: UAC bit 0x10000; only applies TRUE (FALSE is left to AD defaults unless column says FALSE).
                    if ((-not $pneColExists -or $pneWanted -eq $null) -and ($userFlags -band 0x10000)) {
                        $pneWanted = $true
                        $pneSource = "userAccountControl"
                    }

                    # ----------------------------------------------------------------
                    # Normalize by policy: CCP > CPL > PNE
                    # ----------------------------------------------------------------

                    # CCP=TRUE and CPL=TRUE conflict: skip CPL to prevent deadlock (only when CCP is known)
                    if ($ccpKnown -and $ccpWanted -eq $true -and $cplWanted -eq $true) {
                        $warn = "Warning: CannotChangePassword=TRUE and ChangePasswordAtLogon=TRUE conflict for user '$sAMAccountName'. Policy CCP > CPL: skipping ChangePasswordAtLogon."
                        $info = "CPL requested TRUE ($cplSource) was skipped due to CCP conflict for user: $sAMAccountName"
                        Write-Host $warn -ForegroundColor Yellow
                        Write-Log  $warn
                        Write-Verbose $info
                        Write-Log  $info
                        $cplWanted = $false
                    }

                    # CPL=TRUE and PNE=TRUE conflict: skip PNE
                    if ($cplWanted -eq $true -and $pneWanted -eq $true) {
                        $warn = "Warning: ChangePasswordAtLogon=TRUE and PasswordNeverExpires=TRUE conflict for user '$sAMAccountName'. Policy CPL > PNE: skipping PasswordNeverExpires."
                        $info = "PNE requested TRUE ($pneSource) was skipped due to CPL conflict for user: $sAMAccountName"
                        Write-Host $warn -ForegroundColor Yellow
                        Write-Log  $warn
                        Write-Verbose $info
                        Write-Log  $info
                        $pneWanted = $false
                    }

                    # ----------------------------------------------------------------
                    # Apply CCP (CannotChangePassword): highest priority in CCP/CPL/PNE, best-effort.
                    # Applied only when CCP=TRUE is requested, intentionally avoiding setting FALSE
                    # so that destination ACLs/delegation defaults are respected.
                    # ----------------------------------------------------------------
                    if ($ccpWanted -eq $true) {
                        try {
                            Set-ADUser -Identity $sAMAccountName -CannotChangePassword $true
                            Write-Host "  => CannotChangePassword set to True for user: $sAMAccountName (column)"
                            Write-Log  "CannotChangePassword set to True for user: sAMAccountName=$sAMAccountName source=column"
                        } catch {
                            $warn = "Warning: Failed to set CannotChangePassword=TRUE for user '$sAMAccountName'. Continuing. Error: $_"
                            Write-Host $warn -ForegroundColor Yellow
                            Write-Log  $warn
                        }
                    }

                    # ----------------------------------------------------------------
                    # Apply CPL (ChangePasswordAtLogon)
                    # ----------------------------------------------------------------
                    if ($cplWanted -ne $null) {
                        # When applying CPL=TRUE but CCP status is unknown, warn that deadlock check was skipped.
                        if ($cplWanted -eq $true -and -not $ccpKnown) {
                            if ($ccpMissing) {
                                $warn = "Warning: CannotChangePassword column is missing for user '$sAMAccountName'. ChangePasswordAtLogon=TRUE will be applied as requested (deadlock check skipped)."
                            } else {
                                $warn = "Warning: CannotChangePassword column is blank/invalid for user '$sAMAccountName'. ChangePasswordAtLogon=TRUE will be applied as requested (deadlock check skipped)."
                            }
                            Write-Host $warn -ForegroundColor Yellow
                            Write-Log  $warn
                        }

                        if ($cplWanted -eq $true -and -not $IsPasswordSet) {
                            Write-Host "Warning: Failed to set ChangePasswordAtLogon (wanted=TRUE) for account $sAMAccountName as no password is set" -ForegroundColor Yellow
                            Write-Log  "Failed to set ChangePasswordAtLogon (wanted=TRUE) for account $sAMAccountName as no password is set"
                        } else {
                            try {
                                Set-ADUser -Identity $sAMAccountName -ChangePasswordAtLogon $cplWanted
                                Write-Host "  => ChangePasswordAtLogon set to $cplWanted for user: $sAMAccountName ($cplSource)"
                                Write-Log  "ChangePasswordAtLogon set to $cplWanted for user: sAMAccountName=$sAMAccountName source=$cplSource"
                            } catch {
                                Write-Error "Failed to set ChangePasswordAtLogon for user ${sAMAccountName}: $_"
                                Write-Log "Failed to set ChangePasswordAtLogon for user: sAMAccountName=${sAMAccountName}, ChangePasswordAtLogon='$cplRawValue' - $_"
                            }
                        }
                    }

                    # ----------------------------------------------------------------
                    # Apply PNE (PasswordNeverExpires) with destination-state safety check before applying TRUE
                    # ----------------------------------------------------------------
                    if ($pneWanted -ne $null) {
                        if ($pneWanted -eq $true) {
                            # Safety check: verify destination user does not have ChangePasswordAtLogon effectively TRUE.
                            $cplEffective = IsChangePasswordAtLogonEffective -SamAccountName $sAMAccountName
                            if ($cplEffective -eq $true) {
                                $warn = "Warning: Destination user '$sAMAccountName' has ChangePasswordAtLogon effectively TRUE (pwdLastSet=0). Skipping PasswordNeverExpires=TRUE to prevent conflict."
                                $info = "PNE requested TRUE ($pneSource) was skipped due to destination safety check (pwdLastSet=0) for user: $sAMAccountName"
                                Write-Host $warn -ForegroundColor Yellow
                                Write-Log  $warn
                                Write-Verbose $info
                                Write-Log  $info
                            } elseif ($null -eq $cplEffective) {
                                $warn = "Warning: Could not verify ChangePasswordAtLogon state for destination user '$sAMAccountName'. Skipping PasswordNeverExpires=TRUE (safe-by-default)."
                                $info = "PNE requested TRUE ($pneSource) was skipped because destination pwdLastSet could not be verified for user: $sAMAccountName"
                                Write-Host $warn -ForegroundColor Yellow
                                Write-Log  $warn
                                Write-Verbose $info
                                Write-Log  $info
                            } else {
                                try {
                                    Set-ADUser -Identity $sAMAccountName -PasswordNeverExpires $true
                                    Write-Host "  => PasswordNeverExpires set to True for user: $sAMAccountName ($pneSource)"
                                    Write-Log  "PasswordNeverExpires set to True for user: sAMAccountName=$sAMAccountName source=$pneSource"
                                } catch {
                                    Write-Error "Failed to set PasswordNeverExpires for user ${sAMAccountName}: $_"
                                    Write-Log "Failed to set PasswordNeverExpires for user: sAMAccountName=${sAMAccountName}, PasswordNeverExpires='$pneRawValue' - $_"
                                }
                            }
                        } else {
                            # Dedicated column explicitly sets PasswordNeverExpires=FALSE
                            try {
                                Set-ADUser -Identity $sAMAccountName -PasswordNeverExpires $false
                                Write-Host "  => PasswordNeverExpires set to False for user: $sAMAccountName ($pneSource)"
                                Write-Log  "PasswordNeverExpires set to False for user: sAMAccountName=$sAMAccountName source=$pneSource"
                            } catch {
                                Write-Error "Failed to set PasswordNeverExpires for user ${sAMAccountName}: $_"
                                Write-Log "Failed to set PasswordNeverExpires for user: sAMAccountName=${sAMAccountName}, PasswordNeverExpires='$pneRawValue' - $_"
                            }
                        }
                    }

                    # Enable or disable the account only if the password is set
                    if ($userFlags -band 2) {
                        try {
                            Disable-ADAccount -Identity $sAMAccountName
                            Write-Host "  => Account disabled: $sAMAccountName"
                            Write-Log "Account disabled: sAMAccountName=$sAMAccountName"
                        } catch {
                            Write-Error "Failed to disable account ${sAMAccountName}: $_"
                            Write-Log "Failed to disable account: sAMAccountName=$sAMAccountName - $_"
                        }
                    } else {
                        if ($IsPasswordSet) {
                            try {
                                Enable-ADAccount -Identity $sAMAccountName
                                Write-Host "  => Account enabled: $sAMAccountName"
                                Write-Log "Account enabled: sAMAccountName=$sAMAccountName"
                            } catch {
                                Write-Error "Failed to enable account ${sAMAccountName}: $_"
                                Write-Log "Failed to enable account: sAMAccountName=$sAMAccountName - $_"
                            }
                        } else {
                            Write-Host "Warning: Failed to enable account $sAMAccountName as no password is set" -ForegroundColor Yellow
                            Write-Log "Failed to enable account $sAMAccountName as no password is set"
                        }
                    }

                    # Add this user to groups
                    $memberOfGroups = $usr.MemberOf -split ';'
                    $memberOfGroups = $memberOfGroups | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

                    # Ignore "Domain Users" from MemberOf list because the user joins it automatically as primary group
                    $memberOfGroups = $memberOfGroups | Where-Object { $_ -notmatch '(?i)^CN=Domain Users,' }

                    foreach ($mgrp in $memberOfGroups) {
                        if ($mgrp -ne "") {
                            $newDN = ""
                            try {
                                $newDN = Get-NewMemberOfDN -OriginalGroupDN $mgrp -DNPath $DNPath -SystemGroupSams $systemGroupSams
                                if (-not $newDN -or $newDN.Trim() -eq "") {
                                    Write-Host "Warning: Target group not found on destination AD; skipped MemberOf entry: $mgrp" -ForegroundColor Yellow
                                    Write-Log  "Warning: Target group not found on destination AD; skipped MemberOf entry: $mgrp (user=$sAMAccountName)"
                                    continue
                                }

                                Add-ADGroupMember -Identity $newDN -Members $($createdUser.DistinguishedName)
                                Write-Host "Added user $sAMAccountName to group: $newDN"
                                Write-Log  "User: sAMAccountName=$sAMAccountName added to group: $newDN"
                            } catch {
                                Write-Host "Failed to add user $sAMAccountName to group $newDN. Error: $_" -ForegroundColor Red
                                Write-Log  "Failed to add user sAMAccountName=$sAMAccountName to group: $newDN - $_"
                            }
                        }
                    }
                }
                else {
                    Write-Host "User $sAMAccountName already exists; skipping import"
                    Write-Log "User Skipped (Already Exists): sAMAccountName=$sAMAccountName"
                }
            }

        } elseif ($objectClass -eq "group") {
            # Import and sort groups by the total character length of MemberOf property
            # Check column duplication
            Assert-NoDuplicateCsvColumns -Path $filePath

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

                    # Set only required properties for 'New-ADGroup' here; move all others to '$additionalProperties'
                    $newGroupParams = @{
                        Name           = $grp.Name       # or $grp.CN
                        SamAccountName = $sAMAccountName
                        GroupCategory  = "Security"      # modified later if necessary
                        GroupScope     = "Global"        # modified later if necessary
                    }

                    # Set GroupCategory and GroupScope based on the groupType column.
                    # If groupType is blank, contains only spaces, or is prefixed with '#', use the GroupCategory and GroupScope string columns instead.
                    if (
                        -not $grp.groupType -or
                        ($grp.groupType -is [string] -and ($grp.groupType.Trim() -eq "" -or $grp.groupType.StartsWith('#')))
                    ) {
                        # Use the values from the string columns directly
                        foreach ($col in @("GroupCategory", "GroupScope")) {
                            if ($grp.$col -and $grp.$col.Trim() -ne "") {
                                $newGroupParams.$col = $grp.$col
                            } else {
                                Write-Host "Warning: '$col' column for group ${sAMAccountName} does not have a valid value" -ForegroundColor Yellow
                                Write-Log "Warning: '$col' column for group ${sAMAccountName} does not have a valid value; The property may be set to unintended value"
                            }
                        }
                    } else {
                        # Determine based on groupType integers
                        if ($grp.groupType -band 0x80000000) {
                            $newGroupParams.GroupCategory = "Security"
                        } else {
                            $newGroupParams.GroupCategory = "Distribution"
                        }
 
                        if ($grp.groupType -band 0x2)     { $newGroupParams.GroupScope = "Global" }
                        elseif ($grp.groupType -band 0x4) { $newGroupParams.GroupScope = "DomainLocal" }
                        elseif ($grp.groupType -band 0x8) { $newGroupParams.GroupScope = "Universal" }
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
                        Write-Log "Group Created: sAMAccountName=${sAMAccountName}, DistinguishedName=$($createdGroup.DistinguishedName)"
                    } else {
                        Write-Host "Group creation failed for ${sAMAccountName}; skipping further property setting." -ForegroundColor Red
                        Write-Log "Group creation failed for sAMAccountName=${sAMAccountName}; skipping further property setting."
                        continue
                    }

                    # Set additional properties using Set-ADGroup
                    $additionalProperties = @{
                        Description    = $grp.Description
                        # DON'T include "ManagedBy". It is registered separately in '-FixGroup' mode run of this script.
                        # Define other properties here if needed
                    }

                    foreach ($property in $additionalProperties.Keys) {
                        if ($additionalProperties[$property] -ne $null -and $additionalProperties[$property] -ne "") {
                            $params = @{
                                Identity = $sAMAccountName
                            }
                            $params[$property] = $additionalProperties[$property]
                            Try {
                                Set-ADGroup @params
                                Write-Host "  => Property $property set for group: $sAMAccountName"
                                Write-Log "Property $property set for group: sAMAccountName=$sAMAccountName"
                            } Catch {
                                Write-Host "Warning: Failed to set property $property for group ${sAMAccountName}" -ForegroundColor Yellow
                                Write-Log "Failed to set property $property for group: sAMAccountName=$sAMAccountName, ${property}='$($additionalProperties[$property])' - $_"
                            }
                        }
                    }

                    # Add this group to parent groups
                    $memberOfGroups = $grp.MemberOf -split ';'
                    foreach ($parentGroup in $memberOfGroups) {
                        if ($parentGroup -ne "") {
                            $newDN = ""
                            try {
                                $newDN = Get-NewMemberOfDN -OriginalGroupDN $parentGroup -DNPath $DNPath -SystemGroupSams $systemGroupSams
                                if (-not $newDN -or $newDN.Trim() -eq "") {
                                    Write-Host "Warning: Target group not found on destination AD; skipped MemberOf entry: $parentGroup" -ForegroundColor Yellow
                                    Write-Log  "Warning: Target group not found on destination AD; skipped MemberOf entry: $parentGroup (group=$sAMAccountName)"
                                    continue
                                }

                                Add-ADGroupMember -Identity $newDN -Members $($createdGroup.DistinguishedName)
                                Write-Host "Added group $sAMAccountName to parent group: $newDN"
                                Write-Log  "Group: sAMAccountName=$sAMAccountName added to group: $newDN"
                            } catch {
                                Write-Host "Failed to add group $sAMAccountName to group $newDN. Error: $_" -ForegroundColor Red
                                Write-Log  "Failed to add group sAMAccountName=$sAMAccountName to group: $newDN - $_"
                            }
                        }
                    }
                }
                else {
                    Write-Host "Group $sAMAccountName already exists; skipping import"
                    Write-Log "Group Skipped (Already Exists): sAMAccountName=$sAMAccountName"
                }
            }

        } elseif ($objectClass -eq "computer") {
            # Check column duplication
            Assert-NoDuplicateCsvColumns -Path $filePath

            $computers = Import-Csv -Path $filePath | Where-Object {
                if ($IncludeSystemObject) {
                    return $true
                } else {
                    if ($_.isCriticalSystemObject -eq "TRUE" -or $_.sAMAccountName -in $excludedComputers) {
                        Write-Host "Excluded System Computer: $($_.sAMAccountName)"
                        Write-Log "Excluded System Computer: sAMAccountName=$($_.sAMAccountName)"
                        return $false
                    } else {
                        return $true
                    }
                }
            }

            # Ensure these records are of AD Computers
            Test-ObjectClassColumn -CsvRows $computers -ExpectClass 'computer' -NoClassCheck:$NoClassCheck

            foreach ($comp in $computers) {
                $sAMAccountName = $comp.sAMAccountName

                # Check existence of the computer
                $computerExists = Get-ADComputer -Filter "SamAccountName -eq '$sAMAccountName'" -ErrorAction SilentlyContinue

                if (-not $computerExists) {
                    Write-Host "Processing computer sAMAccountName=`"$sAMAccountName`""
                    Write-Log "Processing computer sAMAccountName=`"$sAMAccountName`""

                    $ouPath = ConvertDNBase -oldDN $comp.DistinguishedName -newDNPath $DNPath -CreateOUIfNotExists
                    $managedByDN = if ($comp.ManagedBy -ne "") {
                          Get-NewDN -originalDN $comp.ManagedBy -DNPath $DNPath -DefaultContainer (Get-DefaultContainerName -Want "User")
                      } else {
                          $null
                    }

                    # Set only required properties for 'New-ADComputer' here; move all others to '$additionalProperties'
                    $newComputerParams = @{
                        Name           = $comp.Name
                        SamAccountName = $sAMAccountName
                    }

                    Try {
                        if ($ouPath -match '^CN=Computers,DC=') {
                            New-ADComputer @newComputerParams -ErrorAction Stop
                            Write-Log "New-ADComputer `@newComputerParams"
                        } else {
                            New-ADComputer @newComputerParams -Path $ouPath -ErrorAction Stop
                            Write-Log "New-ADComputer `@newComputerParams -Path $ouPath"
                        }
                    } Catch {
                        Write-Error "Failed to create computer ${sAMAccountName}: $_"
                        Write-Log "Failed to create computer: sAMAccountName=$sAMAccountName - $_"
                    }

                    $createdComputer = Get-ADComputer -Filter "SamAccountName -eq '$sAMAccountName'" -Properties DistinguishedName
                    if ($createdComputer) {
                        Write-Host "Computer Created DistinguishedName=$($createdComputer.DistinguishedName)"
                        Write-Log "Computer Created: sAMAccountName=${sAMAccountName}, DistinguishedName=$($createdComputer.DistinguishedName)"
                    } else {
                        Write-Host "Computer creation failed for ${sAMAccountName}; skipping further property setting." -ForegroundColor Red
                        Write-Log "Computer creation failed for sAMAccountName=${sAMAccountName}; skipping further property setting."
                        continue
                    }

                    # Set additional properties using Set-ADComputer
                    $additionalProperties = @{
                        Description            = $comp.Description
                        Location               = $comp.Location
                        ManagedBy              = $managedByDN
                        OperatingSystem        = $comp.OperatingSystem        # Will be overwritten on actual computer join
                        OperatingSystemVersion = $comp.OperatingSystemVersion # Will be overwritten on actual computer join
                        DNSHostName            = $comp.DNSHostName            # Will be overwritten on actual computer join
                        # Define other properties here if needed
                    }

                    foreach ($property in $additionalProperties.Keys) {
                        if ($additionalProperties[$property] -ne $null -and $additionalProperties[$property] -ne "") {
                            $params = @{
                                Identity = $sAMAccountName
                            }
                            $params[$property] = $additionalProperties[$property]
                            Try {
                                Set-ADComputer @params
                                Write-Host "  => Property $property set for computer: $sAMAccountName"
                                Write-Log "Property $property set for computer: sAMAccountName=$sAMAccountName"
                            } Catch {
                                Write-Host "Warning: Failed to set property $property for computer ${sAMAccountName}" -ForegroundColor Yellow
                                Write-Log "Failed to set property $property for computer: sAMAccountName=$sAMAccountName, ${property}='$($additionalProperties[$property])' - $_"
                            }
                        }
                    }

                    # Disable computer account if source userAccountControl has disabled bit
                    if ([int]$comp.userAccountControl -band 2) {
                        try {
                            Disable-ADAccount -Identity $sAMAccountName
                            Write-Host "  => Account disabled: $sAMAccountName"
                            Write-Log "Account disabled: sAMAccountName=$sAMAccountName"
                        } catch {
                            Write-Error "Failed to disable computer account ${sAMAccountName}: $_"
                            Write-Log "Failed to disable computer account: sAMAccountName=$sAMAccountName - $_"
                        }
                    }

                    # Add this computer to groups
                    $memberOfGroups = $comp.MemberOf -split ';'
                    foreach ($mgrp in $memberOfGroups) {
                        if ($mgrp -ne "") {
                            $newDN = ""
                            try {
                                $newDN = Get-NewMemberOfDN -OriginalGroupDN $mgrp -DNPath $DNPath -SystemGroupSams $systemGroupSams
                                if (-not $newDN -or $newDN.Trim() -eq "") {
                                    Write-Host "Warning: Target group not found on destination AD; skipped MemberOf entry: $mgrp" -ForegroundColor Yellow
                                    Write-Log  "Warning: Target group not found on destination AD; skipped MemberOf entry: $mgrp (computer=$sAMAccountName)"
                                    continue
                                }

                                Add-ADGroupMember -Identity $newDN -Members $($createdComputer.DistinguishedName)
                                Write-Host "Added computer $sAMAccountName to group: $newDN"
                                Write-Log  "Computer: sAMAccountName=$sAMAccountName added to group: $newDN"
                            } catch {
                                Write-Host "Failed to add computer $sAMAccountName to group $newDN. Error: $_" -ForegroundColor Red
                                Write-Log  "Failed to add computer sAMAccountName=$sAMAccountName to group: $newDN - $_"
                            }
                        }
                    }
                }
                else {
                    Write-Host "Computer $sAMAccountName already exists; skipping import"
                    Write-Log "Computer Skipped (Already Exists): sAMAccountName=$sAMAccountName"
                }
            }
        }
    }

    # Register ManagedBy property for Groups
    function Fixup-GroupManagedBy {
        param(
            [string]$GroupFile,
            [string]$DNPath
        )

        # Check column duplication and import the CSV
        Assert-NoDuplicateCsvColumns -Path $GroupFile
        $groups = Import-Csv -Path $GroupFile

        foreach ($grp in $groups) {
            $sAMAccountName = $grp.sAMAccountName
            $managedByOrig  = $grp.ManagedBy

            if (-not $managedByOrig -or $managedByOrig.Trim() -eq "") {
              # Write-Log "debug :: Fixup-GroupManagedBy : Group '$sAMAccountName' has no ManagedBy set in source; skipping"
                continue
            }
            Write-Host "Processing group sAMAccountName=`"$sAMAccountName`""
            Write-Log  "Processing group sAMAccountName=`"$sAMAccountName`""

            # Locate the group in AD
            $targetGroup = Get-ADGroup -Filter "SamAccountName -eq '$sAMAccountName'" -Properties ManagedBy -ErrorAction SilentlyContinue
            if (-not $targetGroup) {
                Write-Host "Group '$sAMAccountName' does not exist; skipping" -ForegroundColor Yellow
                Write-Log  "Group skipped (Not Exist): sAMAccountName=$sAMAccountName"
                continue
            }

            $newManagedBy = Get-NewDN -originalDN $managedByOrig -DNPath $DNPath
            if (-not $newManagedBy) {
                Write-Host "ManagedBy DN could not be resolved for ${sAMAccountName}; skipping" -ForegroundColor Yellow
                Write-Log  "ManagedBy DN could not be resolved: sAMAccountName=$sAMAccountName"
                continue
            }

            # Try to resolve as user, then group
            $managedByObject = Get-ADUser -Identity $newManagedBy -ErrorAction SilentlyContinue
            $managedByType = "user"
            if (-not $managedByObject) {
                $managedByObject = Get-ADGroup -Identity $newManagedBy -ErrorAction SilentlyContinue
                $managedByType = "group"
            }

            if (-not $managedByObject) {
                $msg = "Reference held by 'ManagedBy' property of group '$sAMAccountName' does not exist or is unexpected object type (Contact?)"
                Write-Host $msg -ForegroundColor Yellow
                Write-Log "${msg}: Source DN='$managedByOrig', Target DN='$newManagedBy'"
                continue
            }

            # Skip if the same DN is already set
          # Write-Log "debug :: Fixup-GroupManagedBy : targetGroup.ManagedBy: $($targetGroup.ManagedBy)"
            if ($targetGroup.ManagedBy -eq $newManagedBy) {
                Write-Host "Group '$sAMAccountName': ManagedBy already set to correct DN, skipping"
                Write-Log "Group '$sAMAccountName': ManagedBy already set to correct DN: '$newManagedBy', skipping"
                continue
            }

            Try {
                Set-ADGroup -Identity $targetGroup.DistinguishedName -ManagedBy $newManagedBy
                Write-Host "Set ManagedBy for $sAMAccountName -> $newManagedBy"
                Write-Log  "Set ManagedBy for sAMAccountName=$sAMAccountName -> $newManagedBy ($managedByType)"
            } Catch {
                Write-Host "Failed to set ManagedBy for ${sAMAccountName}: $_" -ForegroundColor Red
                Write-Log  "Failed to set ManagedBy for sAMAccountName=${sAMAccountName}: $_"
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

        $DNPath = ConvertPrefixToDNPath -prefix $DNPrefix -depth $DCDepth
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
    if ($NoDefaultContainer) {
        Write-Host "Option: 'NoDefaultContainer' enabled"
        Write-Log  "Option: 'NoDefaultContainer' enabled"
    }
    if ($NoForceDefaultContainer) {
        Write-Host "Option: 'NoForceDefaultContainer' enabled"
        Write-Log  "Option: 'NoForceDefaultContainer' enabled"
    }
    if ($PSBoundParameters.ContainsKey('NewUPNSuffix')) {
        $upnMsg = "Option: 'NewUPNSuffix' specified: $NewUPNSuffix"
        Write-Host $upnMsg
        Write-Log $upnMsg
    }

    # Group Data Import Mode
    if ($groupMode) {
        # Select the group file if not specified
        if (-not $GroupFile) {
            $GroupFile = Select-Input-File -type "group"
        }
        if (-not (Test-Path $GroupFile)) {
            Write-Error "Specified GroupFile does not exist"
            exit 1
        }

        # Warn if filename looks like other modes
        if (FileName-WrongType-Warn -FilePath $GroupFile -MyType "group") { exit 1 }

        Write-Host "Group File Path: $GroupFile"
        Write-Log "Group File Path: $GroupFile"
        Import-ADObject -filePath $GroupFile -objectClass "group"
    }

    # User Data Import Mode
    if ($userMode) {
        # Select the user file if not specified
        if (-not $UserFile) {
            $UserFile = Select-Input-File -type "user"
        }
        if (-not (Test-Path $UserFile)) {
            Write-Error "Specified UserFile does not exist"
            exit 1
        }

        # Warn if filename looks like other modes
        if (FileName-WrongType-Warn -FilePath $UserFile -MyType "user") { exit 1 }

        Write-Host "User File Path: $UserFile"
        Write-Log "User File Path: $UserFile"
        Import-ADObject -filePath $UserFile -objectClass "user"
    }

    # Computer Data Import Mode
    if ($computerMode) {
        # Select the computer file if not specified
        if (-not $ComputerFile) {
            $ComputerFile = Select-Input-File -type "computer"
        }
        if (-not (Test-Path $ComputerFile)) {
            Write-Error "Specified ComputerFile does not exist"
            exit 1
        }

        # Warn if filename looks like other modes
        if (FileName-WrongType-Warn -FilePath $ComputerFile -MyType "computer") { exit 1 }

        Write-Host "Computer File Path: $ComputerFile"
        Write-Log "Computer File Path: $ComputerFile"
        Import-ADObject -filePath $ComputerFile -objectClass "computer"
    }

    # Group Fix Mode
    if ($fixGroupMode) {
        # Select the group file if not specified
        if (-not $GroupFile) {
            $GroupFile = Select-Input-File -type "group"
        }
        if (-not (Test-Path $GroupFile)) {
            Write-Error "Specified GroupFile does not exist"
            exit 1
        }

        # Warn if filename looks like other modes
        if (FileName-WrongType-Warn -FilePath $GroupFile -MyType "group") { exit 1 }

        Write-Host "Group File Path: $GroupFile"
        Write-Log "Group File Path: $GroupFile"
        Fixup-GroupManagedBy -GroupFile $GroupFile -DNPath $DNPath
    }

# End of process
}

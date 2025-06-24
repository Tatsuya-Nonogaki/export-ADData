<#
 .SYNOPSIS
  Check whether the user's password is set as expected.
 
 .DESCRIPTION
  Checks whether the user's password is set as expected by querying the AD. 
  You can preset Domain in the script itself to save labor when running the 
  script repeatedly.
  Version: 0.1.1
 
 .PARAMETER UserName
  (Alias -u) The user whose password is to be validated. Mandatory but 
  PowerShell will prompt you if omitted.
 
 .PARAMETER Password
  (Alias -p) The passowrd string in plain text. Mandatory but PowerShell 
  will prompt you if omitted, which is recommended for security.
 
 .PARAMETER Domain
  (Alias -d) Optional. The AD Domain to query. The preset Domain is used if 
  omitted. It accepts either dot-notation and DistinguishedName format.
#>
[CmdletBinding()]
param(
    [Parameter(Position=0, Mandatory=$true)]
    [Alias("u")]
    [string]$UserName,

    [Parameter(Position=1)]
    [Alias("p")]
    [string]$Password,

    [Parameter(Position=2)]
    [Alias("d")]
    [string]$Domain
) 

# Preset Domain to query to save labor
$MyDomain = "mytestrealm.local"

Import-Module ActiveDirectory -ErrorAction Stop

if (-not $Password) {
    $SecurePassword = Read-Host "Enter Password" -AsSecureString
    # Convert to plain text for DirectoryEntry operation
    $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    try {
        $PasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)
    }
} else {
    $PasswordPlain = $Password
}

if ($Domain) {
    $domainURL = "LDAP://" + $Domain
} else {
    $domainURL = "LDAP://" + $MyDomain
}

$domainObj =  New-Object System.DirectoryServices.DirectoryEntry(
   $domainURL, 
   $UserName,
   $PasswordPlain
)
if ($null -eq $domainObj.Name) {
  Write-Host "User `"$Username`": password unmatched or user is not active" -ForegroundColor Yellow
} else {
  Write-Host "User `"$Username`": password matched"
}

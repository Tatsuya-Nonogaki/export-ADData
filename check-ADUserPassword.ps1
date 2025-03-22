<#
 .SYNOPSIS
  Check whether the user's password is set as expected.
 
 .DESCRIPTION
  Checks whether the user's password is set as expected by querying the AD. 
  You can preset Domain in the script itself to save labor when running the 
  script repeatedly.
  Version: 0.1.0
 
 .PARAMETER UserName
  (Alias -u) The user whose password is to be validated. Mandatory but 
  PowerShell will prompt you if omitted.
 
 .PARAMETER Password
  (Alias -p) The passowrd string in plain text. Mandatory but PowerShell 
  will prompt you if omitted, which is recommended for security.
 
 .PARAMETER Domain
  (Alias -d) Optional. The AD Domain to query. The preset Domain is used if 
  omitted.
#>
[CmdletBinding()]
param(
    [Parameter(Position=0, Mandatory=$true)]
    [Alias("u")]
    [string]$UserName,

    [Parameter(Position=1, Mandatory=$true)]
    [Alias("p")]
    [string]$Password,

    [Parameter(Position=2)]
    [Alias("d")]
    [string]$Domain
) 

# Preset Domain to query to save labor
$MyDomain = "mytestrealm.local"

Import-Module ActiveDirectory -ErrorAction Stop

if ($Domain) {
    $domainURL = "LDAP://" + $Domain
} else {
    $domainURL = "LDAP://" + $MyDomain
}

$domainObj =  New-Object System.DirectoryServices.DirectoryEntry(
   $domainURL, 
   $UserName,
   $Password
)
if ($null -eq $domainObj.Name) {
  Write-Host "User `"$Username`": password unmatched or user is not active" -ForegroundColor Yellow
} else {
  Write-Host "User `"$Username`": password matched"
}

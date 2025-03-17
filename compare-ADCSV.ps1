<#
 .SYNOPSIS
  Compare two CSVs of users or groups exported from Active Directory.
 
 .DESCRIPTION
  Compare two CSVs of users or groups exported from Active Directory, 
  with sAMAccountName as the key.
  Version: 0.1.1
 
 .PARAMETER OldFile
  (Alias -o) Mandatory. Old CSV file to compare, with relative or absolute path.
 
 .PARAMETER OldFile
  (Alias -n) Mandatory. New CSV file, with relative or absolute path.
 
 .PARAMETER OutFile
  Optional. Path of desired output CSV file. If not specified, output is written 
  only to the PS console.
#>
[CmdletBinding()]
param(
    [Parameter(Position=0, Mandatory=$true)]
    [Alias("o")]
    [string]$OldFile,

    [Parameter(Position=1, Mandatory=$true)]
    [Alias("n")]
    [string]$NewFile,

    [Parameter(Position=2)]
    [string]$OutFile
)

$scriptdir = Split-Path -Path $myInvocation.MyCommand.Path -Parent

$oldUsers = Import-Csv -Path $OldFile
$newUsers = Import-Csv -Path $NewFile

$comparisonResults = @()

$newUsersHashTable = @{}
$newUsers | ForEach-Object { $newUsersHashTable[$_.sAMAccountName] = $_ }

foreach ($oldUser in $oldUsers) {
    $sAMAccountName = $oldUser.sAMAccountName
    if ($newUsersHashTable.ContainsKey($sAMAccountName)) {
        $newUser = $newUsersHashTable[$sAMAccountName]
        $oldDN = $oldUser.DistinguishedName
        $newDN = $newUser.DistinguishedName

        if ($oldDN -ne $newDN) {
            $differencePoints = Compare-Object -ReferenceObject ($oldDN -split ',') -DifferenceObject ($newDN -split ',') | ForEach-Object {
                if ($_.SideIndicator -eq '<=') {
                    "--- $($_.InputObject)"
                } elseif ($_.SideIndicator -eq '=>') {
                    "+++ $($_.InputObject)"
                }
            }

            $comparisonResult = [PSCustomObject]@{
                sAMAccountName     = $sAMAccountName
                OldDistinguishedName = $oldDN
                NewDistinguishedName = $newDN
                DifferencePoints    = $differencePoints -join "; "
            }
            $comparisonResults += $comparisonResult
        }
    } else {
        # User present in old file but missing in new file
        $comparisonResult = [PSCustomObject]@{
            sAMAccountName     = $sAMAccountName
            OldDistinguishedName = $oldUser.DistinguishedName
            NewDistinguishedName = "MISSING"
            DifferencePoints    = "Entry missing in new CSV"
        }
        $comparisonResults += $comparisonResult
    }
}

# Check for users present in new file but missing in old file
$oldUsersHashTable = @{}
$oldUsers | ForEach-Object { $oldUsersHashTable[$_.sAMAccountName] = $_ }

foreach ($newUser in $newUsers) {
    $sAMAccountName = $newUser.sAMAccountName
    if (-not $oldUsersHashTable.ContainsKey($sAMAccountName)) {
        # User present in new file but missing in old file
        $comparisonResult = [PSCustomObject]@{
            sAMAccountName     = $sAMAccountName
            OldDistinguishedName = "MISSING"
            NewDistinguishedName = $newUser.DistinguishedName
            DifferencePoints    = "Entry missing in old CSV"
        }
        $comparisonResults += $comparisonResult
    }
}

if ($OutFile) {
    $comparisonResults | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
} else {
    $comparisonResults | Format-Table -AutoSize
}

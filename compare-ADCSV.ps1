<#
 .SYNOPSIS
  Compare two CSVs of users or groups exported from Active Directory.
 
 .DESCRIPTION
  Compare two CSVs of users or groups exported from Active Directory, 
  with sAMAccountName as the key.
  Version: 0.1.4
 
 .PARAMETER OldFile
  (Alias -o) Mandatory. Old CSV file to compare, with relative or absolute path.
 
 .PARAMETER NewFile
  (Alias -n) Mandatory. New CSV file, with relative or absolute path.
 
 .PARAMETER OutFile
  Optional. Path to a CSV file for the output. If not specified, output 
  is written only to the PS console.
 
 .PARAMETER IncludeEqual
  Optional. Include entries with no difference in the output.
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
    [string]$OutFile,

    [Parameter()]
    [switch]$IncludeEqual
)

$oldUsers = Import-Csv -Path $OldFile
$newUsers = Import-Csv -Path $NewFile

$comparisonResults = @()

# Determine if the CSVs are user exports by checking for user-specific properties
$isUserExport = $false
if ($oldUsers[0].PSObject.Properties.Name -contains 'ObjectClass') {
    $isUserExport = $oldUsers[0].ObjectClass -eq 'user'
} else {
    $isUserExport = $oldUsers[0].PSObject.Properties.Name -contains 'GivenName' -or $oldUsers[0].PSObject.Properties.Name -contains 'Surname' -or $oldUsers[0].PSObject.Properties.Name -contains 'UserPrincipalName'
}

$newUsersHashTable = @{}
$newUsers | ForEach-Object { $newUsersHashTable[$_.sAMAccountName] = $_ }

foreach ($oldUser in $oldUsers) {
    $sAMAccountName = $oldUser.sAMAccountName
    if ($newUsersHashTable.ContainsKey($sAMAccountName)) {
        $newUser = $newUsersHashTable[$sAMAccountName]
        $oldDN = $oldUser.DistinguishedName
        $newDN = $newUser.DistinguishedName

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

        if ($isUserExport) {
            $oldEnabled = if ($oldUser.PSObject.Properties.Name -contains 'Enabled') { $oldUser.Enabled } else { "" }
            $newEnabled = if ($newUser.PSObject.Properties.Name -contains 'Enabled') { $newUser.Enabled } else { "" }
            $oldPasswordNeverExpires = if ($oldUser.PSObject.Properties.Name -contains 'PasswordNeverExpires') { $oldUser.PasswordNeverExpires } else { "" }
            $newPasswordNeverExpires = if ($newUser.PSObject.Properties.Name -contains 'PasswordNeverExpires') { $newUser.PasswordNeverExpires } else { "" }

            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldEnabled -Value $oldEnabled
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewEnabled -Value $newEnabled
            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldPasswordNeverExpires -Value $oldPasswordNeverExpires
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewPasswordNeverExpires -Value $newPasswordNeverExpires
        }

        if ($comparisonResult.DifferencePoints -or ($isUserExport -and ($comparisonResult.OldEnabled -ne $comparisonResult.NewEnabled -or $comparisonResult.OldPasswordNeverExpires -ne $comparisonResult.NewPasswordNeverExpires)) -or $IncludeEqual) {
            $comparisonResults += $comparisonResult
        }
    } else {
        # Entries present in old file but missing in new file
        $comparisonResult = [PSCustomObject]@{
            sAMAccountName     = $sAMAccountName
            OldDistinguishedName = $oldUser.DistinguishedName
            NewDistinguishedName = "MISSING"
            DifferencePoints    = "Entry missing in new CSV"
        }

        if ($isUserExport) {
            $oldEnabled = if ($oldUser.PSObject.Properties.Name -contains 'Enabled') { $oldUser.Enabled } else { "" }
            $newEnabled = ""
            $oldPasswordNeverExpires = if ($oldUser.PSObject.Properties.Name -contains 'PasswordNeverExpires') { $oldUser.PasswordNeverExpires } else { "" }
            $newPasswordNeverExpires = ""

            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldEnabled -Value $oldEnabled
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewEnabled -Value $newEnabled
            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldPasswordNeverExpires -Value $oldPasswordNeverExpires
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewPasswordNeverExpires -Value $newPasswordNeverExpires
        }

        $comparisonResults += $comparisonResult
    }
}

# Check for entries present in new file but missing in old file
$oldUsersHashTable = @{}
$oldUsers | ForEach-Object { $oldUsersHashTable[$_.sAMAccountName] = $_ }

foreach ($newUser in $newUsers) {
    $sAMAccountName = $newUser.sAMAccountName
    if (-not $oldUsersHashTable.ContainsKey($sAMAccountName)) {
        $comparisonResult = [PSCustomObject]@{
            sAMAccountName     = $sAMAccountName
            OldDistinguishedName = "MISSING"
            NewDistinguishedName = $newUser.DistinguishedName
            DifferencePoints    = "Entry missing in old CSV"
        }

        if ($isUserExport) {
            $oldEnabled = ""
            $newEnabled = if ($newUser.PSObject.Properties.Name -contains 'Enabled') { $newUser.Enabled } else { "" }
            $oldPasswordNeverExpires = ""
            $newPasswordNeverExpires = if ($newUser.PSObject.Properties.Name -contains 'PasswordNeverExpires') { $newUser.PasswordNeverExpires } else { "" }

            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldEnabled -Value $oldEnabled
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewEnabled -Value $newEnabled
            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldPasswordNeverExpires -Value $oldPasswordNeverExpires
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewPasswordNeverExpires -Value $newPasswordNeverExpires
        }

        $comparisonResults += $comparisonResult
    }
}

if ($OutFile) {
    $comparisonResults | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
} else {
    $comparisonResults | Format-Table -AutoSize
}

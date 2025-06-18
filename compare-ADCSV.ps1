<#
 .SYNOPSIS
  Compare two CSVs of users or groups exported from Active Directory.
 
 .DESCRIPTION
  Compare two CSVs of users or groups exported from Active Directory, 
  with sAMAccountName as the key.
  Version: 0.2.0
 
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

# Detect user vs group export
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

        # DistinguishedName diff
        $differencePoints = Compare-Object -ReferenceObject ($oldDN -split ',') -DifferenceObject ($newDN -split ',') | ForEach-Object {
            if ($_.SideIndicator -eq '<=') {
                "--- $($_.InputObject)"
            } elseif ($_.SideIndicator -eq '=>') {
                "+++ $($_.InputObject)"
            }
        }

        # MemberOf diff
        $removed = @()
        $added = @()
        $diffs = @()
        $oldMemberOf = $oldUser.MemberOf
        $newMemberOf = $newUser.MemberOf
        $memberOfDiff = ""
        if ($null -ne $oldMemberOf -or $null -ne $newMemberOf) {
            $oldSet = @()
            $newSet = @()
            if ($null -ne $oldMemberOf -and $oldMemberOf -ne "") {
                $oldSet = $oldMemberOf -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" } | Sort-Object { $_.ToLower() }
            }
            if ($null -ne $newMemberOf -and $newMemberOf -ne "") {
                $newSet = $newMemberOf -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" } | Sort-Object { $_.ToLower() }
            }
            $removed = @(Compare-Object -ReferenceObject $oldSet -DifferenceObject $newSet | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { "--- $($_.InputObject)" })
            $added   = @(Compare-Object -ReferenceObject $oldSet -DifferenceObject $newSet | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object { "+++ $($_.InputObject)" })
            $diffs = $removed + $added
            $memberOfDiff = $diffs -join '; '
        }

        $comparisonResult = [PSCustomObject]@{
            sAMAccountName        = $sAMAccountName
            OldDistinguishedName  = $oldDN
            NewDistinguishedName  = $newDN
            DifferencePoints      = $differencePoints -join "; "
            MemberOfDiff          = $memberOfDiff
        }

        # Additional user properties
        if ($isUserExport) {
            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldEnabled -Value ($oldUser.Enabled)
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewEnabled -Value ($newUser.Enabled)
            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldPasswordNeverExpires -Value ($oldUser.PasswordNeverExpires)
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewPasswordNeverExpires -Value ($newUser.PasswordNeverExpires)
        }

        # Output logic
        $anyDiff = $comparisonResult.DifferencePoints -or $comparisonResult.MemberOfDiff
        if ($isUserExport) {
            $anyDiff = $anyDiff -or ($comparisonResult.OldEnabled -ne $comparisonResult.NewEnabled) -or ($comparisonResult.OldPasswordNeverExpires -ne $comparisonResult.NewPasswordNeverExpires)
        }
        if ($anyDiff -or $IncludeEqual) {
            $comparisonResults += $comparisonResult
        }

        $newUsersHashTable.Remove($sAMAccountName)
    } else {
        # Deleted in new
        $comparisonResults += [PSCustomObject]@{
            sAMAccountName        = $sAMAccountName
            OldDistinguishedName  = $oldUser.DistinguishedName
            NewDistinguishedName  = ""
            DifferencePoints      = "--- Missing in new"
            MemberOfDiff          = ""
        }
    }
}

# Added in new
foreach ($newUser in $newUsersHashTable.Values) {
    $comparisonResults += [PSCustomObject]@{
        sAMAccountName        = $newUser.sAMAccountName
        OldDistinguishedName  = ""
        NewDistinguishedName  = $newUser.DistinguishedName
        DifferencePoints      = "+++ New in new"
        MemberOfDiff          = ""
    }
}

if ($OutFile) {
    $comparisonResults | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
} else {
    $comparisonResults | Format-Table -AutoSize
}

<#
 .SYNOPSIS
  Compare two CSVs of users, groups, or computers exported from Active Directory.
 
 .DESCRIPTION
  Compare two CSVs of users, groups, or computers exported from Active Directory. 
  Version: 0.2.3
  
  Comparison is done with sAMAccountName as the key, without being affected by 
  the order of records in the CSV file, unlike ordinary "diff" tools. Detects 
  and outputs records where there is a difference in DistinguishedName, MemberOf, 
  or when an entry is present only on one side.
  For user CSVs, differences in 'Enabled' and 'PasswordNeverExpires' are also 
  checked and reported, but these fields are considered auxiliary and do not 
  affect the main inclusion criteria.
 
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

$oldRecords = Import-Csv -Path $OldFile
$newRecords = Import-Csv -Path $NewFile

$comparisonResults = @()

# Detect user vs other export
$isUserExport = $false
if ($oldRecords[0].PSObject.Properties.Name -contains 'ObjectClass') {
    $isUserExport = $oldRecords[0].ObjectClass -eq 'user'
} else {
    $isUserExport = $oldRecords[0].PSObject.Properties.Name -contains 'GivenName' -or $oldRecords[0].PSObject.Properties.Name -contains 'Surname' -or $oldRecords[0].PSObject.Properties.Name -contains 'UserPrincipalName'
}

$newRecordsHashTable = @{}
$newRecords | ForEach-Object { $newRecordsHashTable[$_.sAMAccountName] = $_ }

foreach ($oldEntry in $oldRecords) {
    $sAMAccountName = $oldEntry.sAMAccountName
    if ($newRecordsHashTable.ContainsKey($sAMAccountName)) {
        $newEntry = $newRecordsHashTable[$sAMAccountName]
        $oldDN = $oldEntry.DistinguishedName
        $newDN = $newEntry.DistinguishedName

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
        $oldMemberOf = $oldEntry.MemberOf
        $newMemberOf = $newEntry.MemberOf
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
            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldEnabled -Value ($oldEntry.Enabled)
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewEnabled -Value ($newEntry.Enabled)
            $comparisonResult | Add-Member -MemberType NoteProperty -Name OldPasswordNeverExpires -Value ($oldEntry.PasswordNeverExpires)
            $comparisonResult | Add-Member -MemberType NoteProperty -Name NewPasswordNeverExpires -Value ($newEntry.PasswordNeverExpires)
        }

        # Output logic
        $anyDiff = $comparisonResult.DifferencePoints -or $comparisonResult.MemberOfDiff
        if ($isUserExport) {
            $anyDiff = $anyDiff -or ($comparisonResult.OldEnabled -ne $comparisonResult.NewEnabled) -or ($comparisonResult.OldPasswordNeverExpires -ne $comparisonResult.NewPasswordNeverExpires)
        }
        if ($anyDiff -or $IncludeEqual) {
            $comparisonResults += $comparisonResult
        }

        $newRecordsHashTable.Remove($sAMAccountName)
    } else {
        # Deleted in new
        $comparisonResults += [PSCustomObject]@{
            sAMAccountName        = $sAMAccountName
            OldDistinguishedName  = $oldEntry.DistinguishedName
            NewDistinguishedName  = ""
            DifferencePoints      = "--- Missing in new"
            MemberOfDiff          = ""
        }
    }
}

# Added in new
foreach ($newEntry in $newRecordsHashTable.Values) {
    $comparisonResults += [PSCustomObject]@{
        sAMAccountName        = $newEntry.sAMAccountName
        OldDistinguishedName  = ""
        NewDistinguishedName  = $newEntry.DistinguishedName
        DifferencePoints      = "+++ New in new"
        MemberOfDiff          = ""
    }
}

if ($OutFile) {
    $comparisonResults | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
} else {
    $comparisonResults | Format-Table -AutoSize
}

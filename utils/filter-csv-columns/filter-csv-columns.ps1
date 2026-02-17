<#
.SYNOPSIS
  Filter a CSV file by column names and export it as a new CSV.

.DESCRIPTION
  This script reads a CSV file, filters its columns based on a column list,
  and writes the result to another CSV file.

  By default, the column list is treated as an include list:
    - Only the columns listed in the column list are kept.
  When -Exclude is specified (exclude mode):
    - All columns *except* those listed in the column list are kept.

  The column list can be provided in three ways:

  1. No -ColumnFile:
     The built-in list (defined in the "Get-ColumnList" function) is used.
  2. -ColumnFile <file-path> with file extension .csv:
     The file should contain a comma-separated list of column names, e.g.:
       MemberOf,CN,Description,DisplayName,...
  3. -ColumnFile <file-path> with file extension .ps1:
     The file must define a variable named "$columnList", e.g.:
       $columnList = @("MemberOf", "CN", "Description", ...)

  NOTES:
  Input and output are processed via Import-Csv / Export-Csv.
  - Output is written with UTF-8 encoding and without type information.
  - For stable processing, the input file should also be encoded in UTF-8.

.PARAMETER InFile
  (Alias -i) Mandatory. Path to the input CSV file.

.PARAMETER OutFile
  (Alias -o) Mandatory. Path to the output CSV file to be written.

.PARAMETER ColumnFile
  (Alias -c) Optional. Path to a column list definition file:
  - If it ends with .csv, it is treated as a comma-separated list of column names.
  - If it ends with .ps1, it must define a variable named $columnList.

.PARAMETER Exclude
  (Alias -x) Negates the column selection. When specified, the column list
  is treated as an exclude list, so columns NOT listed in the list will be kept.

.EXAMPLE
  # Uses the built-in column list and keeps only those columns.
  .\filter-csv-columns.ps1 -InFile input.csv -OutFile output.csv

.EXAMPLE
  # Reads column names from columns.csv (comma-separated) and keeps only those columns.
  .\filter-csv-columns.ps1 -i data.csv -o filtered.csv -c columns-ADUsers.csv

.EXAMPLE
  # Reads $columnList from columns.ps1 and keeps all columns *except* those in $columnList.
  .\filter-csv-columns.ps1 -i data.csv -o filtered.csv -c columns-ADUsers.ps1 -Exclude
#>

[CmdletBinding()]
param(
    [Parameter(Position=0, Mandatory = $true)]
    [Alias("i")]
    [string]$InFile,

    [Parameter(Position=1, Mandatory = $true)]
    [Alias("o")]
    [string]$OutFile,

    [Parameter(Position=2, Mandatory = $false)]
    [Alias("c")]
    [string]$ColumnFile,

    [Parameter(Mandatory = $false)]
    [Alias("x")]
    [switch]$Exclude
)

# --- Get list of columns (used as include-list or exclude-list)
function Get-ColumnList {
    param(
        [string]$ColumnFilePath
    )

    if (-not $ColumnFilePath) {
        # Default column-list when -ColumnFile is not specified:
        # Define as you need for quick one-shot operations,
        # or always specify -ColumnFile.
        return @(
            "MemberOf",
            "CN",
            "Description",
            "DisplayName",
            "DistinguishedName",
            "Name",
            "ObjectClass",
            "SamAccountName"
        )
    }

    if (-not (Test-Path $ColumnFilePath)) {
        throw "ColumnFile '$ColumnFilePath' does not exist."
    }

    $ext = [IO.Path]::GetExtension($ColumnFilePath).ToLower()

    switch ($ext) {
        ".csv" {
            # Column list from comma-separated text file
            $text = Get-Content -Path $ColumnFilePath -Raw
            $cols = $text -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
            return $cols
        }

        ".ps1" {
            # Column list from PowerShell script defining $columnList
            . $ColumnFilePath
            if ($columnList) {
                return $columnList
            } else {
                throw "ColumnFile '$ColumnFilePath' does not define 'columnList'."
            }
        }

        default {
            throw "Unsupported extension '$ext' for ColumnFile. Use '.csv' or '.ps1'."
        }
    }
}

# --- Main --------------------------------------------------------

try {
    $columnList = Get-ColumnList -ColumnFilePath $ColumnFile

    if (-not $columnList -or $columnList.Count -eq 0) {
        throw "No column names were obtained. Please check the ColumnFile."
    }

    $data = Import-Csv -Path $InFile

    if (-not $data) {
        throw "Input file '$InFile' has no data."
    }

    $allColumns = $data[0].PsObject.Properties.Name

    if ($Exclude) {
        # Exclude mode: keep columns that are NOT listed in columnList
        $validKeep = $allColumns | Where-Object { $_ -notin $columnList }
        if (-not $validKeep -or $validKeep.Count -eq 0) {
            $listed = $columnList -join ", "
            throw "Exclude mode is enabled, but all columns are listed in ColumnFile (nothing to keep). Listed columns: $listed"
        }
        Write-Verbose "Exclude mode: keeping columns NOT listed in the column list."
    } else {
        # Normal mode: keep columns that ARE listed in columnList
        $validKeep = $columnList | Where-Object { $_ -in $allColumns }
        if (-not $validKeep -or $validKeep.Count -eq 0) {
            $available = $allColumns -join ", "
            throw "None of the specified columns were found in input file '$InFile'. Available columns: $available"
        }
        Write-Verbose "Include mode: keeping only columns listed in the column list."
    }

    $data |
        Select-Object $validKeep |
        Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

    Write-Verbose "Completed: '$InFile' -> '$OutFile'"
    Write-Verbose "Kept columns: $($validKeep -join ', ')"
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

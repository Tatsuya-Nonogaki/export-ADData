# Export-ADData

## Overview
`Export-ADData` is a PowerShell script designed to export Active Directory (AD) Users and Groups to CSV files. It allows for flexible export options.

`Import-ADData` is a complementary PowerShell script designed to import AD Users and Groups from CSV files back into Active Directory. Domain base name can be different from that of exported AD. It supports various import options, including handling system objects and creating missing OUs during the import process.

## Features
### Export-ADData
- Export AD Users and Groups to CSV.
- Handle `CN=Users` objects differently by redirecting them to a designated OU.

### Import-ADData
- Import AD Users and Groups from CSV.
- Optionally include system objects during the import.
- Handle `CN=Users` objects by redirecting them to a designated OU.
- Create missing OUs during the import if specified.
- Clear logging of import operations.

## Prerequisites
- PowerShell
- Active Directory Module for Windows PowerShell

## Usage

### Export-ADData

```powershell
.SYNOPSIS
  Exports group and users from Active Directory.

.DESCRIPTION
  Exports group and users from Active Directory to CSV files.
  Version: 0.7.10

.PARAMETER DNPrefix
  (Alias -d) Mandatory. Mutually exclusive with DNPath. 
  Domain component from which you want to retrieve objects. 
  For example: "unit.mydomain.local" which is converted to DistinguishedName(DNPath) "OU=unit,DC=mydomain,DC=local" in the script.

.PARAMETER DCDepth
  Optional. Mutually exclusive with DNPath. Specify the depth count of DC.
  Default is 2.

.PARAMETER DNPath
  (Alias -p) Optional. Mutually exclusive with DNPrefix and DCDepth.
  Specify it in DistinguishedName format.

.PARAMETER OutPath
  (Alias -o) Optional. Folder path where you want to save output CSV files.
  If omitted, a path selection dialog will appear.
```

### Import-ADData

```powershell
.SYNOPSIS
  Imports group and users into Active Directory.

.DESCRIPTION
  Imports group and users into Active Directory from CSV files.
  You can accomplish import of user only, group only, or both at a time.
  Version: 0.7.5

.PARAMETER DNPrefix
  (Alias -d) Mandatory. Mutually exclusive with DNPath. 
  Domain component into which you want to import objects. 
  For example: "unit.mydomain.local" which is converted to DistinguishedName(DNPath) "OU=unit,DC=mydomain,DC=local" internally.
  IMPORTANT: Target DN structure must exist on the destination AD before import.

.PARAMETER DCDepth
  Optional. Mutually exclusive with DNPath. Specify the depth count of DC.
  Default is 2.

.PARAMETER DNPath
  (Alias -p) Optional. Mutually exclusive with DNPrefix and DCDepth.
  Specify it in DistinguishedName format.

.PARAMETER User
  (Alias -u) Operates in user import mode. If -UserFile is specified, this switch is implied and can be omitted.

.PARAMETER UserFile
  (Alias -uf) Optional. Path of input user CSV file. Path selection dialog will ask you if omitted despite -User switch is set.
  Note: If you want to register passwords for users, add a "Password" column to the CSV file and provide passwords in plain text.
  Password is requred to set Enable flag of the account.

.PARAMETER Group
  (Alias -g) Operates in group import mode. If -GroupFile is specified, this switch is implied and can be omitted.

.PARAMETER GroupFile
  (Alias -gf) Optional. Path of input group CSV file. Path selection dialog will ask you if omitted despite -Group switch is set.

.PARAMETER IncludeSystemObject
  Optional. Import also users and groups which are critical system objects. This is usually dangerous and can lead to AD system breakdown.
```

## Examples
### Exporting AD Data
```powershell
# Export AD Users and Groups to CSV files
.\export-ADData.ps1 -DNPath "OU=unit,DC=mydomain,DC=local" -OutPath "C:\ADExport"
```

### Importing AD Data
```powershell
# Import AD Users from CSV excluding system objects
.\import-ADData.ps1 -DNPath "OU=unit,DC=mydomain,DC=local" -UserFile "C:\ADExport\Users_unit_mydomain_local.csv"

# Import AD Users and Groups from CSV including system objects
.\import-ADData.ps1 -DNPath "OU=unit,DC=mydomain,DC=local" -UserFile "C:\ADExport\Users_unit_mydomain_local.csv" -GroupFile "C:\ADExport\Groups_unit_mydomain_local.csv" -IncludeSystemObject
```

## Logging
Import script maintain clear logging of actions performed, including any errors encountered. Logs are saved in the script directory with the name `import-ADData.log`.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Author
Tatsuya Nonogaki

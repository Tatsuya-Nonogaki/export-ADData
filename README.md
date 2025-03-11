# Export-ADData

## Overview
`Export-ADData` is a PowerShell script designed to export Active Directory (AD) Users and Groups to CSV files. It allows for flexible export options.

`Import-ADData` is a complementary PowerShell script designed to import AD Users and Groups from the CSV files back into Active Directory. The destination AD does not need to be the same as the source. Script will automatically convert the paths if you specify a different domain base than the source. Supports creating missing intermediate tier OUs in the destination during import.

The intended usage is to export by specifying the domain basis, so that objects are output without losing their required attributes. When importing, three major strategies are expected;
1. Export specifying "DC=domain,DC=local" and import to "DC=domain,DC=local": It is like backup and restore of AD users/groups.
2. Export specifying "DC=olddomain,DC=local" and import to "DC=newdomain,DC=local": Allocate the users/groups onto a new domain basis, translating the domain naming, respecting hierarchies.
3. Export specifying "DC=domain,DC=local" and import to "OU=osaka,DC=domain,DC=local": Whole migration from the domain basis to a new specific OU, along with all intermediate OUs the users/groups depend on. Secifying "newdomain" is also a viable choice, which is like a move to a different floor of a different building.

## Features
### Export-ADData
- Export AD Users and Groups to a pair of CSV files.

### Import-ADData
- Import AD Users and Groups from CSV files.
- Optionally include system objects during the import, if specified.
- Handle `CN=Users` objects correctly and redirects them to a designated OU when needed.
- Create missing intermediate OUs during the import.
- Clear logging of import operations.
- Option to disable "protection from accidental deletion" for newly created OUs, useful for pre-validation etc.

## Prerequisites
- PowerShell
- Active Directory Module for Windows PowerShell

## Usage

### Export-ADData

```powershell
.SYNOPSIS
  Exports users and groups from Active Directory.

.DESCRIPTION
  Exports users and groups from Active Directory to CSV files.

.PARAMETER DNPath
  (Alias -p) Mandatory. Mutually exclusive with -DNPrefix and -DCDepth. 
  Base of the Domain hierarchy from which you want to retrieve objects. Its 
  argument must be in DistinguishedName form like "DC=mydomain,DC=local" or 
  "OU=sales,DC=mydomain,DC=local". This parameter is much preferable than 
  its alternative -DNPrefix (below) for accuracy.

.PARAMETER DNPrefix
  (Alias -d) Alternative method to -DNPath, and mutually exclusive with it. 
  Its argument must be in dotted format. For example: "unit.mydomain.local" 
  which is converted internally to DistinguishedName(=DNPath) 
  "OU=unit,DC=mydomain,DC=local".

.PARAMETER DCDepth
  Optional. Can be used with -DNPrefix. Mutually exclusive with -DNPath. 
  In calculation of the DNPath, we assume the last 2 elements are DC 
  per default. If it is not what you expect, specify depth count of DC 
  with this. e.g., when -DNPrefix dept.unit.mydomain.local, then
   DCDepth 2: DNPath becomes OU=dept,OU=unit,DC=mydomain,DC=local
   DCDepth 3: DNPath becomes OU=dept,DC=unit,DC=mydomain,DC=local

.PARAMETER OutPath
  (Alias -o) Optional. Folder path where you want to save output CSV files.
  Path selection dialog will prompt you to choose, if omitted.
```

### Import-ADData

```powershell
.SYNOPSIS
  Imports users and groups into Active Directory.

.DESCRIPTION
  Imports users and groups into Active Directory from CSV files.
  You can accomplish import of user only, group only, or both at a time.

.PARAMETER DNPath
  (Alias -p) Mandatory. Mutually exclusive with -DNPrefix and -DCDepth. 
  Base of the Domain hierarchy onto which you want import objects. Its 
  argument must be in DistinguishedName form like "DC=mydomain,DC=local" 
  or "OU=sales,DC=mydomain,DC=local". This parameter is much preferable 
  than its alternative -DNPrefix (below) for accuracy.
  IMPORTANT: The target base DN object, e.g. OU, must exist on the 
  destination AD prior to import.

.PARAMETER DNPrefix
  (Alias -d) Alternative method to -DNPath, and mutually exclusive with it. 
  Its argument must be in dotted format. For example: "unit.mydomain.local" 
  which is converted internally to DistinguishedName(=DNPath) 
  "OU=unit,DC=mydomain,DC=local".

.PARAMETER DCDepth
  Optional. Can be used with -DNPrefix. Mutually exclusive with -DNPath. 
  In calculation of the DNPath, we assume the last 2 elements are DC 
  per default. If it is not what you expect, specify depth count of DC 
  with this. e.g., when -DNPrefix dept.unit.mydomain.local, then 
   DCDepth 2: DNPath becomes OU=dept,OU=unit,DC=mydomain,DC=local
   DCDepth 3: DNPath becomes OU=dept,DC=unit,DC=mydomain,DC=local

.PARAMETER User
  (Alias -u) Operates in user import mode. If -UserFile (below) is 
  specified, this switch is implied and can be omitted.

.PARAMETER UserFile
  (Alias -uf) Optional. Path of input user CSV file. File selection 
  dialog will prompt you to choose, if omitted despite -User switch is set.
  Note: If you want to register password to any users, make a copy of 
  the whole CSV file, add "Password" column to it, which is missing from 
  the original, and put password in plain text. Password is required to 
  restore the "Enable" flag of the account.

.PARAMETER Group
  (Alias -g) Operates in group import mode. If -GroupFile (below) is 
  specified, this switch is implied and can be omitted.

.PARAMETER GroupFile
  (Alias -gf) Optional. Path of input group CSV file. File selection 
  dialog will prompt you to choose, if omitted despite -Group switch 
  is set.

.PARAMETER IncludeSystemObject
  Optional. Import also users and groups which are critical system object, 
  such as: Administrator(s), Domain Admins and COMPUTER$ and trusted 
  DOMAIN$. This is usually dangerous and leads to AD system breakdown.

.PARAMETER NewUPNSuffix
  Optional. New UserPrincipalName suffix to use for conversion. If not 
  provided, script will convert UPN based on DNPath. It is usually not 
  necessary to specify.

.PARAMETER NoProtectNewOU
  Optional. If specified, newly created OUs will not be protected from 
  accidental deletion. By default, OUs will be created in protected state.
```

## Examples
### Exporting AD Data
```powershell
# Export AD Users and Groups from the Domain basis to CSV files in "C:\ADExport"
.\export-ADData.ps1 -DNPath "DC=mydomain,DC=local" -OutPath "C:\ADExport"

# (Not recommended) Export AD Users and Groups, specifying a specific hierarchy base.
.\export-ADData.ps1 -DNPath "OU=unit,DC=mydomain,DC=local" -OutPath "C:\ADExport"
```

### Importing AD Data
```powershell
# Import AD Groups from CSV to a new Domain basis, excluding system objects
.\import-ADData.ps1 -DNPath "DC=newdomain,DC=local" -GroupFile "C:\ADExport\Groups_mydomain_local.csv"

# Import AD Users from CSV to an OU on a Domain. A file selection dialog will pop-up to let you choose CSV.
.\import-ADData.ps1 -DNPath "OU=unit,DC=newdomain,DC=local" -User

# Import AD Users and Groups at a time. Internally, users are processed after the whole groups, but this 
is not recommended because of potential massive errors due to group/user to groups membership dependency 
violation when any of groups were not successfully created.
.\import-ADData.ps1 -DNPath "DC=newdomain,DC=local" -UserFile "C:\ADExport\Users_mydomain_local.csv" -GroupFile "C:\ADExport\Groups_mydomain_local.csv"
```

## Logging
Import script maintains clear logging of actions performed, including any errors encountered. Logs are saved in the script directory with the name `import-ADData.log`.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Author
Tatsuya Nonogaki

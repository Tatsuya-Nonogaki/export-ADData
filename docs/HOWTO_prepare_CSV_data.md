# [Procedures to Export and Edit CSV Files for Successful Imports](https://github.com/Tatsuya-Nonogaki/export-ADData/docs/HOWTO_prepare_CSV_data.md)

---

## Preparation Phase

- Export the source Groups and Users from AD to CSV using `export-ADData.ps1`. At this time, system users and groups are unnecessary, except for the most special cases, so be sure to use the `-ExcludeSystemObject` option.

- Similarly, export from the import target AD using `-ExcludeSystemObject`. Even if your intended import target is a branch OU, always specify the base domain in `-DNPath` during export.

- All CSV and TXT files should use UTF-8 encoding. Do not use local encodings such as ShiftJIS or CP932.

- Check for collisions between the SamAccountName of Groups and Users on both sides. If any are found, decide on a policy for renaming or deletion.

---

## Main Procedure

### Basic Intermediate File Flow

📝 Describing mostly for Users as an example, but applies to both Groups and Users.

1. **Users_domain_local-nosys.csv (Groups_domain_local-nosys.csv)**  
   The original data exported from `export-ADData.ps1` with system objects excluded.

2. **Users_domain_local-nosys.xlsx (Groups_domain_local-nosys.xlsx)**  
   Convert to Excel for further operations. Identify and highlight columns unnecessary for import by utilizing conditional formatting, etc—these are not harmful for `import-ADData.ps1` but are cumbersome for editing.

   - For Groups (save if you want as i.e., headers-slim-Groups.csv; for Excel processing, local encoding like ShiftJIS may be appropriate):  
     **Minimal**  
     `MemberOf,CN,Description,DisplayName,DistinguishedName,GroupCategory,GroupScope,groupType,HomePage,isCriticalSystemObject,ManagedBy,Name,ObjectCategory,ObjectClass,SamAccountName`  

     **Note:** Some columns e.g., DisplayName, HomePage, ObjectCategory, CN are not used in `import-ADData.ps1` for now. But we recommend to keep these for your reference or future utilization.

   - For Users (i.e., headers-slim-Users.csv):  
     **Minimal**  
     `MemberOf,Manager,CanonicalName,City,CN,codePage,Company,Country,countryCode,Department,Description,DisplayName,DistinguishedName,Division,EmailAddress,EmployeeID,EmployeeNumber,Enabled,Fax,GivenName,HomeDirectory,HomeDrive,HomePage,HomePhone,Initials,isCriticalSystemObject,MobilePhone,Name,ObjectCategory,ObjectClass,Office,OfficePhone,Organization,OtherName,PasswordNeverExpires,POBox,PostalCode,PrimaryGroup,ProfilePath,SamAccountName,sAMAccountType,ScriptPath,State,StreetAddress,Surname,Title,userAccountControl,UserPrincipalName`  

     📝 **Note:** Some columns e.g., CanonicalName, CN, codePage, HomePage, Initials, Organization, PrimaryGroup, sAMAccountType are not used in `import-ADData.ps1` for now. But we recommend to keep these for your reference or future utilization.

     📝 **Note:** Add `"Password"` column if you need to register password for any user. (See site README or import-ADData.ps1 help.) Existence of this column does no harm because `import-ADData.ps1` ignores each Password field if it is blank.

     📝 **Note:** You may also add a `"ChangePasswordAtLogon"` column to the user CSV to control whether users must change their password at next logon. Acceptable values are `TRUE`, `YES`, or `1` to enable, and `FALSE`, `NO`, or `0` to disable. This column takes precedence over the `userAccountControl` property for this setting. To activate this feature, you may have to use the `"Password"` column together with `"ChangePasswordAtLogon"`. For more details, see the README and `import-ADData.ps1` help.

3. **Users_domain_local-slim.xlsx (Groups_domain_local-slim.xlsx)**  
   Save this file after removing unnecessary columns.

4. **Users_domain_local-slim.csv (Groups_domain_local-slim.csv)**  
   Save the previous Excel file as CSV (UTF-8).

5. **Users_domain_local-slim-mod.csv (Groups_domain_local-slim-mod.csv)**  
   If you need to delete certain groups or users, create a regex file (e.g., `exclude-users-regex.txt`) containing patterns to match SamAccountName, Name, or CN for exclusion. (If you only have a few entries to remove, manual deletion is fine. However, this method will also save you when you need to re-export the original data later to start over.):  
   ```
   ,*alpha*,
   ,*foxtrot*,
   ```
   Then run (if you are using Linux):  
   ```bash
   grep -v -f exclude-users-regex.txt Users_domain_local-slim.csv > Users_domain_local-slim-mod.csv
   ```
   This produces a "mod" CSV with the specified entries excluded.  
   For Users, this file is the final form for use in import.

6. **Users_domain_local-slim-mod.xlsx (Groups_domain_local-slim-mod.xlsx)**  
   Save as Excel.  
   For groups, to minimize race conditions due to dependencies among groups during import, sort the file in Excel and save. (Recommended sort condition: primary:SamAccountName secondary:DistinguishedName)

7. **Groups_domain_local-slim-mod.csv**  
   For groups, export the edited Excel file back to CSV (UTF-8) as the final form.

---

# [Procedures to Export and Edit CSV Files for Successful Imports](https://github.com/Tatsuya-Nonogaki/export-ADData/docs/HOWTO_prepare_CSV_data.md)

---

## Preparation Phase

- Export the source Groups and Users from AD to CSV using `export-ADData.ps1`. At this time, system users and groups are unnecessary, except for the most special cases, so be sure to use the `-ExcludeSystemObject` (`-nosys`) option.

- Similarly, export from the import target AD using `-ExcludeSystemObject`. Even if your intended import target is a branch OU, always specify the base domain in `-DNPath` during export.

- All CSV and TXT files should use UTF-8 encoding. Do not use local encodings such as ShiftJIS or CP932.

- Check for collisions between the SamAccountName of Groups and Users on both sides. If any are found, decide on a policy for renaming or deletion.

---

## Main Procedure

### Basic Intermediate File Flow

📝 Describing mostly for Users as an example, but applies to both Groups and Users.

1. **Users_domain_local-nosys.csv (Groups_domain_local-nosys.csv)**  
   The original data exported from `export-ADData.ps1` with system objects excluded.

2. **Remove unnecessary columns for import**

   Although having extra columns in the CSV does not break `import-ADData.ps1`, removing columns that are not used for import will make later editing, checking, and troubleshooting much easier.

   **Minimal column sets**

   - For Groups:  

     `MemberOf,CN,Description,DisplayName,DistinguishedName,GroupCategory,GroupScope,groupType,HomePage,isCriticalSystemObject,ManagedBy,Name,ObjectCategory,ObjectClass,SamAccountName`  

     📝 **Note:**
     - Some columns such as `DisplayName`, `HomePage`, `ObjectCategory`, `CN` are not currently used by `import-ADData.ps1`. However, they can still be useful for reference during your work, or for future extensions.
     - **GroupCategory / GroupScope override:**  
       If you need to change a group's category or scope, prefer editing the dedicated columns `GroupCategory` and `GroupScope` rather than recalculating the `groupType` integer, even though `groupType` is originally the primary data source.

       - `GroupCategory`: `"Security"` or `"Distribution"`
       - `GroupScope`: `"Global"`, `"DomainLocal"`, or `"Universal"`

       Dedicated columns are evaluated first (per-property). If a dedicated value is present but non-blank and invalid, the group will be skipped during import.
       - In general, it is recommended not to modify `groupType` unless you know exactly what you are doing. Use the dedicated columns for safe edits.

       For full details, see the repository [README](../README.md) and `import-ADData.ps1` help.

   - For Users:  

     `MemberOf,Manager,CannotChangePassword,CanonicalName,City,CN,codePage,Company,Country,countryCode,Department,Description,DisplayName,DistinguishedName,Division,EmailAddress,EmployeeID,EmployeeNumber,Enabled,Fax,GivenName,HomeDirectory,HomeDrive,HomePage,HomePhone,Initials,isCriticalSystemObject,MobilePhone,Name,ObjectCategory,ObjectClass,Office,OfficePhone,Organization,OtherName,PasswordNeverExpires,POBox,PostalCode,PrimaryGroup,ProfilePath,SamAccountName,sAMAccountType,ScriptPath,State,StreetAddress,Surname,Title,userAccountControl,UserPrincipalName`  

     📝 **Note:**
     - Some columns such as `CanonicalName`, `CN`, `codePage`, `HomePage`, `Initials`, `Organization`, `PrimaryGroup`, `sAMAccountType` are not currently used by `import-ADData.ps1`. But it is recommended to keep them for reference or future utilization.

     - If you want to assign passwords to selected users, add a `"Password"` column. (See the repository README and `import-ADData.ps1` help for details.) This column is safe to add: if a row’s `Password` field is empty, `import-ADData.ps1` simply ignores it.

     - **Dedicated columns for `userAccountControl`-related settings (CCP/CPL/PNE):**  
       Some password-policy-related settings are normally encoded in `userAccountControl`, but `import-ADData.ps1` supports dedicated per-property columns for safer editing and import.

       - Recognized columns:  
         - `"CannotChangePassword"` (CCP): included by `export-ADData.ps1` by default
         - `"ChangePasswordAtLogon"` (CPL): add this column if needed
         - `"PasswordNeverExpires"` (PNE): included by `export-ADData.ps1` by default
       - Acceptable boolean values: `TRUE`, `YES`, or `1` (case-insensitive) to enable; `FALSE`, `NO`, or `0` to disable.
       - If a column exists and contains a valid boolean value, it takes precedence over the corresponding `userAccountControl` bit (when applicable).
       - Fallback behavior:
         - CPL/PNE may fall back to the corresponding `userAccountControl` bit, but only introduces the **TRUE (bit set)** case.
         - CCP does **not** fall back to `userAccountControl` bit `0x40`.
       - CCP is applied best-effort only when CCP=TRUE is requested; CCP=FALSE is intentionally not forced so destination ACLs/delegation defaults are respected.
       - These three settings (CCP/CPL/PNE) can contradict each other, so `import-ADData.ps1` evaluates them with a conflict-resolution policy to avoid unsafe combinations (e.g., `ChangePasswordAtLogon` requests an immediate password change, while `CannotChangePassword` denies password changes—both cannot be effective at the same time).  
         Conflict-resolution priority: **CCP > CPL > PNE** (contradictory TRUE combinations may be skipped).

       For full details (including the normalization and conflict-resolution policies, plus the PNE safety check), see the repository [README](../README.md) and `import-ADData.ps1` help.  

   You can remove columns in either of the following ways:  

   - **Manual method (Excel)**  
     Load the CSV into Excel (e.g., save as `Users_domain_local-nosys.xlsx` or `Groups_domain_local-nosys.xlsx`), then manually delete columns that you do not need for import.

   - **Automatic method (filter-csv-columns.ps1)**  
     You can use the helper script [utils/filter-csv-columns/filter-csv-columns.ps1](../utils/filter-csv-columns/filter-csv-columns.ps1) to trim your CSVs automatically, as described below:  

     Save the minimal column sets strings above (including commas) in files (UTF-8, CRLF):  
       - `column_list-Groups.csv`
       - `column_list-Users.csv`

     Then run the following in a PowerShell console:

     ```powershell
     .\filter-csv-columns.ps1 -InFile .\Groups_domain_local-nosys.csv -OutFile .\Groups_domain_local-slim.csv -ColumnFile .\column_list-Groups.csv
     .\filter-csv-columns.ps1 -InFile .\Users_domain_local-nosys.csv -OutFile .\Users_domain_local-slim.csv -ColumnFile .\column_list-Users.csv
     ```

     That’s all. Just review the output files briefly to confirm the columns look as expected.  
     For more details, see the help and comments of [filter-csv-columns.ps1](../utils/filter-csv-columns/filter-csv-columns.ps1).

   - **Bulk column removal with an Excel macro (DeleteExtraColumns.bas)**  
     The macro [utils/filter-csv-columns/DeleteExtraColumns.bas](../utils/filter-csv-columns/DeleteExtraColumns.bas) can be imported into an Excel workbook and run to create an additional worksheet where unnecessary columns have been removed.  
     The original worksheet will NOT be modified, but as a precaution it is recommended to run the macro on a copy of your workbook or keep a backup before applying it.  
     For detailed usage instructions, see the comments inside `DeleteExtraColumns.bas`.

3. **Users_domain_local-slim.xlsx (Groups_domain_local-slim.xlsx)**  
   Save this file after removing unnecessary columns.  
   If you used `filter-csv-columns.ps1` in step 2 to generate `*-slim.csv`, you may skip this additional Excel step unless you need Excel specifically for manual editing or review.

4. **Users_domain_local-slim.csv (Groups_domain_local-slim.csv)**  
   Save the previous Excel file as CSV (UTF-8).  
   If you used `filter-csv-columns.ps1` in step 2, this `*-slim.csv` file has already been created, so no further conversion is required here.

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

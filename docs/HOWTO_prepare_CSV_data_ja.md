# [上手にインポートするための エクスポートとCSVファイルの準備のしかた](https://github.com/Tatsuya-Nonogaki/export-ADData/docs/HOWTO_prepare_CSV_data_ja.md)

---

## 準備フェーズ

- エクスポート元ADのグループおよびユーザーを、`export-ADData.ps1` を使用してCSVにエクスポートします。この際、かなり特殊な場合を除きシステムユーザーおよびグループは不要なので、必ず `-ExcludeSystemObject`(`-nosys`) オプションを付けてください。

- インポート先ADについても同様に `-ExcludeSystemObject` を付けてエクスポートします。インポート先が枝OUであっても、エクスポート時の `-DNPath` には必ずそのADの基底ドメインを指定してください。

- すべてのCSVおよびTXTファイルはUTF-8エンコーディングで保存してください。ShiftJISやCP932などのローカルエンコーディングは避けるべきです。

- グループとユーザーのSamAccountNameが、エクスポート元・インポート先の双方で重複していないかを確認します。もし重複があれば、リネームや削除など方針を決めておきます。

---

## メイン手順

### 基本的な中間ファイル処理の流れ

📝 主にユーザーを例に説明していますが、グループも同様です

1. **Users_domain_local-nosys.csv（Groups_domain_local-nosys.csv）**  
   `export-ADData.ps1` でシステムオブジェクトを除外してエクスポート。

2. インポートに不要なカラムを削除

   インポートに使用されない列を含んでいても `import-ADData.ps1` の動作に影響はありませんが、整理しておいたほうがこの後の編集やチェックがスムーズです。

   **必要最小限のカラム**
   
   - グループデータ：
  
     `MemberOf,CN,Description,DisplayName,DistinguishedName,GroupCategory,GroupScope,groupType,HomePage,isCriticalSystemObject,ManagedBy,Name,ObjectCategory,ObjectClass,SamAccountName`  
  
     📝 **注:** DisplayName, HomePage, ObjectCategory, CN など一部の列は現状 `import-ADData.ps1` では使用されませんが、作業中に参考にしたり将来の活用に備えて、保持しておくことをお勧めします。
  
   - ユーザーデータ：  
     `MemberOf,Manager,CannotChangePassword,CanonicalName,City,CN,codePage,Company,Country,countryCode,Department,Description,DisplayName,DistinguishedName,Division,EmailAddress,EmployeeID,EmployeeNumber,Enabled,Fax,GivenName,HomeDirectory,HomeDrive,HomePage,HomePhone,Initials,isCriticalSystemObject,MobilePhone,Name,ObjectCategory,ObjectClass,Office,OfficePhone,Organization,OtherName,PasswordNeverExpires,POBox,PostalCode,PrimaryGroup,ProfilePath,SamAccountName,sAMAccountType,ScriptPath,State,StreetAddress,Surname,Title,userAccountControl,UserPrincipalName`  

     📝 **注:**
     - CanonicalName, CN, codePage, HomePage, Initials, Organization, PrimaryGroup, sAMAccountType など一部の列は現状 `import-ADData.ps1` では使用されませんが、作業中に参考にしたり将来の活用に備えて、保持しておくことをお勧めします。

     - 任意のユーザーにパスワードを登録したい場合は`"Password"`列を追加してください。この列は、空欄の場合には `import-ADData.ps1` によって無視されるので、追加しても害はありません。詳しくは [README](../README.md) や`import-ADData.ps1`のヘルプを参照してください。

     - **`userAccountControl`関連の専用カラムについて (CCP/CPL/PNE):**  
       通常は `userAccountControl` にビットとして格納されている属性のうち、いくつかは、CSVの専用列によって設定することも可能です。これにより、`userAccountControl`のビット値を再計算するという面倒でミスをはらむ作業を避けられます。

       - 認識される専用カラムには以下のものがあります:  
         - `"CannotChangePassword"` (CCP): `export-ADData.ps1`の出力に既定で存在
         - `"ChangePasswordAtLogon"` (CPL): 使用する場合は要追加
         - `"PasswordNeverExpires"` (PNE): `export-ADData.ps1`の出力に既定で存在
       - 設定可能な値: 有効化なら `TRUE`, `YES`, `1` のいずれか (大文字小文字区別なし)、無効化なら `FALSE`, `NO`, `0`。
       - カラムが存在し真偽値として解釈できた場合は、対応する `userAccountControl` のビット値よりも優先されます (ただし例外あり)。
       - フォールバックの挙動:
         - CPL/PNE は、専用カラム値が採用できない場合、対応する `userAccountControl` ビットへファールバックします。ただし、**TRUE (ビットが立っている)** の場合に限られます。
         - CCP は `userAccountControl` の `0x40` ビットへのフォールバックはしません。
       - CCP は CCP=TRUE の場合のみ反映 (インポート先ADのACLとの兼ね合いでベストエフォートとなる)。CCP=FALSE は、インポート先ADのACLや委任設定によって割り当てられる既定値を尊重するため、敢えて反映しないようにしています。
       - これら3つ (CCP/CPL/PNE) は互いに矛盾・衝突し得る関係にあります。例えば、`ChangePasswordAtLogon` は「今すぐにパスワードを変更せよ」である一方、`CannotChangePassword` はパスワードの変更を禁止しており、同時に設定するわけには行きません。そのため `import-ADData.ps1` は、あってはならない組み合わせにならないよう、コンフリクト回避評価を行います。  
         コンフリクト回避評価での優先順位: **CCP > CPL > PNE**

       詳しくは、当レポジトリの [README](../README.md) や `import-ADData.ps1` のヘルプを参照してください。これらの値の普遍化、衝突回避ポリシー、PNE 設定時の安全対策などについても述べられています。

   不要な列を削除するには、いくつか方法があります:  

   - **手動で削除 (Excel)**  
     一旦 Excel に (例えば、`Users_domain_local-nosys.xlsx` と `Groups_domain_local-nosys.xlsx`) 読み込ませて、不要な列を手動で削除。

   - **スクリプトで一括削除 (filter-csv-columns.ps1)**  
     補助スクリプト [utils/filter-csv-columns/filter-csv-columns.ps1](../utils/filter-csv-columns/filter-csv-columns.ps1) を使えば、以下のようにして、自動で削除することができます:  

     前述の「必要最小限のカラム」の文字列を (カンマも含めて) ファイルに保存します (UTF-8, CRLF):  
       - `column_list-Groups.csv`
       - `column_list-Users.csv`

     そして、PowerShellコンソール上で下記それぞれを実行します:

     ```powershell
     .\filter-csv-columns.ps1 -InFile .\Groups_domain_local-nosys.csv -OutFile .\Groups_domain_local-slim.csv -ColumnFile .\column_list-Groups.csv
     .\filter-csv-columns.ps1 -InFile .\Users_domain_local-nosys.csv -OutFile .\Users_domain_local-slim.csv -ColumnFile .\column_list-Users.csv
     ```

     これだけです! 念のため、出力ファイルをチェックしてくださいね。詳しくは [filter-csv-columns.ps1](../utils/filter-csv-columns/filter-csv-columns.ps1) のヘルプやコメントを参照してください。

   - **Excelマクロで一括削除 (DeleteExtraColumns.bas)**  
     [utils/filter-csv-columns/DeleteExtraColumns.bas](../utils/filter-csv-columns/DeleteExtraColumns.bas) は、Excelブックにインポートして実行することで、不要な列の除かれたデータを追加のワークシートとして生成することができるマクロです。  
     もとのワークシートは改変されませんが、念のため、複製したワークブック上で実行するか、バックアップを採ってから適用することをお勧めします。  
     詳しい使い方は `DeleteExtraColumns.bas` 内のコメントを参照してください。

3. **Users_domain_local-slim.xlsx（Groups_domain_local-slim.xlsx）**  
   不要な列を除去した後にこのファイル名で保存します。ただし `filter-csv-columns.ps1` で処理した場合は必要ありません。

4. **Users_domain_local-slim.csv（Groups_domain_local-slim.csv）**  
   上記ExcelファイルをCSV（UTF-8）として"名前を付けて保存"します。(`filter-csv-columns.ps1` で処理した場合は既にこのファイルができているはずです)

5. **Users_domain_local-slim-mod.csv（Groups_domain_local-slim-mod.csv）**  
   特定のグループやユーザーを除外したい場合は、除外対象のSamAccountNameやName、CNに合致するパターンを記載した正規表現ファイル（例: `exclude-users-regex.txt`）を作成します。少数であれば手作業で削除しても構いませんが、作業の途中で変更が入ったり、元データの採りなおしから始めなくてはならなくなった際に役立ちます：  
   ```
   ,*alpha*,
   ,*foxtrot*,
   ```
   その後（Linuxの場合の例）：  
   ```bash
   grep -v -f exclude-users-regex.txt Users_domain_local-slim.csv > Users_domain_local-slim-mod.csv
   ```
   これにより、指定したエントリを除外した"mod" CSVが作成されます。  
   ユーザーの場合、このファイルがインポート用の最終形になります。

6. **Users_domain_local-slim-mod.xlsx（Groups_domain_local-slim-mod.xlsx）**  
   Excel形式で保存します。  
   グループの場合、インポート時のグループどうしの依存関係によるレースコンディションを減らすため、一旦Excel化して、ソートすることをお勧めします。（推奨ソート条件：第1キー SamAccountName、第2キー DistinguishedName）。

7. **Groups_domain_local-slim-mod.csv**  
   グループの場合、編集済みExcelファイルをCSV（UTF-8）で再エクスポートして最終形とします。

---

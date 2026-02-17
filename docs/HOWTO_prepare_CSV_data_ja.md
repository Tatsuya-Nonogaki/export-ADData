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

   インポートに使わない列を含んでいても `import-ADData.ps1` の動作に影響はありませんが、整理しておいたほうがこの後の編集やチェックがスムーズです。

   **必要最小限のカラム**
   
   - グループデータ：
  
     `MemberOf,CN,Description,DisplayName,DistinguishedName,GroupCategory,GroupScope,groupType,HomePage,isCriticalSystemObject,ManagedBy,Name,ObjectCategory,ObjectClass,SamAccountName`  
  
     📝 **注:** DisplayName, HomePage, ObjectCategory, CN など一部の列は現状 `import-ADData.ps1` では使用されませんが、作業中に参考にしたり将来の活用に備えて、保持しておくことをお勧めします。
  
   - ユーザーデータ：  
     `MemberOf,Manager,CanonicalName,City,CN,codePage,Company,Country,countryCode,Department,Description,DisplayName,DistinguishedName,Division,EmailAddress,EmployeeID,EmployeeNumber,Enabled,Fax,GivenName,HomeDirectory,HomeDrive,HomePage,HomePhone,Initials,isCriticalSystemObject,MobilePhone,Name,ObjectCategory,ObjectClass,Office,OfficePhone,Organization,OtherName,PasswordNeverExpires,POBox,PostalCode,PrimaryGroup,ProfilePath,SamAccountName,sAMAccountType,ScriptPath,State,StreetAddress,Surname,Title,userAccountControl,UserPrincipalName`  

     📝 **注:**
     - CanonicalName, CN, codePage, HomePage, Initials, Organization, PrimaryGroup, sAMAccountType など一部の列は現状 `import-ADData.ps1` では使用されませんが、作業中に参考にしたり将来の活用に備えて、保持しておくことをお勧めします。

     - 任意のユーザーにパスワードを登録したい場合は`"Password"`列を追加してください（詳細はREADMEや import-ADData.ps1 のヘルプ参照）。この列は、空欄の場合には `import-ADData.ps1` は無視するので、追加しても害はありません。詳しくはREADMEや`import-ADData.ps1`のヘルプを参照してください。

     - ユーザーに次回ログオン時のパスワード変更を強制するかどうかを制御する`"ChangePasswordAtLogon"`列を追加することも可能です。値が`TRUE`/`YES`/`1`の場合は有効に、`FALSE`/`NO`/`0`の場合は無効になります。この列の存在は、`userAccountControl`に含まれるビットより優先されます。場合によっては`"Password"`列との併用が必要となります。詳しくはREADMEや`import-ADData.ps1`のヘルプを参照してください。

   不要な列を削除するには、一旦 Excel に (例えば、Users_domain_local-nosys.xlsx と Groups_domain_local-nosys.xlsx として) 読み込ませて手動で削除してもいいですが、CSVのままスクリプトで一括処理する手があります。  
   [utilsフォルダにある **filter-csv-columns.ps1**](../utils/filter-csv-columns/filter-csv-columns.ps1) が活用できます。  
  
   **使用例**  
   先に、前述の最小カラム名一覧を `column_list-Groups.csv`, `column_list-Users.csv` (UTF-8, CRLF) でファイル化しておきます。そして、PowerShellコンソール上で下記それぞれを実行します:
   ```powershell
   .\filter-csv-columns.ps1 -InFile .\Groups_domain_local-nosys.csv -OutFile .\Groups_domain_local-slim.csv -ColumnFile .\column_list-Groups.csv
   .\filter-csv-columns.ps1 -InFile .\Users_domain_local-nosys.csv -OutFile .\Users_domain_local-slim.csv -ColumnFile .\column_list-Users.csv
   ```
   これだけです! 念のため、出力ファイルをチェックしてくださいね。詳しくは [filter-csv-columns.ps1](../utils/filter-csv-columns/filter-csv-columns.ps1) のヘルプヘッダを参照してください。

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

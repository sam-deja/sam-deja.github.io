---
title: "PowerShell for Offensive Security: Loading, Detection, and Evasion"
date: 2025-11-06 09:00:00 -0700
categories: [Security, Windows]
tags: [powershell, amsi, evasion, logging, defenders, windows]
description: How PowerShell works on modern Windows, what built-in defenses exist, and practical approaches for running, modifying, and avoiding noisy detections—so you can adapt to your target environment.
---

In offensive security we rely on two major tool types. For enumeration, we use PowerShell. For almost everything else we lean on .NET or C. This article explains how PowerShell works in modern Windows environments, what built-in defenses exist, and practical approaches for running, modifying, and evading detections when needed. I will share the methods and rationale I use so you can adapt them to your target environment.

## Why PowerShell

PowerShell is a cross-platform task-automation solution made up of a command-line shell, a scripting language, and a configuration-management framework. The key reason we use PowerShell is simple: like Bash or JavaScript, it ships by default on modern Windows operating systems. Since Windows Vista and Windows Server 2012, PowerShell has been present on every modern Windows machine.

There are two flavors to be aware of. What Microsoft now calls **PowerShell** is the cross-platform PowerShell Core, which is not the default on most Windows installations. What ships by default is **Windows PowerShell**. The tools we use in class are largely based on Windows PowerShell.

## PowerShell is not PowerShell.exe

PowerShell is a .NET assembly (`System.Management.Automation`). `powershell.exe` is just one host—the blue console you see. Attackers and tools use many other hosts: custom runspaces, alternative hosts, embedded uses, and more. Blocking `powershell.exe` alone does not stop PowerShell usage.

## Loading PowerShell Code: Scripts, Modules, and Remote Loading

There are a few basic operations you should know when running PowerShell in the field:

- Load a script from disk via dot-sourcing: `.` **space** `<path-to-script>`.
- Import modules with `Import-Module`. Modules may be `.psd1`, `.psm1`, and other formats.
- Once a module is loaded, list commands with `Get-Command -Module <ModuleName>`.

To load and run PowerShell remotely or in memory, common patterns include downloading a script as a string and executing it with `Invoke-Expression`. These download-execute techniques have been widely used since about 2011 and were so common they drove Microsoft to introduce the Antimalware Scan Interface (AMSI) in Windows PowerShell 5.1 in 2016.

## Windows PowerShell 5.1: Security Enhancements

From 2016 onward, Windows PowerShell gained several defensive features. The most relevant ones are:

- **System-wide transcription:** Logs commands and output regardless of host. Transcripts are written as clear-text files and are not protected, so they can leak secrets if transcription is enabled and the transcript directory is writable or accessible.
- **Script block logging:** Logs executed script blocks. There are two relevant event types: 4104 and 4103. Script block logging can be noisy but useful.
- **Antimalware Scan Interface (AMSI):** Before executing script content, AMSI passes that content to the registered antivirus on the machine. If the antivirus has a matching signature, the script may be detected.
- **Constrained Language Mode (CLM):** When PowerShell determines it cannot execute normally due to app control policies, it may drop into CLM. CLM severely restricts what scripts can do. It is used in conjunction with AppLocker and Windows Defender Application Control. Only a few Microsoft modules, such as the `ActiveDirectory` module, are fully functional under CLM.

There are four language modes: `NoLanguage` (used by JEA), `ConstrainedLanguage`, `RestrictedLanguage`, and `FullLanguage`. Depending on policies, the environment may restrict PowerShell to one of these modes.

## Execution Policy Is Not a Security Control

Execution policy is not an effective security control. There are numerous ways to bypass or evade execution policy, so do not rely on it as a defense.

## Is Offensive PowerShell Dead?

No. The effectiveness of offensive PowerShell depends on the target organization and how mature their security posture is. Tools fall in and out of favor, but that does not mean they are useless. If you can customize code or if your target has weaker or misconfigured detections, PowerShell remains a practical option. History shows this pattern: popularity shifts between .NET, PowerShell, and C#-based tooling as defenders and attackers adapt.

Decide your tools based on the target, not on what is fashionable.

## Typical Detection and Evasion Layers

When working against modern Windows endpoints, you will encounter three primary defensive layers that matter for PowerShell:

1. System-wide transcription and host-level logging mechanisms.  
2. Script block logging and other event logging.  
3. AMSI hooking into registered antivirus engines.

There are several classes of bypass strategies:

- Run in a custom host or use a non-`powershell.exe` entry point so that simple process-based blocks are ineffective.
- Hook or modify .NET assemblies at runtime to neutralize AMSI, transcription, or script block logging.
- Obfuscate code or change specific strings and tokens that signatures detect.
- Remove or replace detected functionality within complex tools to avoid signature matches.

## InvisiShell: Practical Example of a Runtime Evasion

One tool we use in class is a slightly modified version of InvisiShell. InvisiShell makes specific hooks into two .NET assemblies: the PowerShell assembly and `System.Core`. These hooks can disable system-wide transcription, AMSI, and script block logging in the running session.

How to run it depends on privileges. If you have administrator privileges, run the admin batch file. If you do not have administrator privileges, run the non-admin batch file. Either way, the result is a PowerShell session where the targeted logging and AMSI protections are neutralized.

## Disk-Based Scripts: Obfuscation and Targeted Modification

If you insist on loading scripts from disk, there are several approaches to reduce detection:

- Obfuscate the entire script using tools like `Invoke-Obfuscation` or custom obfuscators. This is a blunt approach and can work but may be heavy-handed.
- Use a modular, surgical approach. Identify the exact strings or bytes that trigger signatures and obfuscate only those parts. Tools like **MZTrigger** and **DefenderCheck** help with this workflow.
- Modify scripts to remove functionality you do not need. Many large tools include optional features that introduce binaries or behaviors that antivirus flags. Removing those parts can make the tool undetected for your purposes.

**Workflow I recommend:**

1. Scan the script with DefenderCheck or MZTrigger to get detection points.  
2. Use helper scripts like **ByteToLineNumber** to map detected byte offsets to actual lines in the script.  
3. Identify the specific token, string, or code fragment responsible for the detection.  
4. Obfuscate or modify only that fragment and re-scan. Repeat until no detections are reported by your scanner.

*Example:* A simple reverse TCP script I wrote was flagged because of the literal string `"Net.Sockets"`. Reversing that string or otherwise hiding it removed the detection. That is typical: targeted changes are often enough.

## Modifying Tools to Remove Detected Functionality

Tools such as **PowerUp** or **Invoke-Mimikatz** offer many capabilities. Sometimes the simplest path is to remove the particular functionality that triggers detection rather than trying to evade signatures that target a full-featured tool.

For example, PowerUp includes an option to drop a binary into a service binary as part of a local privilege-escalation check. That binary drop is commonly detected. If you remove that specific portion of the script, the remaining functionality of PowerUp will often be enough for your measurements and will no longer trigger detection.

## Testing and Expectations

All tools and modifications must be tested against up-to-date detection engines. The versions I share and the techniques discussed were validated against the November 2024 Windows Defender signatures. Because many detections are signature-based, they can change over time. Expect that a drop-in tool you download months later might be detected. If that happens, apply the same methodology: scan, identify the bytes or tokens causing detection, and change them.

Some scripts, like `Invoke-Mimikatz`, are heavily signatured and require much more effort to obfuscate reliably. In class we rarely use heavily signatured scripts except for demonstration. For practical engagements, choose tools and approaches that match your objectives and the maturity of the target.


## Practical Recommendations

- Understand the host you are executing on. Blocking `powershell.exe` is insufficient. Consider how PowerShell is loaded and which host is being used.  
- Prioritize modular obfuscation. Identify the specific strings or code that trigger detection and change those rather than obfuscating everything blindly.  
- Use runtime tools like InvisiShell when you need to neutralize AMSI or script logging in a session, but understand the privilege requirements and forensic implications.  
- Remove unnecessary functionality from large toolkits to avoid signatures tied to optional features such as binary drops.  
- Always test against a current Defender or antivirus baseline. Signatures change. Make scanning and iterative testing part of your workflow.  
- Do not rely on execution policy as a defense. Treat it as a convenience feature, not a control.

## Closing Thoughts

PowerShell remains a powerful and practical tool for enumeration and offensive tasks. Modern Windows defenses like AMSI, script block logging, system-wide transcription, and constrained language mode complicate straightforward attacks, but they do not eliminate PowerShell from the adversary toolbox. With targeted obfuscation, selective modification of tool code, and runtime techniques like InvisiShell, you can adapt tools to the target environment. Choose your approach based on the maturity of the target defenses and your specific objectives.


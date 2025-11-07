---

title: "PowerShell for Offensive Security: Loading, Detection, and Evasion"
date: 2025-11-06 09:00 -0700
categories: [Security, Windows]
tags: [PowerShell, Offensive Security, Windows, AMSI, ETW, CLM, Logging, Evasion, .NET]
description: "How PowerShell really runs on modern Windows, what’s logged and scanned, and pragmatic ways to adapt usage and detections to your target environment."
toc: true
pin: false
----------

PowerShell remains a staple for reconnaissance and task automation during Windows engagements. This post lays out how PowerShell *actually* runs, what built-in defenses matter, and practical ways to run, modify, and (when justified) reduce detection surface—so you can adapt techniques to the maturity of your target environment.

> **Disclaimer**
> This article discusses security controls and common detection/evasion concepts at a high level for legitimate testing and defense. It intentionally avoids exploit code or step-by-step bypass instructions.

---

## Why PowerShell

PowerShell is a cross-platform task-automation solution composed of a command-line shell, a scripting language, and a configuration-management framework. The main reason we rely on it is simple: like Bash or JavaScript in other ecosystems, it’s broadly available on Windows.

* **Availability by default.** Windows PowerShell has been *included by default* since **Windows 7 / Windows Server 2008 R2**. On current Windows 10/11 builds you’ll find **Windows PowerShell 5.1** present.
* **Two flavors.** **PowerShell** (aka PowerShell Core) is the cross-platform edition and is **not** the default on most Windows installations. **Windows PowerShell** is what ships by default, and most tradecraft in this post assumes Windows PowerShell.

---

## PowerShell ≠ `powershell.exe`

PowerShell is a .NET assembly: `System.Management.Automation`. The blue console—`powershell.exe`—is only **one** host. Tools and operators also run PowerShell via:

* custom runspaces
* alternative hosts
* embedded contexts (e.g., inside other .NET apps)

Blocking `powershell.exe` alone does not “turn off” PowerShell.

---

## Loading PowerShell Code

Common operations you’ll use in the field:

* **Dot-sourcing from disk**

  ```powershell
  . <path-to-script>   # dot, space, then the path
  ```
* **Modules**

  ```powershell
  Import-Module <ModuleName>     # .psm1, .psd1, etc.
  Get-Command -Module <ModuleName>
  ```
* **Remote/in-memory patterns**
  Downloading script text and running it with `Invoke-Expression` has been common since ~2011. That ubiquity helped drive tighter controls like AMSI integration in the PowerShell 5.x era.

---

## Security Enhancements That Matter

Beginning with Windows 10 and **Windows Management Framework (WMF) 5.x**, Windows PowerShell gained integrations and policies that meaningfully change how activity is recorded and scanned.

| Control                               | What it does                                                           | Defaults & notes                                                                                                                                    |
| ------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Antimalware Scan Interface (AMSI)** | Scans script content before execution via the machine’s registered AV. | PowerShell’s AMSI integration arrived with **WMF 5.x** (5.0/5.1). Detection hinges on the AV engine and its signatures.                             |
| **Script Block Logging (4104)**       | Logs executed script blocks (deobfuscated form where possible).        | **Opt-in via policy**; Windows may still log certain suspicious blocks even when full 4104 logging isn’t enabled.                                   |
| **Module Logging (4103)**             | Logs pipeline execution details for specified modules.                 | **Opt-in via policy**.                                                                                                                              |
| **Transcription**                     | Captures console input/output to plaintext transcript files.           | **Per-session** by default; **system-wide** when enforced via policy. Plaintext can expose secrets if locations are writable or broadly accessible. |
| **Constrained Language Mode (CLM)**   | Restricts language features when app-control policies apply.           | Allows many **Microsoft-signed** modules; restricts dynamic .NET and numerous operations. Often paired with AppLocker/WDAC.                         |

> **Note**
> There are four language modes: `NoLanguage` (used by JEA), `ConstrainedLanguage`, `RestrictedLanguage`, and `FullLanguage`. Policies determine which mode applies.

---

## Execution Policy Is Not a Security Control

Treat execution policy as a convenience feature, not a defense. There are many ways to run code regardless of policy settings.

---

## “Is Offensive PowerShell Dead?”

No. Effectiveness depends on the organization’s posture and configuration. Popularity waves between .NET, PowerShell, and C# tools as defenders and attackers adapt. Choose tools based on goals and detection realities—not fashion.

---

## Where Detections Usually Happen

You’ll typically run into three defensive layers that matter for PowerShell:

1. **Transcription / host-level logging**
2. **Script Block & Module Logging (4104 / 4103) and related events**
3. **AMSI scanning via the registered AV engine**

**Common reduction strategies (high-level):**

* Use **non-`powershell.exe` hosts** or custom runspaces to avoid simplistic process-based blocks.
* Prefer **least-necessary functionality** and prune features that drive signatures.
* Perform **targeted obfuscation** of strings/tokens that are actually matched, instead of blanket obfuscation.
* Understand runtime tampering risks and forensics implications before considering approaches that alter logging/scanning behavior.

> **Heads-up**
> Transcription is file-based, not event-ID based, and its coverage depends on how the policy is applied.

---

## InvisiShell (Conceptual Overview)

InvisiShell is a well-known research tool that demonstrates **runtime patching** of PowerShell internals to neutralize **AMSI** and **ETW-backed logging** (e.g., Script Block/Module Logging). Impact on **forced transcription** depends on the environment and policy. The key takeaway for operators and defenders alike: logging paths often converge through ETW/AMSI, and controls can be evaluated (and potentially disrupted) at those choke points.

> **Reminder**
> Whether you’re testing or defending, account for **privilege requirements**, **forensic traces**, and **tamper protections** when evaluating any runtime approach.

---

## Disk-Based Scripts: Targeted Changes Beat “Black-Box” Obfuscation

When you must run from disk, minimize signatures with a surgical workflow:

1. **Scan** locally with a tool that reveals **which bytes/strings** trigger detections.
2. **Map** offsets back to lines (helper scripts can translate byte offsets to line numbers).
3. **Identify** the minimal string/token/code fragment responsible.
4. **Change only that fragment** and re-scan. Iterate until detections stop.

> **Example**
> A basic reverse-TCP script tripped AV on the literal `"Net.Sockets"`. Reversing or otherwise masking that *single* token was sufficient to clear signatures—no need for heavy, full-file obfuscation.

---

## Prune Features That You Don’t Need

Large, popular scripts (e.g., privilege-escalation helpers) often include **optional** behaviors—like dropping helper binaries—that are heavily signatured. If a capability isn’t necessary for your objective, removing that portion frequently drops detections while retaining the functionality you *do* need for measurement or validation.

---

## Testing & Expectations

* **Continuously test** against current Defender/AV baselines; signatures change over time.
* Treat validated versions as **point-in-time** artifacts. A tool that’s clean today may alert next month.
* When detections reappear, return to the targeted-change workflow instead of jumping straight to blanket obfuscation.

---

## Focus: Identity & Active Directory First

For many objectives, identity and AD paths (credential exposure, delegation, misconfigurations) are higher-leverage than endpoint cat-and-mouse games. Endpoint evasion still matters—but it isn’t the sole goal of most engagements.

---

## Practical Recommendations (Checklist)

* Understand **how** PowerShell is being hosted in your session; blocking `powershell.exe` doesn’t end PowerShell.
* Prefer **modular, targeted** obfuscation over full-script mangling.
* If evaluating runtime techniques, weigh **privileges**, **forensics**, and **tamper protections** before touching AMSI/ETW surfaces.
* **Remove unnecessary features** from large scripts to avoid signature-heavy branches (e.g., binary drops).
* **Continuously re-scan** against current Defender/AV baselines and iterate when signatures change.
* Do **not** depend on execution policy for defense; treat it as a UX lever, not a control.

---

## Closing Thoughts

PowerShell remains a powerful, pragmatic option for enumeration and many offensive tasks. Controls like AMSI, Script Block/Module Logging, transcription, and CLM complicate naive execution but don’t remove PowerShell from the toolbox. With targeted changes, selective pruning, and informed runtime decisions, you can right-size your approach to the environment and your objectives.


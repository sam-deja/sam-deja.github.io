---
title: "3. PE file format in depth"
date: 2025-11-02 10:00:00 -0500
categories: [windows, internals]
tags: [pe, windows, reversing]
description: "In this article I will walk you through the most important parts of the PE format you really need to know."
image:
  path: https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2Fc3b8bacc-4195-454e-9f35-e9536653d4ba.webp?alt=media&token=050b4fd5-6464-4ab3-9906-0d85c5abc4e1
  alt: "PE Format"
---

PE file format in depth
===========================

When you want to understand how Windows executables actually work, nothing beats digging into the PE file format. Over the years I have returned to this format again and again because many low-level techniques, reverse engineering tasks, and loader behavior investigations require solid knowledge of PE headers and how sections, directories, and addresses are laid out.

In this article I will walk you through the most important parts of the PE format you really need to know. I will avoid exhaustive coverage of every structure in favor of practical understanding: how to read the headers, how to translate file offsets to runtime addresses, what the key fields mean, and how to investigate a real process using tools like PE-bear, Dumpbin, a debugger, and Process Hacker. I will use Notepad.exe as a concrete example throughout because it is available on every system and is an excellent target to inspect.

Early on I want to highlight two small but crucial distinctions that confuse newcomers but that you must master: the difference between a file pointer (raw address) and an RVA (relative virtual address), and the difference between metadata (headers) and data (sections). Once you get these two, the rest becomes far easier to follow.

![Opening Notepad.exe path C:\Windows\System32\notepad.exe in PE-bear](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2Fcb0fb8d8-042e-4fbd-8239-e98c2d0910f4.webp?alt=media&token=c6afcc68-b9ac-45e5-9b9b-ce11cdd5b10b)

Why PE matters and what to focus on
-----------------------------------

The Portable Executable, or PE, format is the structure Windows uses for EXE and DLL files. It contains both metadata and the actual code and data that will run. The metadata tells the loader what to map into memory, how to configure protections, where the entry point is, and where to find imports, exports, resources, relocations, and more.

There is a lot of material produced by Microsoft that documents the PE format in excruciating detail. You can read the specification and header definitions for hours. But if you are doing reverse engineering, binary instrumentation, loader work, or exploit development, you do not need every field. Focus on the following:

*   **DOS header** and the pointer to the PE header
*   **PE signature** and File Header
*   **Optional Header**: magic, entry point, image base, section alignment, size of image and headers, subsystem, DllCharacteristics
*   **Data directories**: especially Import Directory and Export Directory, but also Relocations, Resource, and TLS if relevant
*   **Section Table**: section names, virtual size, virtual address (RVA), size of raw data, pointer to raw data, section characteristics
*   How to translate between raw file offsets and RVAs, and then to actual in-memory addresses

Below I will explain each piece, show how they fit together, and illustrate with examples taken from a real Notepad binary parsed in PE-bear.

File pointer vs RVA: the single most important distinction
----------------------------------------------------------

Let us start with the fundamental address concepts. There are two kinds of offsets you will constantly translate between:

*   **File pointer** (also known as Raw Address). This is an offset inside the file on disk. Think of it as "where this data is stored in the file."
*   **RVA** (Relative Virtual Address). This is the offset of the item when the file is mapped into memory, relative to the base address of the mapped image. Think of it as "where this data will be located in process memory relative to the module base."

> "RVA is an offset in memory and file pointer or raw address is an offset in a file on disk."

Remember: the RVA is computed after the image is loaded into memory. If a module is loaded at base address 0x10000 and an item has RVA 0x1500, its virtual address is 0x10000 + 0x1500 = 0x11500. The raw address, in contrast, might be a completely different offset in the file on disk because the file layout and the memory layout are not identical. Sections are aligned differently on disk and in memory; empty data, alignment padding, and other layout differences make the two sets of offsets typically differ.

### Quick mental model

*   File pointer = offset inside the file on disk
*   RVA = virtual offset inside the in-process image (i.e., address minus image base)
*   Virtual Address (VA) = image base + RVA

Master these and you will stop getting lost when walking between file viewers, hex editors, and debuggers.

PE as a book: metadata and chapters
-----------------------------------

I often describe a PE file like a book. The code and data are the content; the headers are the metadata: author, table of contents, chapter sizes, and pointers telling you where each chapter begins.

In this analogy:

*   **Headers** are the table of contents and page numbers. They point to the sections and provide metadata about the executable.
*   **Sections** correspond to chapters (for example, code, read-only data, writable data, resources).
*   **Data directories** are index entries that point to special tables like the import table, export table, and so on.

When you open a PE viewer you see the DOS header first, then the PE header, the optional header, the data directories, and finally the section headers. After the headers come the contents of the sections themselves. The headers guide you on how to interpret the rest of the file.

![DOS header with 'MZ' magic visible in PE-bear](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2Fc3b8bacc-4195-454e-9f35-e9536653d4ba.webp?alt=media&token=050b4fd5-6464-4ab3-9906-0d85c5abc4e1)

DOS header: the very first structure
------------------------------------

The file starts with the DOS header. Historically this enabled executables to print a message like "This program cannot be run in DOS mode" when run on DOS. Modern Windows systems still use that header as a sanity check and a pointer to the real PE header.

Two fields in the DOS header matter most:

*   **e\_magic**: the magic value. It must start with the ASCII letters 'M' 'Z' (hex 4D 5A). If you open any PE file with a hex viewer you will see 4D 5A at offset 0x0.
*   **e\_lfanew**: this is the file offset to the start of the PE header. It tells you where the modern PE header (the "new exe header") begins. This field is a raw file pointer, not an RVA.

When building a parser, you read the DOS header at file offset 0. Then go to e\_lfanew to find the PE signature and subsequent headers. Many automated tools and parsers follow this same two-step process.

PE signature and File Header
----------------------------

At the offset indicated by e\_lfanew you find the PE signature followed by the IMAGE\_FILE\_HEADER. The signature is the ASCII characters "PE" followed by two zero bytes.

![PE signature 'PE\\0\\0' and File Header visible in PE-bear](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2Ff8d997a4-78cd-4435-b57d-fa880f5ef79b.webp?alt=media&token=56b27f9c-1692-44af-8e4d-d5accb7f16d6)

The File Header contains basic information about the machine architecture, number of sections, time stamp, and importantly the size of the optional header. Some fields to pay attention to:

*   **Machine**: CPU architecture (for example AMD64, x86).
*   **NumberOfSections**: how many entries are in the section table that immediately follows the optional header.
*   **SizeOfOptionalHeader**: length in bytes of the optional header. Although called "optional", this header is always present in EXE and DLL files. You use this value to know how many bytes to skip to reach the section table.
*   **Characteristics**: flags that describe attributes of the file; for example whether it is executable, whether it uses large address awareness, and more.

For example, in my Notepad sample the number of sections is 6. The SizeOfOptionalHeader is 0xF0. These values tell us how to locate the optional header and then hash forward to the section headers.

Optional Header: the core runtime metadata
------------------------------------------

The optional header is rich in runtime configuration. It defines several key values the loader uses to map the image into memory and to start execution.

![Optional header with AddressOfEntryPoint (RVA 1AC50) highlighted in PE-bear](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2F74f98592-c437-4843-ad23-23d874a010c9.webp?alt=media&token=b5b8577c-f2b2-439e-88bd-ad7fd00f3707)

Key fields in the optional header include:

*   **Magic**: identifies whether the image is 32-bit (0x10B) or 64-bit (0x20B). For Notepad.exe on a 64-bit system this was 0x20B.
*   **AddressOfEntryPoint**: this is an RVA pointing to the first instruction executed after the loader hands control to the program. In the sample file this was an RVA of 0x1AC50. Remember this is an RVA—not a raw file offset.
*   **ImageBase**: preferred base address where the loader should map the image. On modern Windows, the loader will apply ASLR and may map at a different base unless the binary is not relocatable.
*   **SectionAlignment and FileAlignment**: used to compute how sections are aligned in memory vs on disk.
*   **SizeOfImage**: size in bytes of the virtual image when loaded into memory, including all sections as they are mapped with SectionAlignment.
*   **SizeOfHeaders**: size of all headers rounded up to FileAlignment.
*   **Subsystem**: indicates whether the program is a GUI app or a console app (for example, 2 means Windows GUI, 3 means console).
*   **DllCharacteristics**: a bitfield with flags like ASLR, NX compatibility, Control Flow Guard, high-entropy ASLR, and more.
*   **NumberOfRvaAndSizes**: count of entries in the Data Directory table. The default is 16.

Two things I often check right away in the optional header:

1.  Is ASLR enabled? This is indicated by IMAGE\_DLLCHARACTERISTICS\_DYNAMIC\_BASE (one of the bits in DllCharacteristics). If this bit is set, the image is relocatable and the loader will pick a randomized base when loading.
2.  Is NX enabled? This is indicated by IMAGE\_DLLCHARACTERISTICS\_NX\_COMPAT. If set, the system will mark the stack non-executable using DEP/NX.

In the Notepad example the DllCharacteristics showed dynamic base, NX compatibility, CFG, and terminal services awareness. You can see these in UI tools that expose the mitigation policies for a running process.

![Optional header mitigations: DP, ASLR, high-entropy ASLR, CFG visible in PE-bear](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2F26e99ca5-c35e-49bb-9811-acff3b7f2519.webp?alt=media&token=fbabd656-28c0-4c54-a64c-311c776a1412)

Data directories: the PE index
------------------------------

After the core optional header fields comes the Data Directory array. This array contains a sequence of IMAGE\_DATA\_DIRECTORY entries. Each entry is just two dwords: **VirtualAddress** (an RVA) and **Size**.

![Data Directory table listing export and import directories with RVAs and sizes](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2Fa758757f-5234-4dff-b8bb-e0ec592f25f7.webp?alt=media&token=549ab9b9-e5e4-49d8-bd33-5c03428544a7)

The default set includes 16 directories for:

*   Export table
*   Import table
*   Resource table
*   Exception table
*   Certificate table
*   Base relocation table
*   Debug data
*   Architecture data
*   Global pointer
*   TLS table
*   Load configuration
*   Bound import table
*   IAT (Import Address Table)
*   Delay import descriptor
*   CLR runtime header
*   Reserved

Each directory entry points to a structure elsewhere in the file (or is zero if not present). For instance, the import directory tells you how to find the list of DLLs and the functions imported by the image. The export directory contains a list of exported functions and names for DLLs and EXEs that export symbols. The relocation directory is used by the loader when the image cannot be loaded at its preferred base and relocations need to be applied.

Note that the directory entries themselves store RVAs. That means to find them in the file or in memory you must translate these RVAs using the section table. More on that below.

### Import directory and import address table distinction

Two commonly confused concepts are the Import Directory and the Import Address Table (IAT). They are related but not the same:

*   **Import Directory** (IMAGE\_IMPORT\_DESCRIPTOR list) is a structure the loader reads to know which modules to load and which functions to import. It contains RVAs to the original import names (or ordinal arrays) and to the IAT.
*   **Import Address Table (IAT)** is the actual array of pointers used by the program at runtime. When the loader resolves imports it writes the resolved VA of each imported function into the IAT. That is the table you will see filled with VAs at runtime.

When you inspect a file on disk, the IAT entries may contain RVAs pointing to IMAGE\_IMPORT\_BY\_NAME entries. When the process is loaded, the loader writes absolute VAs into the IAT so the program calls directly through those pointers. In other words, the IAT is the runtime table of function pointers.

Translating RVA into VA and raw file offset
-------------------------------------------

Translating addresses is a frequent manual step when analyzing a PE file. Here are the steps I use:

1.  Find the RVA you care about. For example, the import directory might have VirtualAddress = 0x1C6B0.
2.  Obtain the module image base at runtime. For a loaded module the base is the virtual address where the loader mapped the image (this often differs from the ImageBase in the Optional Header because of ASLR).
3.  Compute the VA by adding ImageBase + RVA. This gives you the actual pointer you can use in the debugger.
4.  If you want to find the corresponding raw file offset in the file on disk, find the section whose VirtualAddress range includes the RVA, then compute RawOffset = PointerToRawData + (RVA - VirtualAddress of section).

Let us walk through a real example using Notepad:

Suppose the Import Directory contains RVA = 0x1C6B0. To inspect this in a running process, attach a debugger, locate the module base (for example 0x7FF7FF700000), and add the RVA. So the VA becomes 0x7FF7FF700000 + 0x1C6B0 = 0x7FF7FF71C6B0. Jump to that address in the debugger to see the IAT contents. The IAT will include pointers to functions like OpenProcessToken and GetTokenInformation located inside kernelbase.dll.

![Debugger memory dump showing import address table entries with VAs pointing to kernelbase functions](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2F0b1b293e-6e13-4937-b3f6-499234faec69.webp?alt=media&token=715b06db-0cbd-4387-aa8d-9cda89124ef3)

To map the RVA to a raw file offset, locate the section table entry that covers RVA 0x1C6B0. Suppose the .text section has VirtualAddress 0x1000 and PointerToRawData 0x400. Then RawOffset = 0x400 + (0x1C6B0 - 0x1000) = 0x400 + 0x1B6B0 = 0x1BA B0 (depending on the actual numbers). Tools like PE-bear compute this for you automatically, but if you are writing a parser or manually inspecting files you will do this math frequently.

Section Table: chapters of the book
-----------------------------------

After the headers the section table follows. The section table contains one IMAGE\_SECTION\_HEADER for each section listed in NumberOfSections. Each section header describes where that section lives both in the file and when mapped into memory.

![Section header definition and the .text section header displayed in PE-bear](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2Fb8a674c1-a690-4aee-ac1f-5be054bdb9e0.webp?alt=media&token=e974c2b9-f433-49b2-bf01-33003aba14d4)

Important fields in a section header include:

*   **Name**: an 8-byte ASCII name (for example .text, .rdata, .data, .rsrc).
*   **VirtualSize**: the size of the section in memory (may be smaller or larger than SizeOfRawData).
*   **VirtualAddress**: the RVA where the section is mapped in memory (relative to image base).
*   **SizeOfRawData**: size of the section data in the file on disk (rounded up to FileAlignment).
*   **PointerToRawData**: file offset for the section data (raw address).
*   **PointerToRelocations** and **PointerToLinenumbers**: typically zero for modern PE files built by Microsoft compilers.
*   **Characteristics**: flags describing section attributes, such as executable, readable, writable, contains initialized data, etc.

Note the common union in C headers: VirtualSize and PointerToRawData appear in a union in the formal structure definitions. For parsing you should treat them as separate dwords at fixed offsets; the union behavior is a C convenience for different uses across tools.

### Example: mapping a .text section

In my Notepad example the .text section had:

*   VirtualAddress = 0x1000 (so the section is mapped at image base + 0x1000)
*   PointerToRawData = 0x400
*   SizeOfRawData = 0x1AC0
*   Characteristics = executable and readable

This means that the sequence of bytes starting at file offset 0x400 for 0x1AC0 bytes corresponds to the code that will be mapped into memory at RVA 0x1000 and used for execution. Because of alignment and other fields the file offset 0x400 corresponds to RVA 0x1000 in memory. If you want to find the entry point at RVA 0x1AC50, you see that it resides in .text: VA = ImageBase + 0x1AC50 and RawOffset = PointerToRawData + (0x1AC50 - 0x1000) = 0x400 + 0x1A C50 - 0x1000 = computation yields the offset into the file where instruction bytes for the entry point live.

Section characteristics flags
-----------------------------

Each section header ends with a 32-bit Characteristics field that you can decode into flags. Common values are:

*   IMAGE\_SCN\_CNT\_CODE: section contains executable code
*   IMAGE\_SCN\_CNT\_INITIALIZED\_DATA: section contains initialized data
*   IMAGE\_SCN\_CNT\_UNINITIALIZED\_DATA: BSS-like uninitialized data
*   IMAGE\_SCN\_MEM\_EXECUTE: section is executable
*   IMAGE\_SCN\_MEM\_READ: section is readable
*   IMAGE\_SCN\_MEM\_WRITE: section is writable

For example, the .text section usually has Execute and Read bits set, while the .data section typically has Read and Write set but not Execute. You can verify these permissions on the loaded module in a debugger or by looking into the memory map; they will appear as PROT\_EXEC, PROT\_READ, PROT\_WRITE combos depending on the loader settings.

![Section characteristics flags decode for .text showing execute and read flags](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2Fe6901545-034f-4158-82c2-140c06468b41.webp?alt=media&token=1ffe2fe5-9f73-4229-b732-84b5a228ecba)

How PE-bear and other tools help
--------------------------------

While manual parsing is instructive, tools make life easier. PE-bear is one of the tools I like for interactive exploration. It parses all the headers for you, shows the sections, decodes many fields, and offers a raw vs virtual memory view. Dumpbin and other Microsoft tooling offer similar parsed views from the command line.

![PE-bear left pane showing raw file view and virtual memory view of sections](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2Ffc97263b-9e8e-4b74-88fa-9403e94ed489.webp?alt=media&token=705aaa0a-eeb9-43f4-ac22-977f780210e0)

When you open a file in PE-bear you can click on the DOS header, the PE headers, the file header, and the optional header and inspect the fields. You can also click an RVA to jump into the raw file bytes or to the disassembly view of the bytes at that RVA if the tool supports it.

One practical workflow I use when learning a new binary:

1.  Open file with PE-bear to inspect high-level headers and find the entry point RVA, data directories, and number of sections.
2.  Use Dumpbin /headers to cross-check the counts and alignments.
3.  Attach a debugger to a running process and open the module memory map to see the loaded base address and the actual memory protections applied.
4.  Calculate the VA for the import directory and jump to it in the debugger to inspect the IAT filled with resolved VAs.
5.  Use Process Hacker or another process viewer to inspect the module base and memory layout for cross-checking.

This approach lets you correlate on-disk layout with in-memory behavior. The alignment differences, ASLR choices, and mitigations are much easier to understand when you look at both the disk image and a live process instance.

Relocations and why ASLR works
------------------------------

If an image specifies a preferred ImageBase and has relocations/relocation table entries, the loader can apply base relocations when the image is loaded at a different base (for example due to ASLR). The relocation directory contains addresses that must be fixed up by adding the delta between preferred base and actual base. If a binary does not contain relocation information and is not loaded at its preferred base, the loader will fail unless it is rebased by other mechanisms.

For modern defensive techniques, enabling ASLR and shipping relocation information is a common requirement. The DllCharacteristics flag IMAGE\_DLLCHARACTERISTICS\_DYNAMIC\_BASE listed in the optional header indicates that the image can be rebased and thus supports ASLR. Another related flag is IMAGE\_DLLCHARACTERISTICS\_HIGH\_ENTROPY\_VA which enables high-entropy 64-bit ASLR.

Entry point and image initialization
------------------------------------

AddressOfEntryPoint points to the code executed after the loader finishes mapping sections, applying relocations, resolving imports, initializing TLS callbacks, and calling any static constructors. For managed or language runtimes, there may be additional bootstrap code; for simple native apps, the entry point transfers control to the CRT runtime which sets up environment and calls main or WinMain.

Remember that AddressOfEntryPoint is an RVA, not a raw file offset. When you click it in PE-bear the tool jumps to the corresponding bytes and shows a disassembly. In the sample file the entry point was inside .text and the disassembly was visible immediately thanks to the tool.

Practical tips for manual parsing and writing parsers
-----------------------------------------------------

If you plan to write your own PE parser, here are some practical notes and pitfalls I have learned the hard way:

*   Always validate the magic values: MZ in DOS header and PE\\\\0\\\\0 at e\_lfanew. If these are missing, the file is not a PE image.
*   Beware of malformed or intentionally corrupted binaries. Malware and packers may put odd values to confuse naive parsers. Always clamp sizes and verify that offsets fall inside the file bounds.
*   Use SizeOfOptionalHeader to find the start of the section table. The section table follows the optional header which length is specified in the file header.
*   Remember to respect FileAlignment and SectionAlignment when computing raw-to-virtual translations. The file on disk is aligned to FileAlignment. Memory sections are aligned to SectionAlignment.
*   When computing a raw file offset from an RVA: find the section header such that RVA >= VirtualAddress and RVA < VirtualAddress + max(VirtualSize, SizeOfRawData). Then rawOffset = PointerToRawData + (RVA - VirtualAddress).
*   Check NumberOfRvaAndSizes and do not assume 16 directories are always present. Some compilers may produce fewer entries.
*   Never trust pointers in the file blindly. When a directory entry gives VirtualAddress and Size, perform the RVA-to-raw translation and ensure the raw offset plus size fits within the file.
*   Be mindful of overlays: data appended at the end of the file after the sections may be present (e.g., digital signatures or appended resources). SizeOfImage does not account for overlays.

Inspecting a live process: confirming header values vs runtime view
-------------------------------------------------------------------

Inspecting a binary on disk is useful, but looking at the running instance reveals the final mapping and mitigations. When you attach to a running process with a debugger or use Process Hacker, pay attention to these elements:

*   Actual base address where the module is loaded. This is what you add to an RVA to compute a VA in the running process.
*   Memory protections on mapped regions. These should match the section characteristics: code should be executable, read-only data should be readable, writable data should be writeable, and so on.
*   Resolved IAT. The Import Address Table should be filled with the resolved function addresses once the loader completes import resolution.
*   Relocations. You can verify that base relocations have been applied when the loaded base differs from ImageBase.

![Using Process Hacker to view imported functions and base addresses of Notepad](https://firebasestorage.googleapis.com/v0/b/videotoblog-35c6e.appspot.com/o/%2Fusers%2F0uEQRKSAQpaO87XfrCPo2KF20Mm2%2Fblogs%2F3ODhAsqqnO34GxiRAbTP%2Fscreenshots%2F32e01413-dab9-4c9e-9ab6-6a05def77ebe.webp?alt=media&token=71ade404-ca62-4410-a806-54d00a0fe8d2)

For example, I attached a debugger to Notepad and used the memory map to locate the module base. The base I observed differed from the optional header's ImageBase due to ASLR. I then computed VA = base + RVA for the import table to inspect it. The pointer values in the IAT referenced functions in kernelbase.dll such as OpenProcessToken and GetTokenInformation. This confirms how the import mechanism ties disk metadata to runtime pointers.

Putting it all together: a walkthrough example
----------------------------------------------

Here is a step-by-step walkthrough of the core diagnostic flow I use when starting on a new binary:

1.  Open the binary in PE-bear. Confirm DOS header and e\_lfanew. The UI will show MZ at the start and the PE signature at e\_lfanew. This gives confidence the image is a valid PE.
2.  Inspect the File Header: note Machine, NumberOfSections, and SizeOfOptionalHeader. Use SizeOfOptionalHeader value to find where the section table starts.
3.  Inspect the Optional Header: note Magic (32/64 bit), AddressOfEntryPoint (RVA), ImageBase, SectionAlignment, FileAlignment, SizeOfImage, Subsystem, and DllCharacteristics. Check the NumberOfRvaAndSizes and then look at the Data Directory entries.
4.  Open the Data Directory: look at the Import Directory and its RVA. Remember the entries are RVAs, so you cannot index the file directly without translating them to raw offsets via the section table.
5.  Find which section contains the RVA by checking each section's VirtualAddress and VirtualSize. Compute raw offset with PointerToRawData + (RVA - VirtualAddress).
6.  Open the file at the raw offset to inspect the Import Descriptor list (IMAGE\_IMPORT\_DESCRIPTOR). It lists DLL names and pointers to the OriginalFirstThunk and FirstThunk. OriginalFirstThunk points to names/ordinals; FirstThunk is the IAT that will be populated at runtime.
7.  Attach to the running process and find the actual module base. Compute the VA of the IAT using base + RVA and jump to it in the debugger to confirm the runtime addresses resolved to actual function addresses in kernel modules.
8.  Examine the Section Table and find the .text section. Confirm SizeOfRawData and PointerToRawData mapping. You can visually compare disassembly between the raw view and runtime disassembly. Notice differences due to relocations or dynamic ranges.

Following these steps will give you a consistent picture of how a PE file's on-disk metadata becomes an in-memory representation that the OS uses to execute the program.

Common gotchas and subtle points
--------------------------------

After many years working with PE files, these are the recurring traps I see:

*   Mixing up raw offsets and RVAs. This causes off-by-file errors when opening data in a hex editor versus in a debugger.
*   Assuming ImageBase equals the loaded base. With ASLR enabled, the runtime base will usually differ. Always check the live process when analyzing runtime behavior.
*   Assuming all directories are present. Many directories are optional and will have zero VirtualAddress and zero Size when absent.
*   Ignoring FileAlignment and SectionAlignment differences. Mapping between disk and memory must respect these alignments to avoid incorrect offsets.
*   Trusting exported names for an EXE. EXEs can export symbols just like DLLs; do not assume only DLLs export functions.
*   Confusing Import Directory with IAT. The former describes what to import; the latter is where resolved pointers are stored at runtime.

Resources and next steps
------------------------

If you want to go deeper, the authoritative resource is Microsoft's PE and COFF specification and the Windows headers (for example winnt.h) which define the IMAGE\_\* structures. Studying the header file definitions side-by-side with a tool like PE-bear gives an excellent practical learning path. Many advanced topics such as relocations, TLS callbacks, load configuration, and the new security mitigations deserve their own focused sessions.

Recommended practice exercises:

1.  Pick a small EXE such as Notepad or calc.exe. Open it in PE-bear and identify the DOS header e\_lfanew, the PE signature, and the optional header fields.
2.  Find AddressOfEntryPoint as an RVA and map it to raw file offset. Confirm the code bytes in the file match what the disassembler shows at runtime.
3.  Inspect the Import Directory and find the IAT. Start the process and observe the resolved pointers in the debugger or Process Hacker.
4.  Modify a benign constant in a non-code section, save the file, and reload it in a debugger to ensure your raw-to-virtual offset computations are correct. Do not modify code unless you know what you are doing.
5.  Write a small script (in Python or C) that reads the DOS header, locates the PE header using e\_lfanew, parses the FileHeader and OptionalHeader, and enumerates all sections. Printing mappings between RVA and raw offsets is a great first project.

Summary and final thoughts
--------------------------

PE is a compact and powerful format that describes everything the Windows loader needs to run a program. The most useful practical knowledge you can gain in a short time is:

*   How to find the PE header starting from the DOS header's e\_lfanew.
*   How to read the optional header to find the AddressOfEntryPoint, ImageBase, and the Data Directory table.
*   How to translate between RVA, raw file offset, and actual VA in a running process using the section table.
*   How to decode import structures and see how the IAT gets populated at runtime.
*   How to interpret section characteristics to understand what memory protections the loader will apply.

Learning to parse the PE file manually builds intuition that will make tool output much more meaningful. As you practice with PE-bear, Dumpbin, and a debugger, the translations between file layout and runtime behavior will become second nature.

Finally, here is a quote I often repeat because it captures the essence of the space: "PE headers are like road signs; they tell you where to find things in the file and how to get to the relevant data." If you imagine yourself following those signs, walking from DOS header to PE header to optional header to data directories and then to section headers, you will always know where to look next.

Keep exploring, build a small parser, and test your findings on live processes. That is the fastest way to turn theory into reliable practice.
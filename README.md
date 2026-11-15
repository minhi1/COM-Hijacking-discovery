# COMHijackDiscovery

Static COM hijack discovery for Windows, written in C# .NET and designed to run **in-memory from an implant** via Sliver's `execute-assembly` (no `powershell.exe`, no console window, no script file on disk). It enumerates the COM server registrations in the registry, resolves each server path, and classifies every CLSID into one of three states. It is a reconnaissance tool only — it writes nothing and hijacks nothing.

## 1. What it does

For every CLSID found in `HKCU`, `HKLM` and `HKLM\Wow6432Node`:

1. Read the server value from each registration subkey.
2. Expand environment variables and strip quotes.
3. Resolve bare DLL names to a full path (`System32` for 64-bit registrations, `SysWOW64` for 32-bit registrations) instead of testing them relative to the current working directory.
4. Test whether the resolved file exists, with WOW64 filesystem redirection disabled so a 32-bit process still sees the true path.
5. Classify.

### Registration subkeys read

| Subkey | Server type |
|---|---|
| `InprocServer32` | in-process DLL (64-bit registration) |
| `InprocServer` | in-process DLL (legacy) |
| `InprocHandler32` | handler DLL, loaded before the server |
| `LocalServer32` | out-of-process EXE |
| `LocalServer` | out-of-process EXE (legacy) |
| `TreatAs` | CLSID redirect — skipped, see §7 |

### Classification

| Case | HKCU | HKLM | Server file | Meaning |
|---|---|---|---|---|
| `ORPHAN` | absent | present | missing | Registered but the binary is gone. The hijack surface for DLL placement or a per-user overlay. |
| `OVERLAID` | present | any | any | A per-user entry already exists for this CLSID. |
| `SHADOWABLE` | absent | present | exists | A live, working object. Hijackable by a per-user overlay pointing at a proxy DLL that forwards to the real server. |

`Hive` reports where the registration was found: `HKLM`, `HKLM32` (the 32-bit `Wow6432Node` view) or `HKCU`. `HKLM32` also implies the server is 32-bit, so the replacement DLL must be x86 rather than x64.

## 2. Build

Requires .NET Framework 4.x. The project targets `net48` and `x64`.

### Option A — `csc.exe` (no project file needed)

```bat
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
  /target:exe /platform:x64 /optimize+ ^
  /out:COMHijackDiscovery.exe ComHijackDiscovery.cs
```

No extra assembly references are needed, because `Microsoft.Win32.Registry` is part of `mscorlib` on .NET Framework.

### Option B — Visual Studio

Open `ComHijackDiscovery.csproj`, select Release | x64, build.

Build as x64. A 32-bit build still works because redirection is disabled explicitly around the existence check, but a 64-bit process avoids the problem entirely and reads every hive without redirection surprises.

## 3. Run

### From Sliver (in-memory)

```text
execute-assembly COMHijackDiscovery.exe
execute-assembly COMHijackDiscovery.exe -CSV C:\Windows\Temp\com.csv
```

### From a shell

```cmd
COMHijackDiscovery.exe
COMHijackDiscovery.exe -CSV out.csv
```

### Arguments

| Argument | Meaning |
|---|---|
| `-CSV <path>` | Also write the full result set (including every `SHADOWABLE` row) to a CSV file. Without this flag, `SHADOWABLE` is printed only as a count. |

## 4. Output

```
[*] COM hijack discovery (deterministic scope)
[*] subkeys: InprocServer32, InprocServer, InprocHandler32, LocalServer32, LocalServer, TreatAs
[*] hives  : HKCU + HKLM + HKLM(Wow6432Node)

==================== ORPHAN (missing server) ====================
--------------------------------------------
CLSID: {34EAF827-6C36-4CEF-8A9C-7C9842355641}
  Case     : ORPHAN
  Hive     : HKLM
  Subkey   : InprocServer32
  Server   : C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.233.3\psmachine_64.dll
  Arch     : x64 (default)
  Liveness : LIKELY-LIVE (has AppID/TreatAs)
  Stealth  : PLACE DLL or OVERLAY (no proxy needed)
...
==================== OVERLAID (HKCU already present) ====================
==================== SHADOWABLE (live, needs proxy) ====================
    (suppressed: 6100 live objects. Use -CSV for full list.)

[*] summary:
    ORPHAN (missing server)   : 115
    OVERLAID (HKCU present)   : 0
    SHADOWABLE (live object)  : 6100
```

### Per-entry fields

| Field | Meaning |
|---|---|
| `Case` | `ORPHAN`, `OVERLAID` or `SHADOWABLE` |
| `Hive` | `HKLM`, `HKLM32` (32-bit view) or `HKCU` |
| `Subkey` | which registration subkey carried the server value |
| `Server` | the resolved server path, or the raw value if it is not path-like |
| `Arch` | `x86` or `x64`, derived from the hive and the path (`System32` versus `SysWOW64`) |
| `Liveness` | a heuristic, not proof — see §6 |
| `Stealth` | proxy recommendation — see §6 |

### CSV columns

```
CLSID,Case,Hive,Subkey,Server,Arch,Liveness,Stealth
```

## 5. Choosing a target

An `ORPHAN` is the strongest candidate, because you can fill the gap either by placing a DLL at the missing path (no registry write at all) or by writing a per-user overlay for that CLSID.

Classification is not the same thing as exploitability. Of the orphans this tool finds on a clean Windows Server 2016, most fall into three unhelpful groups:

- Dead legacy components: DirectMusic (`dmscript.dll`, `dmime.dll`, `dmstyle.dll`, `dmcompos.dll`, `dmband.dll`), DirectPlay (`dplayx.dll`, `d3dxof.dll`), DAO (`dao360.dll`), Oracle OLE DB (`msdaora.dll`), Windows Connect Now (`wcnwiz.dll`, `wcnapi.dll`, `fdwcn.dll`). These are genuinely missing, but nothing on a server instantiates them.
- Desktop-only features that are absent from Server: `TetheringSettingHandler.dll`, `QuickActionsPS.dll`, `MSMiraDisp.dll`.
- Command-line `LocalServer32` entries, which are false positives. See §7.

Before committing to a target, confirm empirically that something will instantiate it. See §6.

## 6. What this tool cannot tell you

It reads static registry state only. It never observes a running process, which imposes hard boundaries.

### Liveness is a guess, not proof

The `Liveness` field is derived from indirect signals: whether the parent directory exists, and whether the CLSID has other registrations. It is correlated with liveness, not proof of it.

A concrete false positive from real use: a CLSID was reported `LIKELY-LIVE (has AppID/TreatAs)` for `...\EdgeUpdate\1.3.233.3\psmachine_64.dll` on a machine where Microsoft Edge and Edge Update were not installed. The registration was a leftover and nothing would ever instantiate it. Treat `Liveness` as "worth investigating", never as "confirmed".

To actually prove liveness you need runtime observation (ETW on `Microsoft-Windows-Kernel-Registry`, or ProcMon in a lab), because "a process opened `HKCU\...\CLSID\{GUID}\InprocServer32` and got `NAME NOT FOUND`" is a transient event that leaves no trace in the registry.

### "Referenced but unregistered" dangles are not discoverable

A CLSID that a program asks for via `CoCreateInstance` while having no registry entry in any hive cannot be found here, because there is nothing to enumerate. That class of target only appears in runtime observation.

An earlier revision of this tool attempted it by cross-referencing `HKCR\Interface\{IID}\ProxyStubClsid32`. That produced hundreds of false positives, because proxy and stub CLSIDs are themselves registered servers, so the code was removed rather than shipped broken.

### Trigger determinism is a human judgement

Whether a target fires on logon, on a schedule, or only on a rare user action is not derivable from the registry. That step is left to the operator.

### `HKCU` means the current process's user

`HKCU` is relative to the token the tool runs under. Run as a normal user and `HKCU` is that user's hive, so an overlay written there affects that user's processes. Run as SYSTEM and `HKCU` is SYSTEM's hive, so an overlay written there is invisible to the logged-in user's processes and will not affect user-context software.

To write a per-user override from a SYSTEM context, target the specific user's hive by SID instead:

```
HKU\<SID>\Software\Classes\CLSID\{GUID}\InprocServer32
```

Load the hive first with `reg load` if it is not already mounted. This tool reports `HKCU` state from the current token only and does not enumerate other users' hives, so `OVERLAID` means "overlaid for the account this tool ran as".

## 7. Known false positives

### `LocalServer32` and `LocalServer` command lines (not fixed)

`LocalServer32` values are frequently full command lines rather than bare paths:

```
"C:\Windows\System32\rundll32.exe" "C:\Program Files\Windows Photo Viewer\PhotoAcq.dll",AutoplayComServerW {...}
C:\Windows\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {...GUID...}
C:\Windows\explorer.exe /factory,{...GUID...}
"C:\Program Files (x86)\Windows Media Player\wmplayer.exe" /Play
C:\Windows\System32\CastSrv.exe CCastServerControlAsActivator
```

The current implementation tests the entire command line as a filesystem path, which of course fails, so these are reported as `ORPHAN` even though the executable exists. Expect a substantial share of any orphan list to be this class of noise on a stock Windows installation.

A fix would extract the executable token, honouring quotes, before the existence test. Planned, not implemented.

### `TreatAs` is skipped by design, not a false positive

`TreatAs` holds a CLSID, not a path:

```
{00020C01-0000-0000-C000-000000000046}  TreatAs -> {F20DA720-C02F-11CE-927B-0800095AE340}
```

Testing a GUID as a file path always fails, which previously produced a batch of false `ORPHAN` rows. `TreatAs` redirects are a distinct hijack surface, so they are now skipped entirely rather than misreported.

## 8. Relationship to the rest of the toolchain

| Discovery question | Data source | Tool |
|---|---|---|
| Which CLSIDs are registered, and is the server present? | registry (static) | this tool |
| Which CLSIDs does a process actually touch at runtime, and does the HKCU lookup fail? | ETW or ProcMon (dynamic) | runtime observer (not built) |
| Which CLSIDs are referenced but registered nowhere? | runtime observation | runtime observer (not built) |

Static and dynamic discovery are complementary. This tool answers "what is possible to hijack"; only runtime observation can answer "what is actually instantiated".

## 9. Source layout

| File | Purpose |
|---|---|
| `ComHijackDiscovery.cs` | the whole tool: registry walking, classification, output, CSV |
| `ComHijackDiscovery.csproj` | `net48`, `x64`, Release build settings |

Registry access uses `Microsoft.Win32.Registry`. WOW64 redirection is handled through `Wow64DisableWow64FsRedirection` and `Wow64RevertWow64FsRedirection` in `kernel32.dll`.

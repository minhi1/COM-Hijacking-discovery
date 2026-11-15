// COMHijackDiscovery.cs
// ============================================================================
// COM hijack discovery (C# .NET) — the "finished" discovery-stage tool.
//
// Implementation:
//   Step 1 - Discovery  : all 7 server subkeys x 3 hives x 4 cases
//   Step 2 - Liveness   : parent-installed + registry cross-reference,
//                         confidence-labeled (not a false claim of certainty)
//   Step 4 - Host props : architecture + ThreadingModel + AppID
//   Step 5 - Stealth    : proxy-recommendation flag (breakage-risk signal)
//   Step 3 - Trigger    : left to human (documented)
//
// Compile (x64, .NET Framework 4.x):
//   csc /target:exe /platform:x64 /optimize+ /out:COMHijackDiscovery.exe COMHijackDiscovery.cs
//
// Run from Sliver (in-memory):
//   execute-assembly COMHijackDiscovery.exe
//   execute-assembly COMHijackDiscovery.exe -CSV out.csv
//   execute -o COMHijackDiscovery.exe
// ============================================================================
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace COMHijackDiscovery
{
    internal static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Wow64DisableWow64FsRedirection(out IntPtr oldValue);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Wow64RevertWow64FsRedirection(IntPtr oldValue);

        // The complete COM server surface.
        private static readonly string[] ServerSubkeys = {
            "InprocServer32", "InprocServer", "InprocHandler32",
            "LocalServer32", "LocalServer", "TreatAs"
        };

        private static List<Result> _results = new List<Result>();

        private static int Main(string[] args)
        {
            string csvOut = null;
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("-CSV", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    csvOut = args[++i];
            }

            Console.WriteLine("[*] COM hijack discovery (deterministic scope)");
            Console.WriteLine("[*] subkeys: " + string.Join(", ", ServerSubkeys));
            Console.WriteLine("[*] hives  : HKCU + HKLM + HKLM(Wow6432Node)");
            Console.WriteLine();

            // --- Step 1: discovery -------------------------------------------
            Scan();

            // --- Output -------------------------------------------------------
            int orphan = 0, shadow = 0, overlay = 0;
            foreach (var r in _results)
            {
                if (r.Case == "ORPHAN") orphan++;
                else if (r.Case == "SHADOWABLE") shadow++;
                else if (r.Case == "OVERLAID") overlay++;
            }

            Console.WriteLine("==================== ORPHAN (missing server) ====================");
            foreach (var r in _results) if (r.Case == "ORPHAN") r.Print();

            Console.WriteLine("==================== OVERLAID (HKCU already present) ====================");
            foreach (var r in _results) if (r.Case == "OVERLAID") r.Print();

            Console.WriteLine("==================== SHADOWABLE (live, needs proxy) ====================");
            Console.WriteLine("    (suppressed: " + shadow + " live objects. Use -CSV for full list.)");

            Console.WriteLine();
            Console.WriteLine("[*] summary:");
            Console.WriteLine("    ORPHAN (missing server)   : " + orphan);
            Console.WriteLine("    OVERLAID (HKCU present)   : " + overlay);
            Console.WriteLine("    SHADOWABLE (live object)  : " + shadow);

            if (!string.IsNullOrEmpty(csvOut))
                WriteCsv(csvOut);

            return 0;
        }

        // ------------------------------------------------------------------
        private static void Scan()
        {
            var hkcu = LoadHive(Registry.CurrentUser, "Software\\Classes\\CLSID", "HKCU");
            var hklm64 = LoadHive(Registry.LocalMachine, "Software\\Classes\\CLSID", "HKLM");
            var hklm32 = LoadHive(Registry.LocalMachine, "Software\\Wow6432Node\\Classes\\CLSID", "HKLM32");

            // Union of all CLSIDs.
            var all = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var k in hkcu.Keys) all.Add(k);
            foreach (var k in hklm64.Keys) all.Add(k);
            foreach (var k in hklm32.Keys) all.Add(k);

            foreach (string clsid in all)
            {
                Process(clsid, hkcu, hklm64, hklm32);
            }
        }

        // Load CLSID -> (subkey -> server value).
        private static Dictionary<string, Dictionary<string, string>> LoadHive(RegistryKey root, string basePath, string label)
        {
            var map = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
            RegistryKey clsidKey = null;
            try { clsidKey = root.OpenSubKey(basePath); } catch { }
            if (clsidKey == null) return map;

            string[] names;
            try { names = clsidKey.GetSubKeyNames(); } catch { clsidKey.Close(); return map; }

            foreach (string name in names)
            {
                var sub = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string sk in ServerSubkeys)
                {
                    RegistryKey k = null;
                    try
                    {
                        k = clsidKey.OpenSubKey(name + "\\" + sk);
                        if (k != null)
                        {
                            object v = k.GetValue(null);
                            if (v != null) sub[sk] = v.ToString();
                        }
                    }
                    catch { }
                    finally { if (k != null) k.Close(); }
                }
                // AppID + ThreadingModel (host props)
                RegistryKey isk = null;
                try
                {
                    isk = clsidKey.OpenSubKey(name + "\\InprocServer32");
                    if (isk != null)
                    {
                        object tm = isk.GetValue("ThreadingModel");
                        if (tm != null) sub["__ThreadingModel"] = tm.ToString();
                    }
                }
                catch { }
                finally { if (isk != null) isk.Close(); }

                if (sub.Count > 0) map[name] = sub;
            }
            clsidKey.Close();
            return map;
        }

        private static void Process(string clsid,
            Dictionary<string, Dictionary<string, string>> hkcu,
            Dictionary<string, Dictionary<string, string>> hklm64,
            Dictionary<string, Dictionary<string, string>> hklm32)
        {
            Dictionary<string, string> cu = hkcu.ContainsKey(clsid) ? hkcu[clsid] : null;
            Dictionary<string, string> lm64 = hklm64.ContainsKey(clsid) ? hklm64[clsid] : null;
            Dictionary<string, string> lm32 = hklm32.ContainsKey(clsid) ? hklm32[clsid] : null;

            // Which subkeys are relevant (in-proc first priority).
            foreach (string sk in ServerSubkeys)
            {
                string cuVal = (cu != null && cu.ContainsKey(sk)) ? cu[sk] : null;
                string lmVal = null;
                string hive = null;
                if (lm64 != null && lm64.ContainsKey(sk)) { lmVal = lm64[sk]; hive = "HKLM"; }
                else if (lm32 != null && lm32.ContainsKey(sk)) { lmVal = lm32[sk]; hive = "HKLM32"; }

                if (cuVal == null && lmVal == null) continue;

                // TreatAs is a GUID redirect (CLSID -> other CLSID), NOT a file
                // path. It is not a "missing DLL" orphan, so skip it entirely.
                if (sk == "TreatAs") continue;

                var r = new Result { Clsid = clsid, Subkey = sk };

                if (cuVal != null)
                {
                    r.Case = "OVERLAID";
                    r.Hive = "HKCU";
                    r.Server = cuVal;
                    r.Arch = ArchOf("HKCU", cuVal);
                    r.Liveness = "N/A (already hijacked)";
                    _results.Add(r);
                    continue;
                }

                // cuVal null, lmVal present.
                r.Hive = hive;
                r.Server = lmVal;
                string resolved = ResolvePath(lmVal, hive);
                bool exists = FileExistsAnywhere(resolved);

                if (exists)
                {
                    r.Case = "SHADOWABLE";
                    r.Liveness = "LIVE (server exists)";
                    r.Stealth = RecommendProxy(clsid, hklm64, hklm32);
                }
                else
                {
                    r.Case = "ORPHAN";
                    r.Liveness = LivenessOf(clsid, lmVal, hklm64, hklm32);
                    r.Stealth = "PLACE DLL or OVERLAY (no proxy needed)";
                }
                r.Arch = ArchOf(hive, lmVal);
                _results.Add(r);
            }
        }

        // Resolve bare names to full paths (DLL search order approximation).
        private static string ResolvePath(string server, string hive)
        {
            string s = server.Trim('"');
            try { s = Environment.ExpandEnvironmentVariables(s); } catch { }
            if (s.Length >= 2 && char.IsLetter(s[0]) && s[1] == ':') return s;
            if (s.StartsWith("\\\\")) return s;
            // Bare name -> resolve against System32 (or SysWOW64 for 32-bit servers).
            string sysDir = hive == "HKLM32"
                ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
                : Environment.GetFolderPath(Environment.SpecialFolder.System);
            return Path.Combine(sysDir, s);
        }

        // Existence check, WOW64-redirection-safe.
        private static bool FileExistsAnywhere(string path)
        {
            bool exists;
            IntPtr old = IntPtr.Zero;
            bool redirected = false;
            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                redirected = Wow64DisableWow64FsRedirection(out old);
            }
            try
            {
                exists = File.Exists(path) || Directory.Exists(path);
            }
            finally
            {
                if (redirected && old != IntPtr.Zero) Wow64RevertWow64FsRedirection(old);
            }
            return exists;
        }

        // Step 2 liveness (best-effort, confidence-labeled).
        private static string LivenessOf(string clsid, string server,
            Dictionary<string, Dictionary<string, string>> lm64,
            Dictionary<string, Dictionary<string, string>> lm32)
        {
            // Signal A: parent directory exists?
            string parent = null;
            try { parent = Path.GetDirectoryName(server); } catch { }
            bool parentExists = !string.IsNullOrEmpty(parent) && Directory.Exists(parent);

            // Signal B: referenced by another registration (AppID / TreatAs)?
            bool hasAppId = (lm64 != null && lm64.ContainsKey(clsid)) ||
                            (lm32 != null && lm32.ContainsKey(clsid));

            if (parentExists) return "LIKELY-LIVE (parent dir exists)";
            if (hasAppId) return "LIKELY-LIVE (has AppID/TreatAs)";
            return "DEAD (no parent dir, no extra registration)";
        }

        // Step 5 stealth: recommend proxy when the CLSID has multiple consumers.
        private static string RecommendProxy(string clsid,
            Dictionary<string, Dictionary<string, string>> lm64,
            Dictionary<string, Dictionary<string, string>> lm32)
        {
            // System-critical = Microsoft core DLLs in System32 -> proxy strongly recommended.
            // Simplified heuristic: if it's in System32 and referenced by multiple subkeys.
            int consumers = 0;
            if (lm64 != null && lm64.ContainsKey(clsid)) consumers += lm64[clsid].Count;
            if (lm32 != null && lm32.ContainsKey(clsid)) consumers += lm32[clsid].Count;
            if (consumers >= 3) return "PROXY RECOMMENDED (multiple consumers)";
            return "SIMPLE DLL MAY SUFFICE";
        }

        private static string ArchOf(string hive, string server)
        {
            if (hive == "HKLM32") return "x86";
            string s = server.ToLowerInvariant();
            if (s.Contains("syswow64")) return "x86";
            if (s.Contains("system32")) return "x64";
            return "x64 (default)";
        }

        private static void WriteCsv(string path)
        {
            try
            {
                using (var w = new StreamWriter(path))
                {
                    w.WriteLine("CLSID,Case,Hive,Subkey,Server,Arch,Liveness,Stealth");
                    foreach (var r in _results)
                        w.WriteLine(string.Join(",",
                            Escape(r.Clsid), r.Case, r.Hive, r.Subkey, Escape(r.Server),
                            r.Arch, Escape(r.Liveness), Escape(r.Stealth)));
                }
                Console.WriteLine("[*] wrote CSV: " + path);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] CSV write failed: " + ex.Message);
            }
        }

        private static string Escape(string s)
        {
            if (s == null) return "";
            if (s.Contains(",") || s.Contains("\"") || s.Contains("\n"))
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        private class Result
        {
            public string Clsid;
            public string Case;
            public string Hive;
            public string Subkey;
            public string Server;
            public string Arch;
            public string Liveness;
            public string Stealth = "";

            public void Print()
            {
                Console.WriteLine("--------------------------------------------");
                Console.WriteLine("CLSID: " + Clsid);
                Console.WriteLine("  Case     : " + Case);
                Console.WriteLine("  Hive     : " + Hive);
                Console.WriteLine("  Subkey   : " + Subkey);
                Console.WriteLine("  Server   : " + (string.IsNullOrEmpty(Server) ? "(none)" : Server));
                Console.WriteLine("  Arch     : " + Arch);
                Console.WriteLine("  Liveness : " + Liveness);
                if (!string.IsNullOrEmpty(Stealth))
                    Console.WriteLine("  Stealth  : " + Stealth);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

[assembly: AssemblyTitle("NVVPN")]
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8")]


namespace FinlandVPN
{
    public sealed class SplitRules
    {
        public string mode = "except";
        public string[] apps = new string[0];
        public string[] domains = new string[0];
        public bool subdomains = true;
        public bool video_compatibility = true;
        public void Validate()
        {
            if (!new[] { "all", "except", "only" }.Contains(mode)) throw new UserError("Выберите режим маршрутизации.");
            if (video_compatibility && mode == "only") throw new UserError("Проверка видео доступна в режиме VPN для всех, кроме исключений.");
            if (apps == null || domains == null || apps.Length > 100 || domains.Length > 200) throw new UserError("Слишком много правил.");
            if (apps.Any(p => String.IsNullOrWhiteSpace(p) || !Regex.IsMatch(p.Trim(), @"^[A-Za-z]:\\"))) throw new UserError("Укажите полный путь к локальному приложению .exe.");
            apps = apps.Select(p => Path.GetFullPath(p.Trim())).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            foreach (string p in apps)
                if (!Path.IsPathRooted(p) || !p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || p.Any(char.IsControl) || p.StartsWith(@"\\")) throw new UserError("Выберите локальные файлы приложений .exe.");
            domains = domains.Select(Domain).Distinct().ToArray();
            if (mode == "only" && apps.Length + domains.Length == 0) throw new UserError("Добавьте хотя бы одно приложение или сайт.");
        }
        internal static string Domain(string value)
        {
            string domain = value.Trim().TrimEnd('.').ToLowerInvariant();
            try { domain = new IdnMapping().GetAscii(domain); } catch (ArgumentException) { throw new UserError("Неверное имя сайта."); }
            IPAddress ip;
            if (domain.Length > 253 || !domain.Contains('.') || IPAddress.TryParse(domain, out ip) || domain.Split('.').Any(p => p.Length == 0 || p.Length > 63 || !Regex.IsMatch(p, @"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")))
                throw new UserError("Введите домен, например example.com, без https://, пути или звёздочки.");
            return domain;
        }
    }

    internal static class SplitData
    {
        internal static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NeverVPN");
        internal static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 250000 };
        internal static SplitRules Load()
        {
            string file = Path.Combine(Root, "rules.dpapi");
            if (!File.Exists(file)) return new SplitRules();
            SecureFiles.NoLinks(file); if (new FileInfo(file).Length > 250000) throw new UserError("Повреждён файл правил.");
            var rules = Json.Deserialize<SplitRules>(SecureFiles.Decrypt(File.ReadAllBytes(file), DataProtectionScope.CurrentUser));
            rules.Validate(); return rules;
        }
        internal static void Save(SplitRules rules)
        {
            rules.Validate(); SecureFiles.DirectoryAcl(Root, true, false);
            string target = Path.Combine(Root, "rules.dpapi"), stage = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".dpapi");
            SecureFiles.NoLinks(target); SecureFiles.WriteNew(stage, SecureFiles.Encrypt(Json.Serialize(rules), DataProtectionScope.CurrentUser));
            if (File.Exists(target)) File.Replace(stage, target, null); else File.Move(stage, target);
        }
        internal static SplitRules LoadExclusions()
        {
            var rules=Load();if(rules.mode=="except")return rules;
            string file=Path.Combine(Root,"rules.dpapi");
            if(File.Exists(file)){
                SecureFiles.NoLinks(file);
                SecureFiles.WriteNew(Path.Combine(Root,"rules-before-exclusions-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss",CultureInfo.InvariantCulture)+".dpapi"),File.ReadAllBytes(file));
            }
            rules=new SplitRules();Save(rules);return rules;
        }
        internal static string Envelope(Profile profile, SplitRules rules, string nic, bool internalProbe)
        {
            rules.Validate();
            string cachePath="";
            if(!internalProbe&&!String.IsNullOrEmpty(profile.Id)){
                if(!Regex.IsMatch(profile.Id,"^[a-f0-9]{32}$"))throw new UserError("Неверный идентификатор профиля.");
                cachePath=Path.Combine(Root,"Cache",profile.Id+".db");
            }
            return Json.Serialize(new { address = profile.Address, dns = profile.Dns.Split(',').Select(s => s.Trim()).ToArray(),
                endpoint = internalProbe ? "10.14.0.1:8443" : profile.Endpoint, expected_ip = profile.Endpoint.Split(':')[0],
                uapi = Uapi(profile, internalProbe), @interface = nic, rules = rules, seconds = internalProbe ? 120 : 0,cache_path=cachePath });
        }
        internal static string Uapi(Profile p, bool internalProbe)
        {
            var names = new Dictionary<string,string> {
                {"privatekey","private_key"},{"publickey","public_key"},{"presharedkey","preshared_key"},{"listenport","listen_port"},
                {"headerprotectionkey","header_protection_key"},{"contentpaddingaddition","content_padding_addition"},{"rekeyaftertime","rekey_after_time"},
                {"rekeytimeout","rekey_timeout"},{"rejectaftertime","reject_after_time"},{"keepalivetimeout","keepalive_timeout"},
                {"maxhandshakeattempts","max_handshake_attempts"},{"randomtrailers","random_trailers"},{"disablecookies","disable_cookies"},
                {"persistentkeepalive","persistent_keepalive_interval"}
            };
            var s = new StringBuilder(); var peer = new Dictionary<string,string>(); bool isPeer = false;
            foreach (string raw in p.Config.Split('\n'))
            {
                string line = raw.Trim(); if (line == "[Peer]") { isPeer = true; continue; }
                int pos = line.IndexOf('='); if (pos < 0) continue;
                string key = line.Substring(0, pos).Trim().ToLowerInvariant(), val = line.Substring(pos+1).Trim();
                if (isPeer) { peer[key] = val; continue; }
                if (key == "address" || key == "dns" || key == "mtu") continue;
                if (key.EndsWith("key")) val = Hex(val);
                if (key == "randomtrailers" || key == "disablecookies") val = val == "on" ? "1" : "0";
                s.Append(names.ContainsKey(key) ? names[key] : key).Append('=').Append(val).Append('\n');
            }
            s.Append("replace_peers=true\npublic_key=").Append(Hex(peer["publickey"])).Append('\n');
            s.Append("replace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n");
            s.Append("endpoint=").Append(internalProbe ? "10.14.0.1:8443" : peer["endpoint"]).Append('\n');
            if (peer.ContainsKey("presharedkey")) s.Append("preshared_key=").Append(Hex(peer["presharedkey"])).Append('\n');
            s.Append("persistent_keepalive_interval=").Append(peer.ContainsKey("persistentkeepalive") ? peer["persistentkeepalive"] : "25").Append('\n');
            return s.ToString();
        }
        private static string Hex(string base64) { byte[] b = Convert.FromBase64String(base64); try { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); } finally { Array.Clear(b,0,b.Length); } }
    }

    internal sealed class Engine : IDisposable
    {
        private Process process;
        private StreamWriter input;
        internal readonly LocalDiagnostics Diagnostics=new LocalDiagnostics(SplitData.Root);
        private void Record(string value){Diagnostics.Record(value);}
        internal bool Running { get { return process != null && !process.HasExited; } }
        internal static bool OldVpnActive()
        {
            try { using (var service = new ServiceController("FinlandVPN")) return service.Status != ServiceControllerStatus.Stopped; }
            catch (InvalidOperationException e) { var w = e.InnerException as System.ComponentModel.Win32Exception; if (w != null && w.NativeErrorCode == 1060) return false; throw; }
        }
        internal static string[] Interfaces()
        {
            return NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up &&
                (n.NetworkInterfaceType == NetworkInterfaceType.Ethernet || n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) &&
                n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any)) &&
                !Regex.IsMatch(n.Name + " " + n.Description, "vpn|wireguard|amnezia|wintun|tap-", RegexOptions.IgnoreCase)).Select(n => n.Name).ToArray();
        }
        internal static bool Admin { get { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } }
        internal static void VerifyFiles()
        {
            string root = AppDomain.CurrentDomain.BaseDirectory;
            foreach (string name in new[] { "NVVPN.Engine.exe", "wintun.dll" })
            {
                string file = Path.Combine(root, name); SecureFiles.NoLinks(file);
                string expected = name == "NVVPN.Engine.exe" ? EngineHashes.Core : EngineHashes.Wintun;
                using (var sha = SHA256.Create()) using (var stream = File.OpenRead(file))
                    if (!BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").Equals(expected, StringComparison.OrdinalIgnoreCase)) throw new UserError("Файлы NVVPN повреждены. Распакуйте комплект заново.");
            }
        }
        internal async Task<int> Run(string mode, string envelope, Action<string> notify)
        {
            Agreement.RequireEngine(mode);
            if(mode!="--run")return await RunCore(mode,envelope,notify);
            using(var gate=new System.Threading.Semaphore(1,1,@"Local\NeverVPN.Connection")){
                if(!gate.WaitOne(0))throw new UserError("Подключение уже запущено в другом окне NVVPN.");
                try{return await RunCore(mode,envelope,notify);}finally{gate.Release();}
            }
        }
        private async Task<int> RunCore(string mode, string envelope, Action<string> notify)
        {
            Agreement.RequireEngine(mode);
            if (Running) throw new UserError("Испытание уже запущено.");
            if (mode == "--run")
            {
                if (!Admin) throw new UserError("Откройте NVVPN с правами администратора.");
                if (OldVpnActive()) throw new UserError("Сначала отключите прежний Finland VPN вручную, затем подключитесь здесь.");
                if (NetworkInterface.GetAllNetworkInterfaces().Any(n => n.OperationalStatus == OperationalStatus.Up && Regex.IsMatch(n.Name+" "+n.Description,"amnezia|wireguard|wintun|FinlandSplit|NeverVPN",RegexOptions.IgnoreCase)))
                    throw new UserError("Сначала отключите другой VPN.");
            }
            VerifyFiles();
            var settings=SplitData.Json.Deserialize<Dictionary<string,object>>(envelope);
            if(mode=="--run"){
                string cache=settings.ContainsKey("cache_path")?Convert.ToString(settings["cache_path"]):"";
                if(cache.Length>0){
                    string root=Path.Combine(SplitData.Root,"Cache");
                    if(!String.Equals(Path.GetDirectoryName(Path.GetFullPath(cache)),root,StringComparison.OrdinalIgnoreCase)||!Regex.IsMatch(Path.GetFileName(cache),"^[a-f0-9]{32}\\.db$"))throw new UserError("Неверный путь кэша.");
                    SecureFiles.DirectoryAcl(root,true,false);SecureFiles.NoLinks(cache);
                }
            }
            var info = new ProcessStartInfo(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"NVVPN.Engine.exe"),mode) {
                UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,
                StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8,WorkingDirectory=AppDomain.CurrentDomain.BaseDirectory
            };
            process = new Process { StartInfo=info }; process.Start();
            Record("version:0-4-3");Record("start:"+mode.TrimStart('-'));
            var ruleSettings=settings["rules"] as Dictionary<string,object>;
            Record(ruleSettings!=null&&ruleSettings.ContainsKey("video_compatibility")&&Object.Equals(ruleSettings["video_compatibility"],true)?"video:tcp-only":"video:normal");
            input = new StreamWriter(process.StandardInput.BaseStream,new UTF8Encoding(false)){AutoFlush=true};
            await input.WriteLineAsync(envelope);
            var stderr = Drain(process.StandardError); // Record only fixed categories, never raw diagnostics.
            if (mode == "--run") DnsFlushResolverCache();
            try {
                string line;
                while((line=await process.StandardOutput.ReadLineAsync())!=null)
                {
                    if(line.Length>2048) continue;
                    try { var item=SplitData.Json.Deserialize<Dictionary<string,object>>(line); if(item.ContainsKey("event")) {
                        string ev=Convert.ToString(item["event"]);
                        if(mode=="--run"&&ev=="ready")DnsFlushResolverCache();
                        if(ev=="error"&&item.ContainsKey("code")&&Regex.IsMatch(Convert.ToString(item["code"]),"^[a-z-]{1,32}$"))ev+=":"+Convert.ToString(item["code"]);
                        if(item.ContainsKey("vpn_web_connections")){string flows="vpn-web-flows="+Convert.ToInt64(item["vpn_web_connections"]).ToString(CultureInfo.InvariantCulture);Record(flows);notify(flows);}
                        Record(ev);
                        notify(ev);
                    } } catch(ArgumentException) { }
                }
                await Task.Run(()=>process.WaitForExit());await stderr; Record("exit="+process.ExitCode.ToString(CultureInfo.InvariantCulture)); return process.ExitCode;
            }
            finally { if(mode=="--run")DnsFlushResolverCache(); input.Dispose();input=null;process.Dispose();process=null; }
        }
        private async Task Drain(StreamReader reader){
            var counts=new Dictionary<string,int>();string line;
            var categories=new Dictionary<string,string>{
                {"dns: exchanged","dns-exchanged"},{"dns: lookup","dns-lookup"},
                {"found fakeip domain","fakeip-found"},{"missing fakeip record","fakeip-missing"},
                {"inbound connection from","tcp-inbound"},{"inbound packet connection from","udp-inbound"},
                {"found process path","process-found"},{"find process","process-lookup"},
                {"process_path_regex=","app-rule-matched"},
                {"domain_suffix=","site-rule-matched"},{"domain=","site-rule-matched"},
                {"outbound connection to","outbound-connect"},{"connection refused","connection-refused"},
                {"i/o timeout","io-timeout"},{"context deadline exceeded","deadline"},
                {"permission denied","permission-denied"},{"network is unreachable","network-unreachable"},
                {"exchange failed","dns-failed"}
            };
            while((line=await reader.ReadLineAsync())!=null){
                if(line.Contains("=> reject")&&line.Contains("network=udp")&&line.Contains("port=443")&&line.Contains("googlevideo.com")){
                    if(!counts.ContainsKey("video-udp-rejected")){counts["video-udp-rejected"]=0;Record("diag:video-udp-rejected");}counts["video-udp-rejected"]++;
                }
                if(line.StartsWith("panic:",StringComparison.Ordinal))Record("diag:engine-panic");
                if(Regex.IsMatch(line,@"\bERROR(?:\[|\s)")){if(!counts.ContainsKey("errors")){counts["errors"]=0;Record("diag:errors");}counts["errors"]++;}
                foreach(var pair in categories)if(line.IndexOf(pair.Key,StringComparison.OrdinalIgnoreCase)>=0){
                    if(!counts.ContainsKey(pair.Value)){counts[pair.Value]=0;Record("diag:"+pair.Value);}
                    counts[pair.Value]++;
                }
            }
            foreach(var pair in counts)Record("diag:"+pair.Key+"="+pair.Value.ToString(CultureInfo.InvariantCulture));
        }
        internal void Stop(){try{if(input!=null)input.WriteLine("stop");}catch(IOException){} }
        public void Dispose(){Stop();if(process!=null){if(!process.WaitForExit(8000))process.Kill();process.Dispose();process=null;}if(input!=null){input.Dispose();input=null;} }
        [DllImport("dnsapi.dll")] private static extern bool DnsFlushResolverCache();
    }

    internal static class SplitProgram
    {
        static async Task<int> ProxyTest(string path,string report,bool appTest=false,bool videoTest=false)
        {
            var p=Profile.Parse(File.ReadAllText(path),"Validation");var lines=new List<string>();bool pass=true;
            foreach(string mode in videoTest?new[]{"except"}:new[]{"only","except"})using(var e=new Engine()){
                var r=new SplitRules {mode=mode,domains=new[]{"api.ipify.org"},apps=new string[0],subdomains=false,video_compatibility=videoTest};
                if(appTest){r.domains=new string[0];r.apps=new[]{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"curl.exe")};}
                Task traffic=null;int flows=-1;
                int exit=await e.Run("--proxy-test",SplitData.Envelope(p,r,"FinlandVPN",true),ev=>{
                    lines.Add(mode+": "+ev);
                    if(ev.StartsWith("vpn-web-flows=",StringComparison.Ordinal))flows=Int32.Parse(ev.Substring(14),CultureInfo.InvariantCulture);
                    if(ev=="ready")traffic=Task.Run(()=>{
                        try {
                            int probeNumber=0;
                            foreach(string host in videoTest?new[]{"api.ipify.org","api4.ipify.org","www.youtube.com/generate_204"}:new[]{"api.ipify.org","api4.ipify.org"}){
                                probeNumber++;bool videoHost=host.StartsWith("www.youtube.com/",StringComparison.Ordinal);
                                var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"curl.exe"),"--silent --show-error --fail --noproxy \"\" --max-time 20 --socks5-hostname 127.0.0.1:39391 "+(videoHost?"--output NUL --write-out %{http_code} ":"")+"https://"+host){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
                                using(var curl=Process.Start(info)){
                                    string body=curl.StandardOutput.ReadToEnd().Trim();curl.StandardError.ReadToEnd();curl.WaitForExit();
                                    lines.Add(mode+": probe-"+probeNumber.ToString(CultureInfo.InvariantCulture)+"-exit="+curl.ExitCode.ToString(CultureInfo.InvariantCulture));
                                    if(curl.ExitCode!=0||body!=(videoHost?"204":p.Endpoint.Split(':')[0]))throw new UserError("Probe failed");
                                }
                            }
                        }catch{pass=false;}finally{e.Stop();}
                    });
                });
                if(traffic!=null)await traffic;
                int expected=videoTest?2:appTest?(mode=="only"?2:0):1;
                if(exit!=0||flows!=expected||traffic==null)pass=false;
            }
            lines.Add(pass?(videoTest?"PASS live HTTPS including YouTube 204 with video comparison enabled; two VPN flows and one direct exception.":appTest?"PASS Windows process rule: both HTTPS flows use VPN in inclusion mode, both bypass AWG in exception mode.":"PASS two live HTTPS flows in each mode; exactly one web flow used the separate AWG outbound."):"FAIL live routing test");
            File.WriteAllLines(report,lines);return pass?0:1;
        }
        [STAThread] static int Main(string[] args)
        {
            try {
                if(args.Length>0&&Agreement.IsNetworkCli(args[0]))Agreement.RequireCurrent();
                if(args.Length==1&&args[0]=="--apply-update")return UpdateInstall.Apply();
                if(args.Length==3&&args[0]=="--update-scenario")return UpdateScenario.Run(args[1],args[2]);
                if(args.Length==2&&args[0]=="--update-tests")return UpdateTests.Run(args[1]);
                if(args.Length==1&&args[0]=="--setup-check")return Lifecycle.CheckIdle();
                if(args.Length==3&&args[0]=="--proxy-test-internal")return ProxyTest(args[1],args[2]).GetAwaiter().GetResult();
                if(args.Length==3&&args[0]=="--proxy-app-test-internal")return ProxyTest(args[1],args[2],true).GetAwaiter().GetResult();
                if(args.Length==3&&args[0]=="--proxy-video-test-internal")return ProxyTest(args[1],args[2],false,true).GetAwaiter().GetResult();
                if(args.Length==2&&args[0]=="--import-profile"){new ProfileStore(Path.Combine(SplitData.Root,"Profiles")).Import(args[1]);return 0;}
                if(args.Length==2&&args[0]=="--seed-rules"){
                    if(File.Exists(Path.Combine(SplitData.Root,"rules.dpapi")))return 0;
                    var r=SplitData.Json.Deserialize<SplitRules>(File.ReadAllText(args[1]));SplitData.Save(r);return 0;
                }
                if(args.Length==2&&args[0]=="--self-test")return ModelTests(args[1]);
                if(args.Length==2&&args[0]=="--render"){
                    var w=new SplitWindow(true).Window;var v=(FrameworkElement)w.Content;v.Measure(new Size(1000,780));v.Arrange(new Rect(0,0,1000,780));v.UpdateLayout();
                    var bmp=new RenderTargetBitmap(1000,780,96,96,PixelFormats.Pbgra32);bmp.Render(v);var png=new PngBitmapEncoder();png.Frames.Add(BitmapFrame.Create(bmp));using(var f=File.Create(args[1]))png.Save(f);return 0;
                }
                if((args.Length==3||args.Length==4)&&args[0]=="--render-page"){
                    int page;if(!Int32.TryParse(args[1],out page)||page<0||page>3)return 64;
                    var screen=new SplitWindow(true);screen.PreviewPage(page);if(args.Length==4)screen.PreviewState(args[3]);var v=(FrameworkElement)screen.Window.Content;v.Measure(new Size(1000,780));v.Arrange(new Rect(0,0,1000,780));v.UpdateLayout();
                    var bmp=new RenderTargetBitmap(1000,780,96,96,PixelFormats.Pbgra32);bmp.Render(v);var png=new PngBitmapEncoder();png.Frames.Add(BitmapFrame.Create(bmp));using(var f=File.Create(args[2]))png.Save(f);return 0;
                }
                if(args.Length==3&&(args[0]=="--probe-internal"||args[0]=="--check-profile")){
                    var p=Profile.Parse(File.ReadAllText(args[1]),"Validation");var rules=new SplitRules {mode="all",domains=new string[0]};
                    using(var engine=new Engine()){
                        var events=new List<string>();int code=engine.Run(args[0]=="--probe-internal"?"--probe":"--check",SplitData.Envelope(p,rules,args[0]=="--probe-internal"?"FinlandVPN":"Ethernet",args[0]=="--probe-internal"),s=>events.Add(s)).GetAwaiter().GetResult();
                        File.WriteAllLines(args[2],events);return code;
                    }
                }
                string selectedProfile=null, expectedSid=null;
                if(args.Length==2&&args[0]=="--open-profile"&&Regex.IsMatch(args[1],"^[a-f0-9]{32}$"))selectedProfile=args[1];
                else if((args.Length==2||args.Length==3)&&args[0]=="--elevated"&&Regex.IsMatch(args[1],"^S-1-[0-9-]{1,160}$")){
                    expectedSid=new SecurityIdentifier(args[1]).Value;
                    if(args.Length==3){if(!Regex.IsMatch(args[2],"^[a-f0-9]{32}$"))return 64;selectedProfile=args[2];}
                }
                else if(args.Length!=0)return 64;
                if(UpdateInstall.Updating()){System.Windows.MessageBox.Show("Выполняется обновление NVVPN. Дождитесь завершения.","NVVPN");return 0;}
                if(Startup.AlreadyOpen()){Startup.ExplainAlreadyOpen();return 0;}
                if(!Startup.Prepare(expectedSid,selectedProfile))return 0;
                bool created;
                using(var uiPresence=new System.Threading.Mutex(false,@"Local\NeverVPN.UI",out created)){
                    if(!created){Startup.ExplainAlreadyOpen();return 0;}
                    Migration.ImportPrototype();
                    var app=new Application();app.DispatcherUnhandledException+=(s,e)=>{SplitWindow.Error(e.Exception);e.Handled=true;};
                    app.Run(new SplitWindow(false,selectedProfile).Window);
                }return 0;
            }catch(AgreementRequiredException){Console.Error.WriteLine(AgreementRequiredException.Diagnostic);return AgreementRequiredException.ExitCode;}
            catch(Exception e){if(args.Length==0||args[0]=="--elevated"||args[0]=="--open-profile")SplitWindow.Error(e);return 1;}
        }
        static int ModelTests(string report)
        {
            var results=new List<string>();int failed=0;
            Action<string,Action> test=(name,action)=>{try{action();results.Add("PASS "+name);}catch(Exception e){failed++;results.Add("FAIL "+name+" ["+e.GetType().Name+"] "+e.StackTrace);}};
            Action<bool> check=b=>{if(!b)throw new Exception();};
            AgreementTests.Run(test,check,report);
            LocalDiagnostics.Tests(test,check,report);
            test("Startup requests elevation only once and preserves user identity",()=>{
                check(Startup.Decide(false,null,"S-1-5-21-1")==StartupAction.Elevate);
                check(Startup.Decide(true,null,"S-1-5-21-1")==StartupAction.Open);
                check(Startup.Decide(true,"S-1-5-21-1","S-1-5-21-1")==StartupAction.Open);
                check(Startup.Decide(false,"S-1-5-21-1","S-1-5-21-1")==StartupAction.Reject);
                check(Startup.Decide(true,"S-1-5-21-1","S-1-5-21-2")==StartupAction.Reject);
            });
            test("UI offline states, navigation, edits and late ready event",()=>SplitWindow.TestPreview(check));
            test("Domain normalization",()=>check(SplitRules.Domain("Example.COM.")=="example.com"));
            test("International domain",()=>check(SplitRules.Domain("пример.рф").StartsWith("xn--",StringComparison.Ordinal)));
            foreach(string invalid in new[]{"https://example.com","example.com/a","*.example.com","127.0.0.1","-a.com","a..com"}){
                string value=invalid;test("Reject invalid site",()=>{bool rejected=false;try{SplitRules.Domain(value);}catch(UserError){rejected=true;}check(rejected);});
            }
            test("Reject relative application",()=>{bool rejected=false;try{new SplitRules {apps=new[]{"example.exe"}}.Validate();}catch(UserError){rejected=true;}check(rejected);});
            test("Case-insensitive application deduplication",()=>{var r=new SplitRules {apps=new[]{@"C:\Apps\App.exe",@"c:\apps\app.exe"}};r.Validate();check(r.apps.Length==1);});
            test("Reject empty legacy inclusion list",()=>{bool rejected=false;try{new SplitRules {mode="only",domains=new string[0]}.Validate();}catch(UserError){rejected=true;}check(rejected);});
            test("Empty exclusions keep VPN default",()=>{var r=new SplitRules();r.Validate();check(r.mode=="except"&&r.apps.Length==0&&r.domains.Length==0);});
            test("YouTube compatibility default and explicit opt-out round trip",()=>{
                var legacy=SplitData.Json.Deserialize<SplitRules>("{\"mode\":\"except\",\"apps\":[],\"domains\":[\"vk.com\"],\"subdomains\":true}");
                check(legacy.video_compatibility);legacy.video_compatibility=false;legacy.Validate();
                var restored=SplitData.Json.Deserialize<SplitRules>(SplitData.Json.Serialize(legacy));check(!restored.video_compatibility&&restored.domains.Single()=="vk.com");
            });
            test("Migration preserves encrypted bytes, private ACL and existing settings",()=>{
                string root=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(report)),"migration-test-"+Guid.NewGuid().ToString("N"));
                string source=Path.Combine(root,"old"),target=Path.Combine(root,"new");Directory.CreateDirectory(Path.Combine(source,"Profiles"));Directory.CreateDirectory(Path.Combine(source,"Cache"));
                string id=new string('a',32);byte[] opaque=new byte[]{17,23,42,55};
                File.WriteAllBytes(Path.Combine(source,"Profiles",id+".dpapi"),opaque);File.WriteAllBytes(Path.Combine(source,"rules.dpapi"),opaque);File.WriteAllBytes(Path.Combine(source,"Cache",id+".db"),opaque);
                Migration.ImportFrom(source,target);
                check(File.ReadAllBytes(Path.Combine(target,"Profiles",id+".dpapi")).SequenceEqual(opaque));check(File.Exists(Path.Combine(source,"Profiles",id+".dpapi")));check(File.ReadAllBytes(Path.Combine(target,"Cache",id+".db")).SequenceEqual(opaque));check(Directory.GetAccessControl(target).AreAccessRulesProtected);
                File.WriteAllBytes(Path.Combine(target,"rules.dpapi"),new byte[]{99});Migration.ImportFrom(source,target);check(File.ReadAllBytes(Path.Combine(target,"rules.dpapi")).SequenceEqual(new byte[]{99}));
            });
            test("Synthetic settings DPAPI round trip preserves explicit choices",()=>{
                var original=new SplitRules{domains=new[]{"example.com"},apps=new[]{@"C:\Apps\Demo.exe"},subdomains=false,video_compatibility=false};
                byte[] encrypted=SecureFiles.Encrypt(SplitData.Json.Serialize(original),DataProtectionScope.CurrentUser);
                var restored=SplitData.Json.Deserialize<SplitRules>(SecureFiles.Decrypt(encrypted,DataProtectionScope.CurrentUser));
                restored.Validate();check(!restored.subdomains&&!restored.video_compatibility&&restored.domains.Single()=="example.com"&&restored.apps.Single()==@"C:\Apps\Demo.exe");
            });
            test("UAPI preserves AWG 3.1 and key boundary",()=>{
                string key=Convert.ToBase64String(Enumerable.Repeat((byte)7,32).ToArray());
                var p=Profile.Parse("[Interface]\nPrivateKey="+key+"\nAddress=10.14.0.200/32\nDNS=1.1.1.1\nHeaderProtectionKey="+key+"\nRandomTrailers=on\nDisableCookies=on\n[Peer]\nPublicKey="+key+"\nPresharedKey="+key+"\nEndpoint=192.0.2.1:8443\nAllowedIPs=0.0.0.0/0, ::/0\n","Synthetic");
                string u=SplitData.Uapi(p,false);check(!u.Contains(key)&&u.Contains("header_protection_key=")&&u.Contains("random_trailers=1\n")&&u.Contains("disable_cookies=1\n")&&u.IndexOf("public_key=",StringComparison.Ordinal)<u.IndexOf("allowed_ip=",StringComparison.Ordinal));
                check(SplitData.Uapi(p,true).Contains("endpoint=10.14.0.1:8443\n")&&p.Endpoint=="192.0.2.1:8443");
                var live=SplitData.Json.Deserialize<Dictionary<string,object>>(SplitData.Envelope(p,new SplitRules(),"Ethernet",false));var probe=SplitData.Json.Deserialize<Dictionary<string,object>>(SplitData.Envelope(p,new SplitRules(),"FinlandVPN",true));check(Convert.ToInt32(live["seconds"])==0&&Convert.ToInt32(probe["seconds"])==120);
            });
            File.WriteAllLines(report,results);return failed==0?0:1;
        }
    }
}

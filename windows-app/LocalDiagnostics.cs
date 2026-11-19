using System;
using System.IO;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace FinlandVPN
{
    internal sealed class LocalDiagnostics
    {
        internal const int MaxBytes=1048576;
        readonly string root;
        readonly object gate=new object();
        bool enabled;
        internal LocalDiagnostics(string directory){root=Path.GetFullPath(directory);}
        internal string FilePath { get { return Path.Combine(root,"Diagnostics","events.log"); } }
        internal bool Enabled { get { lock(gate)return enabled; } set { lock(gate)enabled=value; } }
        internal void Record(string value)
        {
            lock(gate){
                if(!enabled||value==null||!Regex.IsMatch(value,"^[a-z0-9=:-]{1,80}$"))return;
                try{
                    string folder=Path.GetDirectoryName(FilePath);SecureFiles.DirectoryAcl(folder,true,false);SecureFiles.NoLinks(FilePath);
                    string line=DateTime.UtcNow.ToString("o",CultureInfo.InvariantCulture)+" "+value+Environment.NewLine;
                    if(File.Exists(FilePath)&&new FileInfo(FilePath).Length+Encoding.UTF8.GetByteCount(line)>MaxBytes)
                        File.WriteAllText(FilePath,"",new UTF8Encoding(false));
                    File.AppendAllText(FilePath,line,new UTF8Encoding(false));
                }catch(IOException){}catch(UnauthorizedAccessException){}catch(UserError){}catch(System.Security.SecurityException){}
            }
        }
        internal void Clear()
        {
            lock(gate){
                // Only diagnostic files; never profiles, consent, rules, or DNS cache.
                foreach(string path in new[]{FilePath,Path.Combine(root,"test-events.txt")}){
                    SecureFiles.NoLinks(path);if(File.Exists(path))File.Delete(path);
                }
            }
        }
        internal static void Tests(Action<string,Action> test,Action<bool> check,string report)
        {
            string directory=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(report)),"diagnostics-tests-"+Guid.NewGuid().ToString("N"));
            var log=new LocalDiagnostics(directory);
            test("Diagnostics disabled by default and creates no files",()=>{log.Record("ready");check(!log.Enabled&&!Directory.Exists(directory));});
            test("Diagnostics explicit enable, category filter and disable",()=>{
                log.Enabled=true;log.Record("ready");check(File.ReadAllText(log.FilePath).Contains("ready"));
                string first=File.ReadAllText(log.FilePath);log.Record("https://private.example/path?token=synthetic");check(File.ReadAllText(log.FilePath)==first);
                log.Enabled=false;log.Record("stopping");check(File.ReadAllText(log.FilePath)==first);
                check(!new LocalDiagnostics(directory).Enabled);
            });
            test("Diagnostics size bound and clear preserve other user data",()=>{
                File.WriteAllText(log.FilePath,new string('x',MaxBytes));log.Enabled=true;log.Record("ready");check(new FileInfo(log.FilePath).Length<=MaxBytes);
                string sentinel=Path.Combine(directory,"rules.dpapi");File.WriteAllText(sentinel,"synthetic sentinel");
                File.WriteAllText(Path.Combine(directory,"test-events.txt"),"synthetic legacy log");log.Clear();
                check(!File.Exists(log.FilePath)&&!File.Exists(Path.Combine(directory,"test-events.txt"))&&File.ReadAllText(sentinel)=="synthetic sentinel");
            });
        }
    }
}

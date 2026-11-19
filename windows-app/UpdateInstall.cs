using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Windows;
using Microsoft.Win32;

namespace FinlandVPN
{
    internal sealed class UpdateRequest
    {
        public string original {get;set;}
        public string version {get;set;}
        public string sid {get;set;}
        public int parent {get;set;}
        public long parentStarted {get;set;}
        public string originalHash {get;set;}
    }
    internal static class UpdateInstall
    {
        internal const string GateName=@"Global\NVVPN.Update";
        internal static readonly string[] Payload={"NVVPN.exe","NVVPN.exe.config","NVVPN.Engine.exe","wintun.dll","NVVPN.Engine.exe.sha256","wintun.dll.sha256","README.txt","THIRD-PARTY-NOTICES.txt","DEPENDENCIES.json","NVVPN-Sources.zip","SHA256SUMS.txt"};
        internal static bool Updating(){try{using(Mutex.OpenExisting(GateName))return true;}catch(WaitHandleCannotBeOpenedException){return false;}catch(UnauthorizedAccessException){return true;}}
        internal static string NewStage()
        {
            if(!Engine.Admin)throw new UserError("Для подготовки установки откройте NVVPN с правами той же учётной записи Windows.");
            string parent=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"NVVPN","Updates");
            SecureFiles.DirectoryAcl(Path.GetDirectoryName(parent),false,false);SecureFiles.DirectoryAcl(parent,false,false);string stage=Path.Combine(parent,Guid.NewGuid().ToString("N"));SecureFiles.DirectoryAcl(stage,false,false);return stage;
        }
        internal static bool Installed(string directory)
        {
            string full=Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);SecureFiles.NoLinks(full);
            using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
            using(var key=machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A79BF034-CE27-48CE-91D6-1024A2AE998A}_is1")){
                string path=key==null?null:key.GetValue("InstallLocation") as string;
                if(String.IsNullOrEmpty(path))return false;
                string programs=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                bool protectedPath=String.Equals(full,Path.Combine(programs,"NVVPN"),StringComparison.OrdinalIgnoreCase)||String.Equals(full,Path.Combine(programs,"NeverVPN"),StringComparison.OrdinalIgnoreCase);
                return protectedPath&&String.Equals(full,Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar),StringComparison.OrdinalIgnoreCase);
            }
        }
        internal static Process Launch(string stage)
        {
            string original=Assembly.GetExecutingAssembly().Location,helper=Path.Combine(stage,"NVVPN.Update.exe");SecureFiles.NoLinks(original);
            File.Copy(original,helper,false);if(Updates.HashFile(original)!=Updates.HashFile(helper))throw new UserError("Не удалось подготовить программу обновления.");
            using(var parent=Process.GetCurrentProcess()){
                var r=new UpdateRequest {original=original,version=Updates.CurrentVersion,sid=WindowsIdentity.GetCurrent().User.Value,parent=parent.Id,parentStarted=parent.StartTime.ToUniversalTime().Ticks,originalHash=Updates.HashFile(original)};
                SecureFiles.WriteNew(Path.Combine(stage,"request.json"),System.Text.Encoding.UTF8.GetBytes(Updates.Json().Serialize(r)));
            }
            var process=Process.Start(new ProcessStartInfo(helper,"--apply-update"){UseShellExecute=false,WorkingDirectory=stage,CreateNoWindow=true});
            if(process==null)throw new UserError("Не удалось запустить установку.");return process;
        }
        internal static Dictionary<string,string> Snapshot(string source,string destination,bool app,bool adminOnly=false)
        {
            SecureFiles.DirectoryAcl(destination,!adminOnly,false);var hashes=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            if(!Directory.Exists(source))return hashes;SecureFiles.NoLinks(source);
            if(app){foreach(string name in Payload){string file=Path.Combine(source,name);if(!File.Exists(file))throw new UserError("Неполный текущий комплект. Установка отменена.");CopySnapshot(file,destination,name,hashes,adminOnly);}}
            else CopyTree(source,destination,"",hashes,adminOnly);
            SecureFiles.WriteNew(Path.Combine(destination,"backup-manifest.json"),System.Text.Encoding.UTF8.GetBytes(Updates.Json().Serialize(hashes)));return hashes;
        }
        static void CopyTree(string source,string destination,string relative,Dictionary<string,string> hashes,bool adminOnly)
        {
            string directory=Path.Combine(source,relative);SecureFiles.NoLinks(directory);
            foreach(string file in Directory.GetFiles(directory)){
                string name=Path.Combine(relative,Path.GetFileName(file));if(name=="backup-manifest.json")throw new UserError("Конфликт имени резервной копии.");
                if(new FileInfo(file).Length>268435456)throw new UserError("Файл пользовательских данных слишком велик для резервной копии.");CopySnapshot(file,destination,name,hashes,adminOnly);
            }
            foreach(string child in Directory.GetDirectories(directory))CopyTree(source,destination,Path.Combine(relative,Path.GetFileName(child)),hashes,adminOnly);
        }
        static void CopySnapshot(string file,string destination,string relative,Dictionary<string,string> hashes,bool adminOnly)
        {
            SecureFiles.NoLinks(file);string target=Path.Combine(destination,relative);SecureFiles.DirectoryAcl(Path.GetDirectoryName(target),!adminOnly,false);
            File.Copy(file,target,false);string hash=Updates.HashFile(file);if(Updates.HashFile(target)!=hash)throw new UserError("Ошибка проверки резервной копии.");hashes.Add(relative,hash);
        }
        internal static void RestorePayload(string backup,string destination,Dictionary<string,string> hashes)
        {
            foreach(string name in Payload){if(!hashes.ContainsKey(name)||Updates.HashFile(Path.Combine(backup,name))!=hashes[name])throw new UserError("Резервная копия повреждена. Автоматическое восстановление отменено.");}
            foreach(string name in Payload){string target=Path.Combine(destination,name);SecureFiles.NoLinks(target);File.Copy(Path.Combine(backup,name),target,true);if(Updates.HashFile(target)!=hashes[name])throw new UserError("Не удалось восстановить прежний комплект.");}
        }
        internal static void VerifyPayload(string directory)
        {
            string sums=Path.Combine(directory,"SHA256SUMS.txt");SecureFiles.NoLinks(sums);
            if(new FileInfo(sums).Length>16384)throw new UserError("Неверный список файлов установленного комплекта.");
            var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(string line in File.ReadAllLines(sums)){
                if(line.Length<67||line.Substring(64,2)!="  ")throw new UserError("Неверный список контрольных сумм.");
                string name=line.Substring(66);if(name=="SHA256SUMS.txt"||!Payload.Contains(name)||!seen.Add(name)||Updates.HashFile(Path.Combine(directory,name))!=line.Substring(0,64))throw new UserError("Файлы нового комплекта не прошли проверку.");
            }
            if(seen.Count!=Payload.Length-1)throw new UserError("Новый комплект неполон.");
        }
        internal static void CompleteInstalled(int code,string directory,string backup,Dictionary<string,string> hashes,string version,bool idle)
        {
            try{
                if(code!=0||!idle)throw new UserError("Установщик не завершил обновление.");
                VerifyPayload(directory);
                if(FileVersionInfo.GetVersionInfo(Path.Combine(directory,"NVVPN.exe")).ProductVersion!=version)throw new UserError("Новая версия не подтверждена.");
            }catch{
                if(idle){RestorePayload(backup,directory,hashes);throw new UserError("Обновление не завершено (код "+code+"). Прежние файлы восстановлены. Регистрацию Inno при необходимости исправьте прежним установщиком. Резервная копия сохранена.");}
                throw new UserError("Обнаружен работающий клиент. Восстановление отложено; используйте резервную копию после его завершения.");
            }
        }
        internal static string ExtractPortable(string zip,string destination,string version)
        {
            if(Directory.Exists(destination))throw new UserError("Папка новой версии уже существует; выберите новое расположение.");
            SecureFiles.DirectoryAcl(destination,true,false);string prefix="NVVPN-"+version+"/";var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);long size=0;
            using(var archive=ZipFile.OpenRead(zip)){
                if(archive.Entries.Count!=Payload.Length)throw new UserError("Неполный переносной комплект.");
                foreach(var entry in archive.Entries){
                    string name=entry.FullName.StartsWith(prefix,StringComparison.Ordinal)?entry.FullName.Substring(prefix.Length):"";
                    if(!Payload.Contains(name)||!seen.Add(name)||((entry.ExternalAttributes>>16)&0xF000)==0xA000)throw new UserError("Небезопасный путь или состав ZIP.");
                    size+=entry.Length;if(size>4294967296L||entry.Length>2147483648L)throw new UserError("Распакованный комплект слишком велик.");
                    string target=Path.Combine(destination,name);SecureFiles.NoLinks(target);using(var input=entry.Open())using(var output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None)){byte[] buffer=new byte[65536];long count=0;int n;while((n=input.Read(buffer,0,buffer.Length))>0){count+=n;if(count>entry.Length)throw new UserError("Неверный размер ZIP.");output.Write(buffer,0,n);}if(count!=entry.Length)throw new UserError("ZIP обрезан.");output.Flush(true);}
                }
            }return Path.Combine(destination,"NVVPN.exe");
        }
        internal static int ExecuteInstaller(string installer)
        {
            // Only the caller's already-verified, held-open executable. No arbitrary arguments from release metadata.
            using(var process=Process.Start(new ProcessStartInfo(installer,"/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"){UseShellExecute=false,WorkingDirectory=Path.GetDirectoryName(installer)})){
                if(process==null)throw new UserError("Не удалось запустить установщик.");process.WaitForExit();return process.ExitCode;
            }
        }
        internal static int Apply()
        {
            string stage=AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);string backup=null;bool success=false;
            try{
                if(!Engine.Admin)throw new UserError("Установка требует прав администратора исходной учётной записи.");
                string parent=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"NVVPN","Updates");
                if(!String.Equals(Path.GetDirectoryName(stage),parent,StringComparison.OrdinalIgnoreCase)||!System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(stage),"^[a-f0-9]{32}$"))throw new UserError("Недоверенная папка обновления.");
                SecureFiles.NoLinks(stage);string requestPath=Path.Combine(stage,"request.json");SecureFiles.NoLinks(requestPath);
                if(new FileInfo(requestPath).Length>8192)throw new UserError("Неверный запрос установки.");
                var request=Updates.Json().Deserialize<UpdateRequest>(File.ReadAllText(requestPath));
                if(request.sid!=WindowsIdentity.GetCurrent().User.Value||request.version!=Updates.CurrentVersion||Updates.HashFile(Assembly.GetExecutingAssembly().Location)!=request.originalHash)throw new UserError("Учётная запись или исходный клиент изменились.");
                string originalDir=Path.GetDirectoryName(request.original);SecureFiles.NoLinks(request.original);
                bool created;string newExe=null;
                using(var gate=new Mutex(false,GateName,out created)){
                    if(!created)throw new UserError("Другое обновление уже выполняется.");
                    // Signal only after the gate exists; parent closes after observing this file.
                    SecureFiles.WriteNew(Path.Combine(stage,"ready"),new byte[]{1});
                    try{using(var process=Process.GetProcessById(request.parent)){
                        if(process.StartTime.ToUniversalTime().Ticks!=request.parentStarted||!process.WaitForExit(60000))throw new UserError("NVVPN не завершился. Установка не начиналась.");
                    }}catch(ArgumentException){}
                    if(Lifecycle.CheckIdle()!=0)throw new UserError("NVVPN или движок ещё работает. Установка не начиналась.");
                    if(Updates.HashFile(request.original)!=request.originalHash)throw new UserError("Текущая программа изменилась. Установка отменена.");
                    byte[] bytes=File.ReadAllBytes(Path.Combine(stage,"release-manifest.json")),signature=File.ReadAllBytes(Path.Combine(stage,"release-manifest.sig"));
                    var manifest=Updates.Verify(bytes,signature,UpdateTrust.PublicKey,request.version,Updates.ReadHigh(SplitData.Root),DateTime.UtcNow);
                    bool installed=Installed(originalDir);var asset=installed?manifest.installer:manifest.portable;string package=Path.Combine(stage,asset.name);
                    using(var locked=new FileStream(package,FileMode.Open,FileAccess.Read,FileShare.Read)){
                        Updates.VerifyFile(package,asset);
                        backup=Path.Combine(Path.GetDirectoryName(parent),"Backups",DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N"));
                        SecureFiles.DirectoryAcl(Path.GetDirectoryName(backup),false,false);SecureFiles.DirectoryAcl(backup,false,false);
                        var old=Snapshot(originalDir,Path.Combine(backup,"app"),true,true);Snapshot(SplitData.Root,Path.Combine(backup,"data"),false,true);
                        SecureFiles.WriteNew(Path.Combine(backup,"RESTORE.txt"),System.Text.Encoding.UTF8.GetBytes("NVVPN "+request.version+"\r\nПрежний полный комплект: app. Откройте app\\NVVPN.exe после завершения других версий. VPN автоматически не включится.\r\nЗашифрованные данные: data, только для исходной учётной записи. Не копируйте их поверх новых профилей без отдельного решения.\r\n"));
                        if(installed){
                            int code=ExecuteInstaller(package);
                            CompleteInstalled(code,originalDir,Path.Combine(backup,"app"),old,manifest.version,Lifecycle.CheckIdle()==0);
                            newExe=Path.Combine(originalDir,"NVVPN.exe");
                        }else{
                            string target=Path.Combine(Path.GetDirectoryName(originalDir),"NVVPN-"+manifest.version+"-"+Guid.NewGuid().ToString("N").Substring(0,8));
                            newExe=ExtractPortable(package,target,manifest.version);VerifyPayload(target);
                        }
                        if(FileVersionInfo.GetVersionInfo(newExe).ProductVersion!=manifest.version)throw new UserError("После установки версия не подтверждена. Используйте сохранённую копию.");
                        SecureFiles.WriteNew(Path.Combine(backup,"update-complete.txt"),System.Text.Encoding.UTF8.GetBytes(manifest.version));success=true;
                    }
                }
                if(MessageBox.Show("Обновление установлено. Резервная копия сохранена.\nОткрыть NVVPN без подключения?","NVVPN",MessageBoxButton.YesNo,MessageBoxImage.Information)==MessageBoxResult.Yes)
                    Process.Start(new ProcessStartInfo(newExe){UseShellExecute=true,WorkingDirectory=Path.GetDirectoryName(newExe)});
                return 0;
            }catch(Exception e){MessageBox.Show((e is UserError?e.Message:"Обновление не завершено. Конфиденциальные сведения скрыты.")+(backup==null?"":"\nРезервная копия: "+backup),"NVVPN",MessageBoxButton.OK,MessageBoxImage.Warning);return 1;}
            finally{try{SecureFiles.NoLinks(stage);File.WriteAllText(Path.Combine(stage,"result.txt"),success?"success":"failed");}catch{}}
        }
    }
}

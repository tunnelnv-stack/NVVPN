using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace FinlandVPN
{
    internal static class Lifecycle
    {
        internal static int CheckIdle()
        {
            try{
                int current=Process.GetCurrentProcess().Id;
                foreach(string name in new[]{"NVVPN","NVVPN.Engine","NeverVPN","NeverVPN.Engine"})
                    foreach(var process in Process.GetProcessesByName(name))using(process){if(process.Id!=current)return 2;}
                return 0;
            }catch{return 3;}
        }
    }

    internal static class Migration
    {
        internal static void ImportPrototype()
        {
            string source=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"FinlandVPN","SplitPrototype");
            if(Directory.Exists(source)&&!File.Exists(Path.Combine(SplitData.Root,"migration-v1.complete"))&&Process.GetProcessesByName("FinlandSplitEngine").Length>0)
                throw new UserError("Сначала остановите подключение в прототипе, чтобы перенести настройки. Основной Finland VPN можно оставить работающим.");
            ImportFrom(source,SplitData.Root);
        }
        internal static void ImportFrom(string source,string target)
        {
            SecureFiles.DirectoryAcl(target,true,false);
            string marker=Path.Combine(target,"migration-v1.complete");SecureFiles.NoLinks(marker);
            if(File.Exists(marker))return;
            if(Directory.Exists(source)){
                SecureFiles.NoLinks(source);
                CopyOne(Path.Combine(source,"rules.dpapi"),Path.Combine(target,"rules.dpapi"),250000);
                CopyFolder(source,target,"Profiles","^[a-f0-9]{32}\\.dpapi$",200000);
                CopyFolder(source,target,"Cache","^[a-f0-9]{32}\\.db$",16777216);
            }
            SecureFiles.WriteNew(marker,Encoding.ASCII.GetBytes("v1\n"));
        }
        private static void CopyFolder(string source,string target,string folder,string pattern,long limit)
        {
            string from=Path.Combine(source,folder);if(!Directory.Exists(from))return;
            SecureFiles.NoLinks(from);string to=Path.Combine(target,folder);SecureFiles.DirectoryAcl(to,true,false);
            foreach(string path in Directory.GetFiles(from))
                if(Regex.IsMatch(Path.GetFileName(path),pattern))CopyOne(path,Path.Combine(to,Path.GetFileName(path)),limit);
        }
        private static void CopyOne(string source,string target,long limit)
        {
            SecureFiles.NoLinks(source);SecureFiles.NoLinks(target);
            if(!File.Exists(source)||File.Exists(target))return;
            if(new FileInfo(source).Length>limit)throw new UserError("Не удалось перенести настройки прототипа: файл превышает допустимый размер.");
            // Copy only encrypted profile/rules bytes and the private FakeIP cache.
            // Old files and existing new settings are never overwritten or removed.
            SecureFiles.WriteNew(target,File.ReadAllBytes(source));
        }
    }
}

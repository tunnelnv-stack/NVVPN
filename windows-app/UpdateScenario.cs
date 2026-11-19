using System;
using System.IO;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
namespace FinlandVPN
{
    // Offline integration harness: only creates a new caller-selected directory; never starts VPN or an installer.
    internal static class UpdateScenario
    {
        sealed class LocalRelease : IUpdateTransport
        {
            internal string Root,Version;
            public byte[] Get(string url,int limit,CancellationToken token)
            {
                if(url=="https://api.github.com/repos/"+Updates.Repository+"/releases/latest")return Encoding.UTF8.GetBytes("{\"draft\":false,\"prerelease\":false,\"tag_name\":\"v"+Version+"\"}");
                string path=PathFor(url);if(new FileInfo(path).Length>limit)throw new Exception("Fixture size");return File.ReadAllBytes(path);
            }
            string PathFor(string url){string prefix=Updates.ReleaseRoot+"/download/v"+Version+"/";if(!url.StartsWith(prefix,StringComparison.Ordinal))throw new Exception("Fixture URL");string name=url.Substring(prefix.Length);if(Path.GetFileName(name)!=name||name.Contains("/")||name.Contains("\\"))throw new Exception("Fixture name");return Path.Combine(Root,name);}
            public void Download(string url,string path,long limit,CancellationToken token,Action<long> progress){token.ThrowIfCancellationRequested();string source=PathFor(url);if(new FileInfo(source).Length>limit)throw new Exception("Fixture size");File.Copy(source,path,false);}
        }
        internal static int Run(string releaseDirectory,string output)
        {
            if(Directory.Exists(output))return 64;SecureFiles.DirectoryAcl(output,true,false);
            try{
                var raw=Updates.Json().Deserialize<ReleaseManifest>(File.ReadAllText(Path.Combine(releaseDirectory,"release-manifest.json")));
                var transport=new LocalRelease {Root=Path.GetFullPath(releaseDirectory),Version=raw.version};
                var release=Updates.Check(transport,UpdateTrust.PublicKey,Updates.CurrentVersion,0,CancellationToken.None);
                if(release==null)throw new Exception("No update");
                string stage=Path.Combine(output,"stage");SecureFiles.DirectoryAcl(stage,true,false);
                string zip=Updates.Download(transport,release,release.Manifest.portable,stage,CancellationToken.None,null);
                string data=Path.Combine(output,"synthetic-data");SecureFiles.DirectoryAcl(data,true,false);
                SecureFiles.WriteNew(Path.Combine(data,"profile.dpapi"),SecureFiles.Encrypt("SYNTHETIC PROFILE ONLY",DataProtectionScope.CurrentUser));
                SecureFiles.WriteNew(Path.Combine(data,"rules.dpapi"),SecureFiles.Encrypt("SYNTHETIC EXCEPTIONS AND YOUTUBE OFF",DataProtectionScope.CurrentUser));
                var hashes=UpdateInstall.Snapshot(data,Path.Combine(output,"backup-data"),false);
                string old=Path.Combine(output,"backup-app");UpdateInstall.Snapshot(AppDomain.CurrentDomain.BaseDirectory,old,true);
                string exe=UpdateInstall.ExtractPortable(zip,Path.Combine(output,"new-portable"),release.Manifest.version);
                UpdateInstall.VerifyPayload(Path.GetDirectoryName(exe));
                if(FileVersionInfo.GetVersionInfo(exe).ProductVersion!=release.Manifest.version)throw new Exception("Binary version mismatch");
                foreach(var h in hashes)if(Updates.HashFile(Path.Combine(data,h.Key))!=h.Value)throw new Exception("Synthetic data changed");
                if(FileVersionInfo.GetVersionInfo(Path.Combine(old,"NVVPN.exe")).ProductVersion!=Updates.CurrentVersion)throw new Exception("Rollback version mismatch");
                File.WriteAllText(Path.Combine(output,"RESULT.txt"),"PASS signed offline GitHub-shaped feed; "+Updates.CurrentVersion+" -> "+release.Manifest.version+"; actual portable unpacked; synthetic DPAPI data unchanged; previous binary retained. No VPN, registry, installer or production data access.");return 0;
            }catch{File.WriteAllText(Path.Combine(output,"RESULT.txt"),"FAIL offline update scenario; confidential details suppressed.");return 1;}
        }
    }
}

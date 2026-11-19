// Local publisher utility. Never included in the installed application's executable.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
namespace FinlandVPN
{
    internal static class ReleaseTools
    {
        static int Main(string[] args)
        {
            try{
                if(args.Length==3&&args[0]=="keygen"){
                    SecureFiles.DirectoryAcl(Path.GetDirectoryName(Path.GetFullPath(args[1])),true,false);
                    if(File.Exists(args[1])||File.Exists(args[2]))throw new Exception("Existing key files are never overwritten.");
                    using(var rsa=new RSACryptoServiceProvider(3072)){rsa.PersistKeyInCsp=false;
                        SecureFiles.WriteNew(args[1],SecureFiles.Encrypt(rsa.ToXmlString(true),DataProtectionScope.CurrentUser));
                        File.WriteAllText(args[2],"namespace FinlandVPN { internal static class UpdateTrust { internal const string PublicKey = @\""+rsa.ToXmlString(false)+"\"; } }",new UTF8Encoding(false));
                    }Console.WriteLine("Protected private key and public trust anchor created.");return 0;
                }
                if(args.Length==7&&args[0]=="sign"){
                    string root=Path.GetFullPath(args[2]),version=args[3];var v=new ReleaseVersion(version);if(!v.Stable||v.ToString()!=version)throw new Exception("Stable version required.");
                    Func<string,UpdateAsset> asset=name=>new UpdateAsset {name=name,size=new FileInfo(Path.Combine(root,name)).Length,sha256=Updates.HashFile(Path.Combine(root,name))};
                    var m=new ReleaseManifest {schema=1,product="NVVPN",repository=Updates.Repository,version=version,channel="stable",platform="windows-x64",commit=args[4],sequence=Int64.Parse(args[5]),issuedUtc=DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),expiresUtc=DateTime.UtcNow.AddDays(180).ToString("yyyy-MM-ddTHH:mm:ssZ"),notes=File.ReadAllText(args[6]),installer=asset("NVVPN-Setup-"+version+"-x64.exe"),portable=asset("NVVPN-"+version+"-Windows-x64.zip"),source=asset("NVVPN-"+version+"-Source.zip")};
                    byte[] bytes=Encoding.UTF8.GetBytes(Updates.Json().Serialize(m));
                    using(var rsa=new RSACryptoServiceProvider()){rsa.PersistKeyInCsp=false;rsa.FromXmlString(SecureFiles.Decrypt(File.ReadAllBytes(args[1]),DataProtectionScope.CurrentUser));
                        byte[] signature=rsa.SignData(bytes,"SHA256");Updates.Verify(bytes,signature,rsa.ToXmlString(false),"0.0.0",0,DateTime.UtcNow);
                        SecureFiles.WriteNew(Path.Combine(root,"release-manifest.json"),bytes);SecureFiles.WriteNew(Path.Combine(root,"release-manifest.sig"),signature);
                    }
                    Console.WriteLine("Release manifest signed locally. Nothing published.");return 0;
                }
                Console.Error.WriteLine("Usage: keygen PRIVATE_DPAPI PUBLIC_CS | sign PRIVATE_DPAPI RELEASE_DIR VERSION COMMIT SEQUENCE NOTES_FILE");return 64;
            }catch{Console.Error.WriteLine("Publisher operation failed; confidential details suppressed.");return 1;}
        }
    }
}

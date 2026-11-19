using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
namespace FinlandVPN
{
    internal static class UpdateTests
    {
        sealed class FakeTransport : IUpdateTransport
        {
            internal Dictionary<string,byte[]> Data=new Dictionary<string,byte[]>();
            internal int Calls;
            public byte[] Get(string url,int limit,CancellationToken token){token.ThrowIfCancellationRequested();Calls++;if(!Data.ContainsKey(url))throw new UserError("GitHub недоступен.");return Data[url];}
            public void Download(string url,string path,long limit,CancellationToken token,Action<long> progress){token.ThrowIfCancellationRequested();File.WriteAllBytes(path,Get(url,(int)limit,token));}
        }
        internal static int Run(string report)
        {
            var lines=new List<string>();int fail=0;Action<bool> check=value=>{if(!value)throw new Exception("Assertion");};
            Action<string,Action> test=(name,action)=>{try{action();lines.Add("PASS "+name);}catch{fail++;lines.Add("FAIL "+name);}};
            Action<Action> rejects=action=>{bool rejected=false;try{action();}catch{rejected=true;}check(rejected);};
            string root=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(report)),"update-fixture-"+Guid.NewGuid().ToString("N"));SecureFiles.DirectoryAcl(root,true,false);
            using(var rsa=new RSACryptoServiceProvider(3072)){
                rsa.PersistKeyInCsp=false;string key=rsa.ToXmlString(false);byte[] payload=Encoding.UTF8.GetBytes("Synthetic installer payload, never executed.");
                Func<string,UpdateAsset> a=name=>new UpdateAsset {name=name,sha256=Updates.Hash(payload),size=payload.Length};
                var m=new ReleaseManifest {schema=1,product="NVVPN",repository=Updates.Repository,version="0.4.5",channel="stable",platform="windows-x64",commit=new string('a',40),sequence=5,issuedUtc=DateTime.UtcNow.AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),expiresUtc=DateTime.UtcNow.AddDays(3).ToString("yyyy-MM-ddTHH:mm:ssZ"),notes="Проверка обновления B",installer=a("NVVPN-Setup-0.4.5-x64.exe"),portable=a("NVVPN-0.4.5-Windows-x64.zip"),source=a("NVVPN-0.4.5-Source.zip")};
                Func<byte[]> bytes=()=>Encoding.UTF8.GetBytes(Updates.Json().Serialize(m));
                Func<ReleaseManifest> verify=()=>Updates.Verify(bytes(),rsa.SignData(bytes(),"SHA256"),key,"0.4.4",0,DateTime.UtcNow);
                var transport=new FakeTransport();string api="https://api.github.com/repos/"+Updates.Repository+"/releases/latest",prefix=Updates.ReleaseRoot+"/download/v0.4.5/";
                Action feed=()=>{transport.Data[api]=Encoding.UTF8.GetBytes("{\"tag_name\":\"v0.4.5\",\"draft\":false,\"prerelease\":false}");transport.Data[prefix+"release-manifest.json"]=bytes();transport.Data[prefix+"release-manifest.sig"]=rsa.SignData(bytes(),"SHA256");};feed();
                test("numeric version order",()=>check(new ReleaseVersion("0.4.10").CompareTo(new ReleaseVersion("0.4.9"))>0));
                test("equal versions and metadata",()=>check(new ReleaseVersion("v0.4.5+abc").CompareTo(new ReleaseVersion("0.4.5"))==0));
                test("invalid versions",()=>{foreach(string v in new[]{"01.2.3","0.4.5.1","9999999.2.3","../0.4.5","0.4"})rejects(()=>new ReleaseVersion(v));});
                test("signed new version",()=>check(verify().version=="0.4.5"));
                test("no update",()=>check(Updates.Check(transport,key,"0.4.5",0,CancellationToken.None)==null));
                test("new update API",()=>check(Updates.Check(transport,key,"0.4.4",0,CancellationToken.None).Manifest.version=="0.4.5"));
                test("prerelease flag excluded",()=>{transport.Data[api]=Encoding.UTF8.GetBytes("{\"tag_name\":\"v0.4.5\",\"draft\":false,\"prerelease\":true}");rejects(()=>Updates.Check(transport,key,"0.4.4",0,CancellationToken.None));feed();});
                test("prerelease suffix excluded",()=>{transport.Data[api]=Encoding.UTF8.GetBytes("{\"tag_name\":\"v0.4.5-rc.1\",\"draft\":false,\"prerelease\":false}");rejects(()=>Updates.Check(transport,key,"0.4.4",0,CancellationToken.None));feed();});
                test("offline API",()=>rejects(()=>Updates.Check(new FakeTransport(),key,"0.4.4",0,CancellationToken.None)));
                test("HTTP error messages",()=>{foreach(int code in new[]{403,404,429,500,502})check(GitHubTransport.HttpError(code).Length>20);});
                test("bad JSON",()=>{transport.Data[api]=Encoding.UTF8.GetBytes("{");rejects(()=>Updates.Check(transport,key,"0.4.4",0,CancellationToken.None));feed();});
                test("wrong signature",()=>{byte[] sig=rsa.SignData(bytes(),"SHA256");sig[3]^=1;rejects(()=>Updates.Verify(bytes(),sig,key,"0.4.4",0,DateTime.UtcNow));});
                test("wrong key",()=>{using(var other=new RSACryptoServiceProvider(3072)){other.PersistKeyInCsp=false;rejects(()=>Updates.Verify(bytes(),rsa.SignData(bytes(),"SHA256"),other.ToXmlString(false),"0.4.4",0,DateTime.UtcNow));}});
                test("modified signed bytes",()=>{byte[] b=bytes(),sig=rsa.SignData(b,"SHA256");b[b.Length-2]^=1;rejects(()=>Updates.Verify(b,sig,key,"0.4.4",0,DateTime.UtcNow));});
                test("wrong architecture",()=>{m.platform="windows-arm64";rejects(()=>verify());m.platform="windows-x64";});
                test("wrong repository",()=>{m.repository="other/NVVPN";rejects(()=>verify());m.repository=Updates.Repository;});
                test("replay sequence",()=>rejects(()=>Updates.Verify(bytes(),rsa.SignData(bytes(),"SHA256"),key,"0.4.4",6,DateTime.UtcNow)));
                test("downgrade",()=>rejects(()=>Updates.Verify(bytes(),rsa.SignData(bytes(),"SHA256"),key,"0.4.6",0,DateTime.UtcNow)));
                test("expired manifest",()=>rejects(()=>Updates.Verify(bytes(),rsa.SignData(bytes(),"SHA256"),key,"0.4.4",0,DateTime.UtcNow.AddDays(4))));
                test("duplicate property",()=>{byte[] b=Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes()).Replace("\"schema\":1","\"schema\":1,\"schema\":1"));rejects(()=>Updates.Verify(b,rsa.SignData(b,"SHA256"),key,"0.4.4",0,DateTime.UtcNow));});
                test("URL boundaries",()=>{check(GitHubTransport.Allowed(new Uri(prefix)));foreach(string u in new[]{"http://github.com/","https://github.com.evil.invalid/","https://user@github.com/","file:///C:/bad","https://127.0.0.1/"})check(!GitHubTransport.Allowed(new Uri(u)));});
                test("download and verify",()=>{feed();var r=Updates.Check(transport,key,"0.4.4",0,CancellationToken.None);transport.Data[r.Url(m.installer)]=payload;string stage=Path.Combine(root,"download");Directory.CreateDirectory(stage);string f=Updates.Download(transport,r,m.installer,stage,CancellationToken.None,null);check(Updates.HashFile(f)==m.installer.sha256);});
                test("corrupt download no runnable file",()=>{feed();var r=Updates.Check(transport,key,"0.4.4",0,CancellationToken.None);transport.Data[r.Url(m.installer)]=new byte[]{1};string stage=Path.Combine(root,"bad");Directory.CreateDirectory(stage);rejects(()=>Updates.Download(transport,r,m.installer,stage,CancellationToken.None,null));check(!Directory.GetFiles(stage).Any());});
                test("cancelled download",()=>{var token=new CancellationToken(true);rejects(()=>Updates.Check(transport,key,"0.4.4",0,token));});
                test("DPAPI high water persists",()=>{string data=Path.Combine(root,"high");Updates.SaveHigh(data,9);Updates.SaveHigh(data,5);check(Updates.ReadHigh(data)==9);});
                test("backup preserves opaque data and rules",()=>{string data=Path.Combine(root,"data");SecureFiles.DirectoryAcl(data,true,false);SecureFiles.DirectoryAcl(Path.Combine(data,"Profiles"),true,false);
                    SecureFiles.WriteNew(Path.Combine(data,"Profiles","synthetic.dpapi"),SecureFiles.Encrypt("SYNTHETIC-KEY",DataProtectionScope.CurrentUser));SecureFiles.WriteNew(Path.Combine(data,"rules.dpapi"),SecureFiles.Encrypt("{\"video_compatibility\":false,\"domains\":[\"example.com\"]}",DataProtectionScope.CurrentUser));SecureFiles.WriteNew(Path.Combine(data,"agreement.dpapi"),new byte[]{1,2,3});
                    string backup=Path.Combine(root,"backup-data");var hashes=UpdateInstall.Snapshot(data,backup,false);check(hashes.Count==3);foreach(var h in hashes)check(Updates.HashFile(Path.Combine(data,h.Key))==Updates.HashFile(Path.Combine(backup,h.Key)));check(Directory.GetAccessControl(backup).AreAccessRulesProtected);
                });
                test("installer failure recovery restores payload",()=>{string app=Path.Combine(root,"app"),backup=Path.Combine(root,"backup-app");Directory.CreateDirectory(app);foreach(string name in UpdateInstall.Payload)File.WriteAllText(Path.Combine(app,name),"old:"+name);var hashes=UpdateInstall.Snapshot(app,backup,true);File.WriteAllText(Path.Combine(app,"NVVPN.exe"),"partial failed installation");rejects(()=>UpdateInstall.CompleteInstalled(2,app,backup,hashes,"0.4.5",true));check(hashes.All(h=>Updates.HashFile(Path.Combine(app,h.Key))==h.Value));});
                test("corrupt backup refused",()=>{string backup=Path.Combine(root,"backup-app");var hashes=Updates.Json().Deserialize<Dictionary<string,string>>(File.ReadAllText(Path.Combine(backup,"backup-manifest.json")));File.WriteAllText(Path.Combine(backup,"NVVPN.exe"),"bad");rejects(()=>UpdateInstall.RestorePayload(backup,Path.Combine(root,"app"),hashes));});
                test("portable new directory and old intact",()=>{string zip=Path.Combine(root,"portable.zip");using(var z=ZipFile.Open(zip,ZipArchiveMode.Create))foreach(string name in UpdateInstall.Payload){using(var w=new StreamWriter(z.CreateEntry("NVVPN-0.4.5/"+name).Open()))w.Write("B:"+name);}string target=Path.Combine(root,"portable-B");check(File.Exists(UpdateInstall.ExtractPortable(zip,target,"0.4.5")));check(File.ReadAllText(Path.Combine(root,"app","NVVPN.exe"))=="old:NVVPN.exe");rejects(()=>UpdateInstall.ExtractPortable(zip,target,"0.4.5"));});
                test("portable path traversal refused",()=>{string zip=Path.Combine(root,"traversal.zip");using(var z=ZipFile.Open(zip,ZipArchiveMode.Create))foreach(string name in UpdateInstall.Payload){using(var w=new StreamWriter(z.CreateEntry(name=="NVVPN.exe"?"NVVPN-0.4.5/../escape.exe":"NVVPN-0.4.5/"+name).Open()))w.Write("bad");}rejects(()=>UpdateInstall.ExtractPortable(zip,Path.Combine(root,"badzip"),"0.4.5"));check(!File.Exists(Path.Combine(root,"escape.exe")));});
            }
            lines.Add("RESULT "+(fail==0?"PASS":"FAIL")+" failures="+fail);File.WriteAllLines(report,lines);return fail==0?0:1;
        }
    }
}

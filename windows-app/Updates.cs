using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace FinlandVPN
{
    internal sealed class ReleaseVersion : IComparable<ReleaseVersion>
    {
        internal readonly int Major, Minor, Patch;
        internal readonly string Prerelease;
        internal bool Stable { get { return Prerelease.Length==0; } }
        internal ReleaseVersion(string text)
        {
            var m=Regex.Match(text??"",@"^v?(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})(?:-([0-9A-Za-z.-]{1,64}))?(?:\+([0-9A-Za-z.-]{1,64}))?$");
            if(!m.Success)throw new UserError("Некорректный номер версии обновления.");
            Major=Int32.Parse(m.Groups[1].Value);Minor=Int32.Parse(m.Groups[2].Value);Patch=Int32.Parse(m.Groups[3].Value);Prerelease=m.Groups[4].Value;
            if(new[]{Major,Minor,Patch}.Any(x=>x>65534))throw new UserError("Номер версии вне допустимого диапазона.");
        }
        public int CompareTo(ReleaseVersion b){int n=Major.CompareTo(b.Major);if(n==0)n=Minor.CompareTo(b.Minor);if(n==0)n=Patch.CompareTo(b.Patch);if(n==0)n=Stable.CompareTo(b.Stable);return n;}
        public override string ToString(){return Major+"."+Minor+"."+Patch+(Stable?"":"-"+Prerelease);}
    }
    internal sealed class UpdateAsset
    {
        public string name {get;set;}
        public string sha256 {get;set;}
        public long size {get;set;}
    }
    internal sealed class ReleaseManifest
    {
        public int schema {get;set;}
        public string product {get;set;}
        public string repository {get;set;}
        public string version {get;set;}
        public string channel {get;set;}
        public string platform {get;set;}
        public string commit {get;set;}
        public long sequence {get;set;}
        public string issuedUtc {get;set;}
        public string expiresUtc {get;set;}
        public string notes {get;set;}
        public UpdateAsset installer {get;set;}
        public UpdateAsset portable {get;set;}
        public UpdateAsset source {get;set;}
    }
    internal sealed class UpdateRelease
    {
        internal ReleaseManifest Manifest;
        internal byte[] Bytes, Signature;
        internal string Url(UpdateAsset asset){return Updates.ReleaseRoot+"/download/v"+Manifest.version+"/"+asset.name;}
    }
    internal interface IUpdateTransport
    {
        byte[] Get(string url,int limit,CancellationToken token);
        void Download(string url,string path,long limit,CancellationToken token,Action<long> progress);
    }
    internal sealed class GitHubTransport : IUpdateTransport
    {
        internal static bool Allowed(Uri uri)
        {
            if(uri.Scheme!="https"||!uri.IsDefaultPort||uri.UserInfo.Length!=0)return false;
            return uri.Host=="api.github.com"||uri.Host=="github.com"||uri.Host=="release-assets.githubusercontent.com"||uri.Host=="objects.githubusercontent.com";
        }
        internal static string HttpError(int status)
        {
            if(status==404)return "Стабильный выпуск пока недоступен. Репозиторий может быть ещё не опубликован.";
            if(status==403||status==429)return "GitHub ограничил запросы. Повторите проверку позже; токен не требуется.";
            if(status>=500)return "GitHub временно недоступен. Повторите проверку позже.";
            return "Не удалось получить обновление с GitHub (HTTP "+status+").";
        }
        void Fetch(string url,Stream destination,long limit,CancellationToken token,Action<long> progress)
        {
            Uri uri=new Uri(url);var started=DateTime.UtcNow;
            for(int hop=0;hop<5;hop++){
                token.ThrowIfCancellationRequested();if(!Allowed(uri))throw new UserError("Недоверенный адрес обновления.");
                var request=(HttpWebRequest)WebRequest.Create(uri);request.AllowAutoRedirect=false;request.Timeout=20000;request.ReadWriteTimeout=20000;
                request.UserAgent="NVVPN/"+Updates.CurrentVersion;request.Accept="application/vnd.github+json";
                if(uri.Host=="api.github.com")request.Headers["X-GitHub-Api-Version"]="2022-11-28";
                request.AutomaticDecompression=DecompressionMethods.None;
                using(token.Register(()=>request.Abort()))try{
                    using(var response=(HttpWebResponse)request.GetResponse()){
                        int code=(int)response.StatusCode;
                        if(code>=300&&code<400){string location=response.Headers["Location"];if(String.IsNullOrEmpty(location))throw new UserError("GitHub вернул неверное перенаправление.");uri=new Uri(uri,location);continue;}
                        if(code!=200)throw new UserError(HttpError(code));
                        if(response.ContentLength>limit)throw new UserError("Размер обновления превышает заявленный.");
                        using(var input=response.GetResponseStream()){
                            byte[] buffer=new byte[65536];long count=0;int n;
                            while((n=input.Read(buffer,0,buffer.Length))>0){token.ThrowIfCancellationRequested();count+=n;
                                if(count>limit||DateTime.UtcNow-started>TimeSpan.FromMinutes(30))throw new UserError("Превышен предел размера или времени загрузки.");
                                destination.Write(buffer,0,n);if(progress!=null)progress(count);
                            }
                        }return;
                    }
                }catch(WebException e){token.ThrowIfCancellationRequested();var response=e.Response as HttpWebResponse;
                    if(response!=null){using(response)throw new UserError(HttpError((int)response.StatusCode));}
                    throw new UserError("Не удалось связаться с GitHub. Проверьте интернет и повторите. Проверка TLS не отключается.");
                }
            }throw new UserError("Слишком много перенаправлений GitHub.");
        }
        public byte[] Get(string url,int limit,CancellationToken token){using(var stream=new MemoryStream()){Fetch(url,stream,limit,token,null);return stream.ToArray();}}
        public void Download(string url,string path,long limit,CancellationToken token,Action<long> progress){using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){Fetch(url,f,limit,token,progress);f.Flush(true);}}
    }
    internal static class Updates
    {
        internal const string Repository="tunnelnv-stack/NVVPN";
        internal const string ReleaseRoot="https://github.com/"+Repository+"/releases";
        internal static string CurrentVersion {get{return ((AssemblyInformationalVersionAttribute)Attribute.GetCustomAttribute(Assembly.GetExecutingAssembly(),typeof(AssemblyInformationalVersionAttribute))).InformationalVersion;}}
        internal static string SourceUrl {get{return ReleaseRoot+"/tag/v"+CurrentVersion;}}
        internal static JavaScriptSerializer Json(){return new JavaScriptSerializer {MaxJsonLength=262144,RecursionLimit=16};}
        internal static string Hash(byte[] data){using(var sha=SHA256.Create())return Hex(sha.ComputeHash(data));}
        internal static string HashFile(string path){SecureFiles.NoLinks(path);using(var sha=SHA256.Create())using(var f=File.OpenRead(path))return Hex(sha.ComputeHash(f));}
        static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
        internal static ReleaseManifest Verify(byte[] bytes,byte[] signature,string publicKey,string current,long high,DateTime now)
        {
            if(bytes.Length==0||bytes.Length>262144||signature.Length!=384)throw new UserError("Неверный формат подписи обновления.");
            using(var rsa=new RSACryptoServiceProvider()){rsa.PersistKeyInCsp=false;rsa.FromXmlString(publicKey);
                if(rsa.KeySize!=3072||!rsa.VerifyData(bytes,"SHA256",signature))throw new UserError("Не удалось подтвердить подпись издателя. Запуск запрещён.");}
            string text=new UTF8Encoding(false,true).GetString(bytes);
            var m=Json().Deserialize<ReleaseManifest>(text);
            // Only the publisher's exact, canonical serializer format is accepted; this also rejects duplicate/unknown keys.
            if(Json().Serialize(m)!=text)throw new UserError("Манифест имеет неподдерживаемый формат.");
            if(m.schema!=1||m.product!="NVVPN"||m.repository!=Repository||m.platform!="windows-x64"||m.channel!="stable"||!new ReleaseVersion(m.version).Stable||m.version!=new ReleaseVersion(m.version).ToString())throw new UserError("Обновление не соответствует продукту, платформе или стабильному каналу.");
            if(!Regex.IsMatch(m.commit??"","^[0-9a-f]{40}$")||m.notes==null||m.notes.Length>16000)throw new UserError("Некорректные сведения выпуска.");
            DateTime issued,expires;
            if(!DateTime.TryParseExact(m.issuedUtc,"yyyy-MM-ddTHH:mm:ssZ",CultureInfo.InvariantCulture,DateTimeStyles.AdjustToUniversal|DateTimeStyles.AssumeUniversal,out issued)||
               !DateTime.TryParseExact(m.expiresUtc,"yyyy-MM-ddTHH:mm:ssZ",CultureInfo.InvariantCulture,DateTimeStyles.AdjustToUniversal|DateTimeStyles.AssumeUniversal,out expires)||issued>now.AddMinutes(10)||expires<=now||expires<=issued||expires-issued>TimeSpan.FromDays(366))throw new UserError("Срок подписи истёк или часы компьютера неверны. Повторите проверку позже.");
            if(m.sequence<high||m.sequence<=0||new ReleaseVersion(m.version).CompareTo(new ReleaseVersion(current))<=0)throw new UserError("Предложена прежняя версия. Понижение через обновления запрещено.");
            CheckAsset(m.installer,"NVVPN-Setup-"+m.version+"-x64.exe");CheckAsset(m.portable,"NVVPN-"+m.version+"-Windows-x64.zip");CheckAsset(m.source,"NVVPN-"+m.version+"-Source.zip");return m;
        }
        static void CheckAsset(UpdateAsset a,string name){if(a==null||a.name!=name||a.size<=0||a.size>2147483648L||!Regex.IsMatch(a.sha256??"","^[0-9a-f]{64}$"))throw new UserError("Некорректный файл в манифесте выпуска.");}
        internal static UpdateRelease Check(IUpdateTransport transport,string publicKey,string current,long high,CancellationToken token)
        {
            var data=Json().Deserialize<Dictionary<string,object>>(Encoding.UTF8.GetString(transport.Get("https://api.github.com/repos/"+Repository+"/releases/latest",262144,token)));
            if(data==null||!data.ContainsKey("draft")||!data.ContainsKey("prerelease")||!(data["draft"] is bool)||!(data["prerelease"] is bool)||!data.ContainsKey("tag_name"))throw new UserError("GitHub вернул неполные сведения выпуска.");
            if((bool)data["draft"]||(bool)data["prerelease"])throw new UserError("Тестовый выпуск не предлагается как стабильное обновление.");
            string tag=data["tag_name"] as string;var version=new ReleaseVersion(tag);
            if(!version.Stable)throw new UserError("Предварительный выпуск пропущен.");
            if(tag!="v"+version.ToString())throw new UserError("Неподдерживаемый тег выпуска.");
            if(version.CompareTo(new ReleaseVersion(current))<=0)return null;
            string path=ReleaseRoot+"/download/"+tag+"/";
            byte[] manifest=transport.Get(path+"release-manifest.json",262144,token),sig=transport.Get(path+"release-manifest.sig",384,token);
            var verified=Verify(manifest,sig,publicKey,current,high,DateTime.UtcNow);
            if(verified.version!=version.ToString())throw new UserError("Версия GitHub не совпадает с подписанным выпуском.");
            return new UpdateRelease {Manifest=verified,Bytes=manifest,Signature=sig};
        }
        internal static void VerifyFile(string path,UpdateAsset asset){SecureFiles.NoLinks(path);if(new FileInfo(path).Length!=asset.size||HashFile(path)!=asset.sha256)throw new UserError("Скачанный файл повреждён или подменён. Запуск запрещён.");}
        internal static string Download(IUpdateTransport transport,UpdateRelease release,UpdateAsset asset,string stage,CancellationToken token,Action<long> progress)
        {
            SecureFiles.NoLinks(stage);string partial=Path.Combine(stage,asset.name+".partial"),target=Path.Combine(stage,asset.name);
            try{transport.Download(release.Url(asset),partial,asset.size,token,progress);VerifyFile(partial,asset);File.Move(partial,target);
                SecureFiles.WriteNew(Path.Combine(stage,"release-manifest.json"),release.Bytes);SecureFiles.WriteNew(Path.Combine(stage,"release-manifest.sig"),release.Signature);return target;
            }catch{if(File.Exists(partial)){SecureFiles.NoLinks(partial);File.Delete(partial);}throw;}
        }
        internal static long ReadHigh(string root)
        {
            string file=Path.Combine(root,"update-sequence.dpapi");SecureFiles.NoLinks(file);if(!File.Exists(file))return 0;
            long value;if(new FileInfo(file).Length>4096||!Int64.TryParse(SecureFiles.Decrypt(File.ReadAllBytes(file),DataProtectionScope.CurrentUser),out value)||value<0)throw new UserError("Повреждены сведения проверки обновлений.");return value;
        }
        internal static void SaveHigh(string root,long value)
        {
            SecureFiles.DirectoryAcl(root,true,false);long old=ReadHigh(root);if(value<=old)return;
            string file=Path.Combine(root,"update-sequence.dpapi"),temp=Path.Combine(root,Guid.NewGuid().ToString("N")+".dpapi");
            SecureFiles.WriteNew(temp,SecureFiles.Encrypt(value.ToString(CultureInfo.InvariantCulture),DataProtectionScope.CurrentUser));if(File.Exists(file))File.Replace(temp,file,null);else File.Move(temp,file);
        }
    }
}

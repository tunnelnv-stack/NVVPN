using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows;

namespace FinlandVPN
{
    internal sealed class AgreementDocument
    {
        internal readonly string Id, Version, Date, Text, Sha256;
        internal readonly bool Published;
        internal AgreementDocument(string id, string version, string date, byte[] bytes, bool published)
        {
            Id=id;Version=version;Date=date;Published=published;
            Text=new UTF8Encoding(false,true).GetString(bytes);
            using(var sha=SHA256.Create())Sha256=BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();
        }
        // Release 0.4.3: owner requested usable client terms and delegated privacy defaults.
        // Publication enables explicit acceptance; it never creates user consent.
        internal static readonly AgreementDocument Current=Load();
        private static AgreementDocument Load()
        {
            using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("Agreement.ru.txt"))
            using(var bytes=new MemoryStream()){
                if(input==null)throw new InvalidOperationException("Agreement resource missing");
                input.CopyTo(bytes);
                return new AgreementDocument("nvvpn-use","1.1","19.11.2026",bytes.ToArray(),true);
            }
        }
    }

    internal sealed class AgreementRequiredException : Exception
    {
        internal const int ExitCode=78;
        internal const string Diagnostic="NVVPN_AGREEMENT_REQUIRED";
        internal AgreementRequiredException() : base("Для подключения требуется утверждённое соглашение и его принятие в окне NVVPN.") { }
    }

    internal sealed class AgreementStore
    {
        const int MaxBytes=16384;
        readonly string root, target;
        internal AgreementStore(string directory){root=Path.GetFullPath(directory);target=Path.Combine(root,"agreement.dpapi");}
        internal string FilePath { get { return target; } }
        static JavaScriptSerializer Serializer(){return new JavaScriptSerializer{MaxJsonLength=MaxBytes,RecursionLimit=8};}
        internal bool HasAccepted(AgreementDocument document)
        {
            if(!document.Published)return false;
            return AcceptedRevision(document,true)!=null;
        }
        internal string AcceptedRevision(AgreementDocument document,bool requireCurrent)
        {
            try{
                SecureFiles.NoLinks(target);
                if(!File.Exists(target))return null;
                byte[] cipher;
                using(var input=new FileStream(target,FileMode.Open,FileAccess.Read,FileShare.Read)){
                    if(input.Length==0||input.Length>MaxBytes)return null;
                    cipher=new byte[(int)input.Length];int offset=0,read;
                    while(offset<cipher.Length&&(read=input.Read(cipher,offset,cipher.Length-offset))>0)offset+=read;
                    if(offset!=cipher.Length)return null;
                }
                string json=SecureFiles.Decrypt(cipher,DataProtectionScope.CurrentUser);
                if(Encoding.UTF8.GetByteCount(json)>MaxBytes||!ValidRecord(json,document,requireCurrent))return null;
                return (string)Serializer().Deserialize<Dictionary<string,object>>(json)["agreementVersion"];
            }catch(IOException){return null;}catch(UnauthorizedAccessException){return null;}
            catch(CryptographicException){return null;}catch(ArgumentException){return null;}
            catch(InvalidOperationException){return null;}catch(UserError){return null;}
            catch(System.Security.SecurityException){return null;}
        }
        internal static bool ValidRecord(string json,AgreementDocument document,bool requireCurrent=true)
        {
            if(requireCurrent&&!document.Published)return false;
            var r=Serializer().DeserializeObject(json) as Dictionary<string,object>;
            if(r==null||r.Count!=7)return false;
            object schema,id,version,hash,accepted,time,application;
            if(!r.TryGetValue("schemaVersion",out schema)||!(schema is int)||(int)schema!=1||
               !r.TryGetValue("agreementId",out id)||!(id is string)||(string)id!=document.Id||
               !r.TryGetValue("agreementVersion",out version)||!(version is string)||!Regex.IsMatch((string)version,@"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}$")||
               !r.TryGetValue("documentSha256",out hash)||!(hash is string)||!Regex.IsMatch((string)hash,"^[a-f0-9]{64}$")||
               !r.TryGetValue("accepted",out accepted)||!(accepted is bool)||!(bool)accepted||
               !r.TryGetValue("acceptedAtUtc",out time)||!(time is string)||
               !r.TryGetValue("applicationVersion",out application)||!(application is string)||
               !Regex.IsMatch((string)application,@"^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}(\.[0-9]{1,5})?$"))return false;
            DateTime timestamp;
            return (!requireCurrent||((string)version==document.Version&&(string)hash==document.Sha256))&&
                DateTime.TryParseExact((string)time,"o",CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out timestamp)&&timestamp.Kind==DateTimeKind.Utc;
        }
        internal static string Record(AgreementDocument document)
        {
            return Serializer().Serialize(new {schemaVersion=1,agreementId=document.Id,agreementVersion=document.Version,
                documentSha256=document.Sha256,accepted=true,acceptedAtUtc=DateTime.UtcNow.ToString("o",CultureInfo.InvariantCulture),
                applicationVersion=Assembly.GetExecutingAssembly().GetName().Version.ToString()});
        }
        internal void Accept(AgreementDocument document)
        {
            if(!document.Published)throw new AgreementRequiredException();
            string identity;
            using(var sha=SHA256.Create())identity=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(target.ToUpperInvariant()))).Replace("-","");
            using(var mutex=new Mutex(false,@"Local\NeverVPN.Agreement."+identity)){
                bool locked=false;
                try{
                    try{locked=mutex.WaitOne(3000);}catch(AbandonedMutexException){locked=true;}
                    if(!locked)throw new UserError("Согласие сохраняется в другом окне. Повторите попытку.");
                    if(HasAccepted(document))return;
                    SecureFiles.DirectoryAcl(root,true,false);SecureFiles.NoLinks(target);
                    string stage=Path.Combine(root,"agreement-"+Guid.NewGuid().ToString("N")+".tmp");
                    try{
                        SecureFiles.WriteNew(stage,SecureFiles.Encrypt(Record(document),DataProtectionScope.CurrentUser));
                        SecureFiles.NoLinks(target);SecureFiles.NoLinks(stage);
                        if(File.Exists(target))File.Replace(stage,target,null);else File.Move(stage,target);
                        if(!HasAccepted(document))throw new UserError("Не удалось проверить сохранённое согласие. Подключение не начато.");
                    }finally{if(File.Exists(stage)){SecureFiles.NoLinks(stage);File.Delete(stage);}}
                }finally{if(locked)mutex.ReleaseMutex();}
            }
        }
    }

    internal static class Agreement
    {
        internal static AgreementStore Store { get { return new AgreementStore(SplitData.Root); } }
        internal static bool IsNetworkCli(string mode)
        {
            return mode=="--probe-internal"||mode=="--proxy-test-internal"||mode=="--proxy-app-test-internal"||mode=="--proxy-video-test-internal";
        }
        internal static void RequireCurrent()
        {
            RequireAccepted(Store,AgreementDocument.Current);
        }
        internal static void RequireAccepted(AgreementStore store,AgreementDocument document)
        {
            if(!store.HasAccepted(document))throw new AgreementRequiredException();
        }
        internal static void RequireEngine(string mode)
        {
            RequireEngine(mode,Store,AgreementDocument.Current);
        }
        // Explicit dependencies let offline self-tests use synthetic stores only.
        // Production callers always use the one-argument overload above.
        internal static void RequireEngine(string mode,AgreementStore store,AgreementDocument document)
        {
            // --check returns after parsing/building options, before startAWG/probe/router.Start.
            if(mode=="--check")return;
            if(mode!="--run"&&mode!="--probe"&&mode!="--proxy-test")throw new UserError("Неизвестный режим движка.");
            RequireAccepted(store,document);
        }
        internal static bool EnsureAccepted(Window owner)
        {
            var document=AgreementDocument.Current;var store=Store;
            if(store.HasAccepted(document))return true;
            var dialog=new AgreementDialog(document,true,false);dialog.Window.Owner=owner;
            if(dialog.Window.ShowDialog()!=true)return false;
            store.Accept(document);
            if(!store.HasAccepted(document))throw new AgreementRequiredException();
            return true;
        }
        internal static void Show(Window owner,bool preview)
        {
            var document=AgreementDocument.Current;
            var dialog=new AgreementDialog(document,false,!preview&&Store.HasAccepted(document),preview?null:Store.AcceptedRevision(document,false));dialog.Window.Owner=owner;dialog.Window.ShowDialog();
        }
    }
}

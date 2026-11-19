using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace FinlandVPN
{
    internal static class AgreementTests
    {
        internal static AgreementDocument Synthetic(string version,string text)
        {
            return new AgreementDocument("nvvpn-synthetic-test",version,"19.11.2026",Encoding.UTF8.GetBytes(text),true);
        }
        internal static void Run(Action<string,Action> test,Action<bool> check,string report)
        {
            string root=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(report)),"agreement-tests-"+Guid.NewGuid().ToString("N"));
            var document=Synthetic("test-1","Синтетическое соглашение. Не предоставляет доступ к серверу.");
            var store=new AgreementStore(root);
            var draftDocument=new AgreementDocument(document.Id,"draft-1",document.Date,Encoding.UTF8.GetBytes("Synthetic draft"),false);
            test("Agreement draft cannot authorize or persist consent",()=>{
                check(!store.HasAccepted(draftDocument));
                bool rejected=false;try{store.Accept(draftDocument);}catch(AgreementRequiredException){rejected=true;}
                check(rejected&&!Directory.Exists(root));
            });
            test("Agreement missing record is rejected",()=>check(!store.HasAccepted(document)));
            test("Agreement real CurrentUser DPAPI round trip and profile/rules isolation",()=>{
                SecureFiles.DirectoryAcl(root,true,false);
                File.WriteAllText(Path.Combine(root,"profile.synthetic"),"synthetic profile sentinel");
                File.WriteAllText(Path.Combine(root,"rules.synthetic"),"synthetic rules sentinel");
                store.Accept(document);check(store.HasAccepted(document));
                check(File.ReadAllText(Path.Combine(root,"profile.synthetic"))=="synthetic profile sentinel");
                check(File.ReadAllText(Path.Combine(root,"rules.synthetic"))=="synthetic rules sentinel");
                check(!Encoding.UTF8.GetString(File.ReadAllBytes(store.FilePath)).Contains("acceptedAtUtc"));
                var record=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(SecureFiles.Decrypt(File.ReadAllBytes(store.FilePath),DataProtectionScope.CurrentUser));
                check(record.Count==7&&(string)record["agreementVersion"]=="test-1");
            });
            test("Agreement repeat acceptance keeps original encrypted record",()=>{
                byte[] first=File.ReadAllBytes(store.FilePath);store.Accept(document);
                check(Convert.ToBase64String(first)==Convert.ToBase64String(File.ReadAllBytes(store.FilePath)));
            });
            test("Agreement exact bytes hash and version each require new acceptance",()=>{
                check(!store.HasAccepted(Synthetic("test-2",document.Text)));
                check(!store.HasAccepted(Synthetic("test-1",document.Text+"\n")));
                check(store.AcceptedRevision(Synthetic("test-2",document.Text),false)=="test-1");
                check(!store.HasAccepted(new AgreementDocument("different-operator",document.Version,document.Date,Encoding.UTF8.GetBytes(document.Text),true)));
            });
            test("Agreement tampered ciphertext fails closed",()=>{
                byte[] cipher=File.ReadAllBytes(store.FilePath);cipher[cipher.Length/2]^=0x20;File.WriteAllBytes(store.FilePath,cipher);
                check(!store.HasAccepted(document));store.Accept(document);check(store.HasAccepted(document));
            });
            test("Agreement oversized and malformed records fail closed",()=>{
                File.WriteAllBytes(store.FilePath,new byte[16385]);check(!store.HasAccepted(document));
                File.WriteAllBytes(store.FilePath,SecureFiles.Encrypt("{broken",DataProtectionScope.CurrentUser));check(!store.HasAccepted(document));
                File.WriteAllBytes(store.FilePath,SecureFiles.Encrypt("{}",DataProtectionScope.CurrentUser));check(!store.HasAccepted(document));
            });
            test("Agreement schema, boolean, UTC timestamp, application and digest are validated",()=>{
                var json=new JavaScriptSerializer();
                var cases=new Dictionary<string,object>{{"schemaVersion",2},{"accepted",false},{"acceptedAtUtc","2026-11-19T00:00:00"},{"documentSha256",""},{"applicationVersion","unknown"},{"agreementId",null},{"agreementVersion",1}};
                foreach(var pair in cases){
                    var record=json.Deserialize<Dictionary<string,object>>(AgreementStore.Record(document));record[pair.Key]=pair.Value;
                    File.WriteAllBytes(store.FilePath,SecureFiles.Encrypt(json.Serialize(record),DataProtectionScope.CurrentUser));check(!store.HasAccepted(document));
                }
            });
            test("Agreement concurrent attempts persist one valid record without leftover stage",()=>{
                File.Delete(store.FilePath);Task.WaitAll(Task.Run(()=>store.Accept(document)),Task.Run(()=>store.Accept(document)));
                check(store.HasAccepted(document)&&Directory.GetFiles(root,"agreement-*.tmp").Length==0);
            });
            test("Agreement write error never authorizes connection",()=>{
                string denied=Path.Combine(root,"path-is-a-file");File.WriteAllText(denied,"synthetic");
                var badStore=new AgreementStore(denied);bool failed=false;try{badStore.Accept(document);}catch(IOException){failed=true;}
                check(failed&&!badStore.HasAccepted(document));
            });
            test("Agreement network permission uses isolated store and fails closed",()=>{
                var isolated=new AgreementStore(Path.Combine(root,"isolated-gate"));
                Agreement.RequireEngine("--check",isolated,draftDocument);
                Action<AgreementDocument> denied=doc=>{
                    foreach(string mode in new[]{"--run","--probe","--proxy-test"}){
                        bool blocked=false;try{Agreement.RequireEngine(mode,isolated,doc);}catch(AgreementRequiredException){blocked=true;}
                        check(blocked);
                    }
                };
                denied(document);denied(draftDocument);
                isolated.Accept(document);
                foreach(string mode in new[]{"--run","--probe","--proxy-test"})Agreement.RequireEngine(mode,isolated,document);
                denied(Synthetic("test-2",document.Text));denied(Synthetic(document.Version,document.Text+"changed"));denied(draftDocument);
                File.WriteAllBytes(isolated.FilePath,new byte[]{1,2,3});denied(document);
                bool unknown=false;try{Agreement.RequireEngine("--future-mode",isolated,document);}catch(UserError){unknown=true;}check(unknown);
                foreach(string mode in new[]{"--probe-internal","--proxy-test-internal","--proxy-app-test-internal","--proxy-video-test-internal"})check(Agreement.IsNetworkCli(mode));
                check(!Agreement.IsNetworkCli("--check-profile")&&!Agreement.IsNetworkCli("--render"));
            });
            test("Release agreement requires explicit current-document acceptance",()=>{
                var current=AgreementDocument.Current;
                var releaseStore=new AgreementStore(Path.Combine(root,"release-document"));
                check(current.Published&&current.Id=="nvvpn-use"&&current.Version=="1.1"&&current.Text.Contains("tunnelnv@gmail.com"));
                bool denied=false;try{Agreement.RequireEngine("--run",releaseStore,current);}catch(AgreementRequiredException){denied=true;}check(denied);
                releaseStore.Accept(current);Agreement.RequireEngine("--run",releaseStore,current);
                check(releaseStore.HasAccepted(current));
                check(!releaseStore.HasAccepted(new AgreementDocument(current.Id,current.Version,current.Date,Encoding.UTF8.GetBytes(current.Text+"changed"),true)));
            });
            test("Agreement unchecked, explicit consent, uncheck, draft and read-only dialog states",()=>{
                var dialog=new AgreementDialog(document,true,false);
                check(dialog.Consent.IsChecked==false&&!dialog.Accept.IsEnabled&&!dialog.Accept.IsDefault&&dialog.Cancel.IsCancel);
                dialog.Consent.IsChecked=true;check(dialog.Accept.IsEnabled);
                dialog.Consent.IsChecked=false;check(!dialog.Accept.IsEnabled);
                check(dialog.Document.IsReadOnly&&dialog.Document.Text==document.Text);
                var draft=new AgreementDialog(draftDocument,true,false);
                draft.Consent.IsChecked=true;check(!draft.Consent.IsEnabled&&!draft.Accept.IsEnabled);
                var readOnly=new AgreementDialog(document,false,true);
                readOnly.Consent.IsChecked=true;check(!readOnly.Accept.IsEnabled&&readOnly.Accept.Visibility==System.Windows.Visibility.Collapsed);
                dialog.Window.Close();draft.Window.Close();readOnly.Window.Close();
            });
        }
    }
}

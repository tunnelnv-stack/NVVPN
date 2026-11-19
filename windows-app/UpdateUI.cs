using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace FinlandVPN
{
    internal sealed partial class SplitWindow
    {
        UpdateRelease updateRelease;
        CancellationTokenSource updateCancellation;
        bool updateInstalling;
        int lastEngineExit;
        void SetupUpdates()
        {
            Find<TextBlock>("UpdateVersionText").Text="Текущая версия: "+Updates.CurrentVersion+(UpdateInstall.Installed(AppDomain.CurrentDomain.BaseDirectory)?" · установлена":" · переносная");
            using(var notes=System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("ReleaseNotes.txt"))using(var reader=new StreamReader(notes))Find<TextBox>("UpdateNotes").Text=reader.ReadToEnd();
            Find<Button>("CheckUpdatesButton").Click+=async(s,e)=>await CheckUpdates();
            Find<Button>("InstallUpdateButton").Click+=async(s,e)=>await DownloadUpdate();
            Find<Button>("CancelUpdateButton").Click+=(s,e)=>{if(updateCancellation!=null)updateCancellation.Cancel();};
            Find<Button>("LocalSourcesButton").Click+=(s,e)=>Guard(ShowSources);
            Find<Button>("SourcesButton").Click+=(s,e)=>Guard(()=>OpenLink(Updates.SourceUrl));
            Window.Closed+=(s,e)=>{if(updateCancellation!=null)updateCancellation.Cancel();};
        }
        void UpdateText(string text){Find<TextBlock>("UpdateStatusText").Text=text;}
        void UpdateWorking(bool value)
        {
            Find<Button>("CheckUpdatesButton").IsEnabled=!value;Find<Button>("CancelUpdateButton").IsEnabled=value&&!updateInstalling;
            Find<Button>("InstallUpdateButton").IsEnabled=!value&&updateRelease!=null;
        }
        async Task CheckUpdates()
        {
            if(preview){PreviewUpdate();return;}
            updateRelease=null;Find<TextBox>("UpdateNotes").Text="";UpdateWorking(true);UpdateText("Проверяем стабильные выпуски GitHub…");
            updateCancellation=new CancellationTokenSource();
            try{
                long high=Updates.ReadHigh(SplitData.Root);string current=Updates.CurrentVersion;
                var release=await Task.Run(()=>Updates.Check(new GitHubTransport(),UpdateTrust.PublicKey,current,high,updateCancellation.Token));
                updateRelease=release;
                if(release==null)UpdateText("Нового стабильного обновления нет. Проверено: "+DateTime.Now.ToString("g"));
                else{
                    Updates.SaveHigh(SplitData.Root,release.Manifest.sequence);
                    UpdateText("Доступна версия "+release.Manifest.version+". Подпись издателя проверена.");
                    Find<TextBox>("UpdateNotes").Text=release.Manifest.notes;
                    Find<Button>("InstallUpdateButton").Content=UpdateInstall.Installed(AppDomain.CurrentDomain.BaseDirectory)?"Скачать и установить":"Скачать новую переносную версию";
                }
            }catch(OperationCanceledException){UpdateText("Проверка отменена.");}
            catch(Exception e){UpdateText(e is UserError?e.Message:"Не удалось проверить обновления. Полученные сведения не приняты.");}
            finally{updateCancellation.Dispose();updateCancellation=null;UpdateWorking(false);}
        }
        void PreviewUpdate()
        {
            UpdateText("Доступна следующая версия. Подпись издателя проверена.");
            Find<TextBox>("UpdateNotes").Text="Демонстрация: улучшен раздел обновлений. Профили и настройки сохраняются.\nСеть и установщик не запускались.";
            Find<Button>("InstallUpdateButton").IsEnabled=true;
        }
        async Task DownloadUpdate()
        {
            if(preview){PreviewUpdate();return;}if(updateRelease==null)return;
            UpdateWorking(true);updateCancellation=new CancellationTokenSource();
            try{
                var release=updateRelease;bool installed=UpdateInstall.Installed(AppDomain.CurrentDomain.BaseDirectory);var asset=installed?release.Manifest.installer:release.Manifest.portable;
                if(MessageBox.Show(Window,"Скачать NVVPN "+release.Manifest.version+" ("+(asset.size/1048576.0).ToString("F1")+" МиБ)?\nТекущее подключение продолжит работать.","NVVPN",MessageBoxButton.YesNo,MessageBoxImage.Question)!=MessageBoxResult.Yes)return;
                string stage=UpdateInstall.NewStage();UpdateText("Скачиваем обновление. VPN продолжает работать…");
                long lastMegabyte=-1;
                await Task.Run(()=>Updates.Download(new GitHubTransport(),release,asset,stage,updateCancellation.Token,count=>{long mb=count/1048576;if(mb!=lastMegabyte){lastMegabyte=mb;Window.Dispatcher.BeginInvoke(new Action(()=>UpdateText("Скачано "+mb+" МиБ…")));}}));
                updateCancellation.Token.ThrowIfCancellationRequested();UpdateText("Файл скачан и проверен. Установка требует закрыть NVVPN.");
                string warning=busy?"Для установки нужно завершить VPN. Связь может прерваться.\nЗавершить подключение и установить обновление?":"Сохранить настройки, закрыть NVVPN и установить обновление?";
                if(!installed)warning+="\nПереносная версия будет распакована в новую папку. Прежняя сохранится.";
                if(MessageBox.Show(Window,warning,"NVVPN — установка обновления",MessageBoxButton.YesNo,MessageBoxImage.Warning)!=MessageBoxResult.Yes){UpdateText("Установка отложена. Подключение не изменено. При повторе файл будет загружен и проверен заново.");return;}
                updateInstalling=true;Find<Button>("CancelUpdateButton").IsEnabled=false;connect.IsEnabled=false;
                if(!busy){var rules=Read();SplitData.Save(rules);saved=rules;}
                if(busy){Stop(false);var until=DateTime.UtcNow.AddSeconds(60);while(busy&&DateTime.UtcNow<until)await Task.Delay(100);if(busy||engine.Running||lastEngineExit!=0)throw new UserError("Штатное завершение VPN не подтверждено. Установка не начиналась.");}
                UpdateText("Подготавливаем резервную копию и установку…");
                using(var helper=UpdateInstall.Launch(stage)){
                    var until=DateTime.UtcNow.AddSeconds(10);while(!File.Exists(Path.Combine(stage,"ready"))&&!helper.HasExited&&DateTime.UtcNow<until)await Task.Delay(100);
                    if(!File.Exists(Path.Combine(stage,"ready"))||helper.HasExited)throw new UserError("Программа установки не готова. NVVPN остаётся открыт.");
                }
                exitRequested=true;Window.Close();
            }catch(OperationCanceledException){UpdateText("Загрузка отменена. Установка не запускалась.");}
            catch(Exception e){UpdateText(e is UserError?e.Message:"Обновление не завершено. Повторите проверку. Профили не удалялись.");}
            finally{updateInstalling=false;updateCancellation.Dispose();updateCancellation=null;UpdateWorking(false);}
        }
    }
}

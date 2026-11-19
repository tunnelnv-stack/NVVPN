using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Automation;
using System.Windows.Threading;
using Microsoft.Win32;

namespace FinlandVPN
{
    internal sealed partial class SplitWindow
    {
        internal readonly Window Window;
        readonly ComboBox profiles,interfaces;
        readonly TextBox apps,domains;
        readonly CheckBox subdomains,video;
        readonly TextBlock status,hint,endpoint,session,check,notice,footer,connectIcon,connectLabel;
        readonly Button connect,saveRules,saveSettings,import,browse,removeDomain,removeApp;
        readonly StackPanel homePage,rulesPage,settingsPage,aboutPage;
        readonly Button homeNav,rulesNav,settingsNav,aboutNav;
        readonly ProfileStore store=new ProfileStore(Path.Combine(SplitData.Root,"Profiles"));
        readonly Engine engine=new Engine();
        readonly DispatcherTimer timer=new DispatcherTimer {Interval=TimeSpan.FromSeconds(2)};
        System.Windows.Forms.NotifyIcon tray;
        System.Drawing.Icon trayIcon;
        System.Windows.Forms.ToolStripMenuItem trayDisconnect;
        bool busy,ready,stopping,exitRequested,preserveNotice,loading,agreementPending;
        readonly bool preview;
        SplitRules saved;
        DateTime connectedAt;

        T Find<T>(string name) where T:class{return (T)Window.FindName(name);}
        static Brush Brush(string color){return (Brush)new BrushConverter().ConvertFromString(color);}
        internal SplitWindow(bool preview,string selectedProfile=null)
        {
            this.preview=preview;
            using(var source=Assembly.GetExecutingAssembly().GetManifestResourceStream("MainWindow.xaml"))Window=(Window)XamlReader.Load(source);
            ClampWindowGeometry(Window,SystemParameters.WorkArea);
            // One frozen, shared bitmap; no animation, decoding loop or background work.
            using(var art=Assembly.GetExecutingAssembly().GetManifestResourceStream("ConnectionArt.jpg")){
                var bitmap=new BitmapImage();bitmap.BeginInit();bitmap.CacheOption=BitmapCacheOption.OnLoad;bitmap.StreamSource=art;bitmap.EndInit();bitmap.Freeze();
                var hero=new ImageBrush(bitmap){Stretch=Stretch.UniformToFill,Opacity=0.72};hero.Freeze();Find<Border>("HeroArt").Background=hero;
                var edge=new ImageBrush(bitmap){Viewbox=new Rect(0,0,0.19,1),ViewboxUnits=BrushMappingMode.RelativeToBoundingBox,Stretch=Stretch.UniformToFill,Opacity=0.52};edge.Freeze();
                Find<Border>("SidebarArt").Background=edge;
            }
            connectIcon=Find<TextBlock>("ConnectIcon");connectLabel=Find<TextBlock>("ConnectLabel");
            profiles=Find<ComboBox>("ProfilesBox");interfaces=Find<ComboBox>("InterfacesBox");
            apps=Find<TextBox>("AppsBox");domains=Find<TextBox>("DomainsBox");subdomains=Find<CheckBox>("SubdomainsBox");video=Find<CheckBox>("VideoCompatibilityBox");
            status=Find<TextBlock>("StatusText");hint=Find<TextBlock>("StatusHint");endpoint=Find<TextBlock>("EndpointText");session=Find<TextBlock>("SessionText");check=Find<TextBlock>("CheckText");notice=Find<TextBlock>("NoticeText");footer=Find<TextBlock>("FooterStatus");
            connect=Find<Button>("ConnectButton");saveRules=Find<Button>("SaveRulesButton");saveSettings=Find<Button>("SaveSettingsButton");import=Find<Button>("ImportButton");browse=Find<Button>("BrowseAppButton");
            removeDomain=Find<Button>("RemoveDomainButton");removeApp=Find<Button>("RemoveAppButton");
            homePage=Find<StackPanel>("HomePage");rulesPage=Find<StackPanel>("RulesPage");settingsPage=Find<StackPanel>("SettingsPage");aboutPage=Find<StackPanel>("AboutPage");
            homeNav=Find<Button>("HomeNav");rulesNav=Find<Button>("RulesNav");settingsNav=Find<Button>("SettingsNav");aboutNav=Find<Button>("AboutNav");
            homeNav.Click+=(s,e)=>Page(0);rulesNav.Click+=(s,e)=>Page(1);settingsNav.Click+=(s,e)=>Page(2);aboutNav.Click+=(s,e)=>Page(3);
            import.Click+=(s,e)=>Guard(Import);browse.Click+=(s,e)=>Guard(Browse);saveRules.Click+=(s,e)=>Guard(()=>Save(false));saveSettings.Click+=(s,e)=>Guard(()=>Save(true));
            removeDomain.Click+=(s,e)=>RemoveLine(domains);removeApp.Click+=(s,e)=>RemoveLine(apps);
            apps.TextChanged+=(s,e)=>Edited();domains.TextChanged+=(s,e)=>Edited();subdomains.Click+=(s,e)=>Edited();video.Click+=(s,e)=>Edited();
            Find<CheckBox>("DiagnosticsBox").Click+=(s,e)=>{if(!preview)engine.Diagnostics.Enabled=Find<CheckBox>("DiagnosticsBox").IsChecked==true;};
            Find<Button>("OpenDiagnosticsButton").Click+=(s,e)=>Guard(()=>{
                if(preview)return;string path=engine.Diagnostics.FilePath;SecureFiles.NoLinks(path);
                if(File.Exists(path))Process.Start(new ProcessStartInfo(path){UseShellExecute=true});
                else MessageBox.Show(Window,"Журнал пока пуст. Включите запись и повторите действие, которое нужно проверить.","NVVPN",MessageBoxButton.OK,MessageBoxImage.Information);
            });
            Find<Button>("ClearDiagnosticsButton").Click+=(s,e)=>Guard(()=>{if(preview)return;engine.Diagnostics.Clear();notice.Text="Технические журналы очищены.";preserveNotice=true;});
            Find<Button>("AgreementButton").Click+=(s,e)=>Guard(()=>Agreement.Show(Window,preview));
            Find<TextBlock>("AgreementRevisionText").Text="Редакция "+AgreementDocument.Current.Version+(AgreementDocument.Current.Published?" · условия использования":" · проект");
            Find<Button>("LicensesButton").Click+=(s,e)=>Guard(ShowLicenses);
            SetupUpdates();
            Find<Button>("AmneziaLink").Click+=(s,e)=>Guard(()=>OpenLink("https://github.com/amnezia-vpn/amneziawg-go"));
            Find<Button>("SingBoxLink").Click+=(s,e)=>Guard(()=>OpenLink("https://github.com/SagerNet/sing-box"));
            Find<Button>("WintunLink").Click+=(s,e)=>Guard(()=>OpenLink("https://www.wintun.net/"));
            string version=((AssemblyInformationalVersionAttribute)Attribute.GetCustomAttribute(Assembly.GetExecutingAssembly(),typeof(AssemblyInformationalVersionAttribute))).InformationalVersion;
            Find<TextBlock>("VersionText").Text="NVVPN "+version;Find<TextBlock>("SidebarVersion").Text=version+"  ·  WINDOWS";
            connect.Click+=async(s,e)=>{if(stopping||(busy&&!ready))return;if(busy){Stop(false);}else await Start();};
            Find<Button>("HelpButton").Click+=(s,e)=>MessageBox.Show(Window,"1. Добавьте свой файл .conf и выберите Ethernet или Wi-Fi.\n2. Отключите другой VPN вручную.\n3. Нажмите «Подключиться». Права Windows запрашиваются при открытии программы; само открытие VPN не включает.\n\nРаздел «Без VPN» содержит исключения. В настройках включена совместимость YouTube.\n\nВо время подключения окно можно закрыть — приложение останется в трее. Чтобы остановить VPN, нажмите «Отключиться» или выберите «Выход» в трее.","NVVPN",MessageBoxButton.OK,MessageBoxImage.Information);
            profiles.SelectionChanged+=(s,e)=>{Profile p=profiles.SelectedItem as Profile;endpoint.Text=p==null?"Добавьте профиль":p.Endpoint.Split(':')[0];};
            if(preview){profiles.Items.Add("Демонстрационный профиль");profiles.SelectedIndex=0;interfaces.Items.Add("Ethernet");interfaces.SelectedIndex=0;Apply(new SplitRules {domains=new[]{"vk.com","vk.ru","userapi.com"}});endpoint.Text="192.0.2.1";notice.Text="Демонстрация интерфейса. Соединение не запускалось.";return;}
            Reload(selectedProfile);interfaces.ItemsSource=Engine.Interfaces();interfaces.SelectedIndex=0;Apply(SplitData.LoadExclusions());
            SetupTray();
            Window.StateChanged+=(s,e)=>{if(Window.WindowState==WindowState.Minimized){Window.Hide();tray.Visible=true;}};
            Window.Closing+=(s,e)=>{if(busy&&!exitRequested){e.Cancel=true;Window.Hide();tray.Visible=true;}};
            Window.Closed+=(s,e)=>{timer.Stop();engine.Dispose();if(tray!=null){tray.Visible=false;tray.Dispose();}if(trayIcon!=null)trayIcon.Dispose();};
            timer.Tick+=(s,e)=>Refresh();timer.Start();Refresh();
        }
        internal static void ClampWindowGeometry(Window window,Rect workArea){
            if(workArea.IsEmpty||workArea.Width<=0||workArea.Height<=0)return;
            double width=Math.Max(1,workArea.Width-16),height=Math.Max(1,workArea.Height-16);
            window.MinWidth=Math.Min(window.MinWidth,width);window.MinHeight=Math.Min(window.MinHeight,height);
            window.Width=Math.Min(window.Width,width);window.Height=Math.Min(window.Height,height);
        }
        void SetupTray()
        {
            trayIcon=System.Drawing.Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
            tray=new System.Windows.Forms.NotifyIcon {Icon=trayIcon,Text="NVVPN",Visible=true};
            var menu=new System.Windows.Forms.ContextMenuStrip();
            menu.Items.Add("Открыть NVVPN",null,(s,e)=>Window.Dispatcher.BeginInvoke(new Action(Show)));
            trayDisconnect=new System.Windows.Forms.ToolStripMenuItem("Отключиться",null,(s,e)=>Window.Dispatcher.BeginInvoke(new Action(()=>Stop(false))));
            menu.Items.Add(trayDisconnect);menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
            menu.Items.Add("Выход",null,(s,e)=>Window.Dispatcher.BeginInvoke(new Action(()=>{exitRequested=true;if(busy)Stop(true);else Window.Close();})));
            tray.ContextMenuStrip=menu;tray.DoubleClick+=(s,e)=>Window.Dispatcher.BeginInvoke(new Action(Show));
        }
        void Show(){Window.Show();Window.WindowState=WindowState.Normal;Window.Activate();}
        void Page(int page){
            var pages=new[]{homePage,rulesPage,settingsPage,aboutPage};var buttons=new[]{homeNav,rulesNav,settingsNav,aboutNav};
            for(int i=0;i<pages.Length;i++){pages[i].Visibility=page==i?Visibility.Visible:Visibility.Collapsed;buttons[i].Background=Brush(page==i?"#174D52":"#00000000");buttons[i].BorderBrush=Brush(page==i?"#4EE0D7":"#00000000");buttons[i].FontWeight=page==i?FontWeights.SemiBold:FontWeights.Normal;}
            Find<ScrollViewer>("PageScroll").ScrollToTop();
        }
        internal void PreviewPage(int page){Page(page);}
        void UpdateTray(){if(trayDisconnect!=null)trayDisconnect.Enabled=busy&&!stopping;if(tray!=null)tray.Text="NVVPN · "+(stopping?"Отключаемся":ready?"Подключён":busy?"Подключаемся":"Не подключён");}
        void Stop(bool exiting){
            if(!busy)return;
            stopping=true;ready=false;PrimaryAction("Отключение…","…",false);
            status.Text="Отключаемся";status.Foreground=Brush("#E8F0F5");hint.Text=exiting?"Завершаем соединение и закрываем приложение…":"Возвращаем обычное подключение…";
            notice.Text="VPN отключается. Дождитесь завершения перед новым подключением.";
            footer.Text="Дождитесь завершения соединения";UpdateTray();if(!preview)engine.Stop();
        }
        void Event(string ev,SplitRules rules){
            if(ev=="stopping"){Stop(exitRequested);return;}
            if(stopping)return;
            if(ev=="vpn-verified")check.Text="Доступ к серверу подтверждён";
            else if(ev=="udp-verified")check.Text="Проверки сервера пройдены";
            else if(ev=="ready"){ready=true;connectedAt=DateTime.UtcNow;PrimaryAction("Отключить","■",true);status.Text="Подключён";status.Foreground=Brush("#BAF2DC");hint.Text="Ваш трафик идёт через VPN. Исключения — напрямую.";notice.Text=rules.video_compatibility?"VPN работает. Совместимость YouTube включена.":"VPN работает. Совместимость YouTube выключена.";footer.Text="Закрытие окна свернёт NVVPN в трей";UpdateTray();}
            else if(ev=="system-https-selected-vpn"||ev=="system-https-other-vpn")check.Text="Интернет через VPN проверен";
        }
        internal void PreviewState(string value){
            if(value=="connecting"||value=="connected"||value=="stopping"){SetBusy(true);status.Text="Подключаемся";hint.Text="Проверяем сервер перед подключением…";if(value!="connecting")Event("ready",saved);if(value=="stopping")Stop(false);}
            else if(value=="idle"){SetBusy(false);status.Text="Не подключён";status.Foreground=Brush("#ECF5F8");hint.Text="Выберите профиль и подключитесь";session.Text="—";check.Text="Соединение будет проверено при подключении";notice.Text="Демонстрация интерфейса. Соединение не запускалось.";footer.Text="Готов к подключению";}
            else if(value=="error"){SetBusy(false);status.Text="Ошибка подключения";status.Foreground=Brush("#FFB4A9");hint.Text="Проверьте сеть и попробуйте ещё раз.";check.Text="Проверка соединения не завершена";}
        }
        internal static void TestPreview(Action<bool> assert){
            var w=new SplitWindow(true);assert(!w.engine.Diagnostics.Enabled&&w.Find<CheckBox>("DiagnosticsBox").IsChecked!=true);var content=(FrameworkElement)w.Window.Content;content.Measure(new Size(1000,780));content.Arrange(new Rect(0,0,1000,780));content.UpdateLayout();assert(!w.busy&&!w.engine.Running);
            for(int i=0;i<4;i++){w.Page(i);assert(new[]{w.homePage,w.rulesPage,w.settingsPage,w.aboutPage}[i].Visibility==Visibility.Visible);}
            w.trayDisconnect=new System.Windows.Forms.ToolStripMenuItem();w.SetBusy(true);assert(w.trayDisconnect.Enabled&&!w.connect.IsEnabled&&w.connectLabel.Text=="Подключение…");w.Event("ready",w.saved);assert(w.ready&&!w.profiles.IsEnabled&&w.connect.IsEnabled);
            w.Stop(false);w.Event("ready",w.saved);assert(!w.ready&&!w.connect.IsEnabled&&!w.trayDisconnect.Enabled&&w.status.Text=="Отключаемся");
            w.SetBusy(false);assert(w.profiles.IsEnabled&&w.connect.IsEnabled&&!w.stopping);
            w.domains.Text="example.com\r\nexample.org";w.domains.CaretIndex=0;w.RemoveLine(w.domains);assert(w.domains.Text=="example.org");
            w.video.IsChecked=false;var settings=w.ReadSection(true);assert(!settings.video_compatibility&&settings.domains.SequenceEqual(w.saved.domains));
            var rules=w.ReadSection(false);assert(rules.video_compatibility==w.saved.video_compatibility&&rules.domains.Single()=="example.org");
            w.domains.CaretIndex=w.domains.Text.Length;w.RemoveLine(w.domains);assert(w.domains.Text.Length==0);
            var normal=new Window {Width=1120,Height=840,MinWidth=900,MinHeight=650};
            ClampWindowGeometry(normal,new Rect(0,0,1920,1040));assert(normal.Width==1120&&normal.Height==840&&normal.MinHeight==650);
            ClampWindowGeometry(normal,new Rect(0,0,960,520));assert(normal.Width<=944&&normal.Height<=504&&normal.MinWidth<=944&&normal.MinHeight<=504);normal.Close();
            var sidebar=w.Find<ScrollViewer>("SidebarScroll");
            content.Measure(new Size(960,520));content.Arrange(new Rect(0,0,960,520));content.UpdateLayout();assert(sidebar.ScrollableHeight>0);
            sidebar.ScrollToBottom();content.UpdateLayout();var version=w.Find<TextBlock>("SidebarVersion");
            double bottom=version.TransformToAncestor(sidebar).Transform(new Point(0,version.ActualHeight)).Y;assert(bottom<=sidebar.ViewportHeight+1&&bottom>0);
            content.Measure(new Size(1120,800));content.Arrange(new Rect(0,0,1120,800));content.UpdateLayout();assert(sidebar.ScrollableHeight==0);
            assert(!w.engine.Running);w.trayDisconnect.Dispose();w.Window.Close();
        }
        void RemoveLine(TextBox box){
            if(busy||box.Text.Length==0)return;
            string text=box.Text;int caret=Math.Min(box.CaretIndex,text.Length);
            int previous=caret==0?-1:text.LastIndexOf('\n',caret-1);
            int start=previous+1,next=text.IndexOf('\n',caret);
            int end=next<0?text.Length:next+1;
            if(next<0&&start>0){start--;if(start>0&&text[start-1]=='\r')start--;}
            box.Select(start,end-start);box.SelectedText="";box.Focus();
        }

        void Edited(){if(loading||busy)return;preserveNotice=true;notice.Text="Есть несохранённые изменения. Сохраните их на соответствующей странице. При подключении применяются все текущие настройки.";}
        static void OpenLink(string url){Process.Start(new ProcessStartInfo(url){UseShellExecute=true});}
        void ShowLicenses(){
            string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"THIRD-PARTY-NOTICES.txt");SecureFiles.NoLinks(path);
            if(!File.Exists(path))throw new UserError("Файл лицензий не найден. Распакуйте полный комплект NVVPN.");
            var text=new TextBox{Text=File.ReadAllText(path),IsReadOnly=true,TextWrapping=TextWrapping.Wrap,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,Background=Brush("#101B24"),Foreground=Brush("#E8F0F5"),Padding=new Thickness(18)};
            new Window{Title="NVVPN — лицензии и уведомления",Owner=Window,Width=780,Height=620,Content=text,WindowStartupLocation=WindowStartupLocation.CenterOwner}.ShowDialog();
        }
        void ShowSources(){
            string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"NVVPN-Sources.zip");SecureFiles.NoLinks(path);
            if(!File.Exists(path))throw new UserError("Архив исходников не найден. Распакуйте полный комплект NVVPN.");
            Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"explorer.exe"),"/select,\""+path+"\""){UseShellExecute=true});
        }
        void Guard(Action action){try{action();}catch(Exception e){Error(e);}}
        internal static void Error(Exception e){MessageBox.Show(e is UserError||e is AgreementRequiredException?e.Message:"Не удалось выполнить операцию. Конфиденциальные данные скрыты.","NVVPN",MessageBoxButton.OK,MessageBoxImage.Warning);}
        void Refresh()
        {
            UpdateTray();
            if((agreementPending||updateInstalling)&&!busy){connect.IsEnabled=false;return;}
            if(busy){if(ready){var elapsed=DateTime.UtcNow-connectedAt;session.Text=elapsed.TotalHours>=1?elapsed.ToString(@"h\:mm\:ss"):elapsed.ToString(@"mm\:ss");}return;}
            bool old=!preview&&Engine.OldVpnActive();bool profile=profiles.SelectedItem is Profile;bool nic=interfaces.SelectedItem is string;
            PrimaryAction("Подключиться","▶",!old&&(!profile||nic));
            if(!preserveNotice)notice.Text=old?"Сейчас работает прежний Finland VPN. Отключите его вручную перед подключением здесь.":!profile?"Добавьте свой профиль .conf. Он хранится только на этом устройстве.":!nic?"Нет доступного Ethernet или Wi-Fi. Проверьте обычное подключение к интернету.":"Готово. Все приложения через VPN, кроме выбранных исключений.";
            footer.Text=old?"Прежний VPN работает":"Автоматического подключения нет";
        }
        void PrimaryAction(string label,string icon,bool enabled){
            connectLabel.Text=label;connectIcon.Text=icon;connect.IsEnabled=enabled;
            AutomationProperties.SetName(connect,label);
            AutomationProperties.SetHelpText(connect,busy&&!ready&&!stopping?"Идёт проверка подключения. Отмена доступна в меню значка NVVPN в трее.":stopping?"Дождитесь завершения отключения.":ready?"Останавливает VPN и возвращает обычное подключение.":"Подключает VPN. Если профиль отсутствует, откроется выбор файла .conf.");
        }
        void SetBusy(bool value){busy=value;ready=false;profiles.IsEnabled=interfaces.IsEnabled=apps.IsEnabled=domains.IsEnabled=subdomains.IsEnabled=video.IsEnabled=saveRules.IsEnabled=saveSettings.IsEnabled=import.IsEnabled=browse.IsEnabled=removeDomain.IsEnabled=removeApp.IsEnabled=!value;stopping=false;PrimaryAction(value?"Подключение…":"Подключиться",value?"…":"▶",!value);UpdateTray();}
        void Apply(SplitRules r){loading=true;saved=r;apps.Text=String.Join(Environment.NewLine,r.apps);domains.Text=String.Join(Environment.NewLine,r.domains);subdomains.IsChecked=r.subdomains;video.IsChecked=r.video_compatibility;loading=false;}
        SplitRules Read(){var r=new SplitRules {mode="except",apps=Lines(apps.Text),domains=Lines(domains.Text),subdomains=subdomains.IsChecked==true,video_compatibility=video.IsChecked==true};r.Validate();return r;}
        static string[] Lines(string value){return value.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries).Select(s=>s.Trim()).Where(s=>s.Length>0).ToArray();}
        SplitRules ReadSection(bool settings){
            var r=SplitData.Json.Deserialize<SplitRules>(SplitData.Json.Serialize(saved));
            if(settings)r.video_compatibility=video.IsChecked==true;
            else{r.apps=Lines(apps.Text);r.domains=Lines(domains.Text);r.subdomains=subdomains.IsChecked==true;}
            r.Validate();return r;
        }
        void Save(bool settings){if(preview||busy)return;var r=ReadSection(settings);SplitData.Save(r);saved=r;preserveNotice=true;notice.Text=(settings?"Настройка YouTube сохранена.":"Исключения сохранены.")+" Применится при следующем подключении.";}
        void Reload(string id){var list=store.List();profiles.ItemsSource=list;profiles.SelectedItem=list.FirstOrDefault(p=>p.Id==id)??list.FirstOrDefault(p=>p.Name.EndsWith("Windows-Test",StringComparison.OrdinalIgnoreCase))??list.FirstOrDefault();}
        void Import(){if(preview||busy)return;var dialog=new OpenFileDialog {Filter="Профиль AmneziaWG (*.conf)|*.conf",InitialDirectory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),"VPN","Conf")};if(dialog.ShowDialog(Window)==true){Reload(store.Import(dialog.FileName).Id);preserveNotice=false;Refresh();}}
        void Browse(){if(preview||busy)return;var dialog=new OpenFileDialog {Filter="Приложение Windows (*.exe)|*.exe"};if(dialog.ShowDialog(Window)==true)apps.Text=(apps.Text.Trim()+Environment.NewLine+dialog.FileName).Trim();}
        async System.Threading.Tasks.Task Start()
        {
            if(preview||busy||agreementPending||updateInstalling||UpdateInstall.Updating())return;
            agreementPending=true;
            try{
                var profile=profiles.SelectedItem as Profile;if(profile==null){Import();return;}
                connect.IsEnabled=false;
                if(!Agreement.EnsureAccepted(Window)){preserveNotice=true;notice.Text="Соглашение не принято. Подключение не запускалось.";return;}
                string nic=interfaces.SelectedItem as string;if(nic==null)throw new UserError("Выберите обычное подключение Ethernet или Wi-Fi.");
                var rules=Read();SplitData.Save(rules);saved=rules;
                if(Engine.OldVpnActive())throw new UserError("Сначала вручную отключите прежний Finland VPN.");
                if(!Engine.Admin)throw new UserError("Перезапустите NVVPN и подтвердите запрос прав Windows.");
                preserveNotice=false;ready=false;SetBusy(true);Page(0);status.Text="Подключаемся";status.Foreground=Brush("#E8F0F5");hint.Text="Проверяем сервер перед подключением…";session.Text="—";check.Text="Проверяем доступ к интернету";notice.Text="Настройки обычного подключения сохраняются. Дождитесь проверки сервера.";
                string failure=null;
                int code=await engine.Run("--run",SplitData.Envelope(profile,rules,nic,false),ev=>{
                    if(ev.StartsWith("error",StringComparison.Ordinal)){failure=ev;}
                    Event(ev,rules);
                });
                lastEngineExit=code;preserveNotice=code!=0;if(code!=0)notice.Text="Подключение не завершено. Проверьте сеть и настройки профиля.";
                ready=false;status.Foreground=Brush(code==0?"#E8F0F5":"#FFB4A9");status.Text=code==0?"Отключён":"Не удалось подключиться";hint.Text=code==0?"Обычное подключение восстановлено":"Проверьте сеть и попробуйте ещё раз. Прежний клиент можно включить вручную.";check.Text=code==0?"Сеанс завершён":failure==null?"Проверка соединения не завершена":"Проверка соединения завершилась ошибкой";session.Text="—";
            }catch(System.ComponentModel.Win32Exception e){if(e.NativeErrorCode!=1223)Error(e);status.Text="Не подключён";hint.Text="Подключение не запускалось.";}
            catch(Exception e){Error(e);status.Text="Не подключён";hint.Text="Проверьте настройки и повторите подключение.";}
            finally{agreementPending=false;ready=false;SetBusy(false);Refresh();if(exitRequested)Window.Close();}
        }
    }
}

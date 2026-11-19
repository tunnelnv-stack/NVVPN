using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Markup;

namespace FinlandVPN
{
    internal sealed class AgreementDialog
    {
        internal readonly Window Window;
        internal readonly CheckBox Consent;
        internal readonly Button Accept,Cancel;
        internal readonly TextBox Document;
        readonly bool canAccept;
        static Brush Color(string value){return (Brush)new BrushConverter().ConvertFromString(value);}
        internal AgreementDialog(AgreementDocument document,bool acceptanceMode,bool alreadyAccepted,string acceptedRevision=null)
        {
            canAccept=acceptanceMode&&document.Published;
            Window=new Window{Title="NVVPN — пользовательское соглашение",Width=790,Height=720,MinWidth=560,MinHeight=480,
                Background=Color("#101B24"),Foreground=Color("#E8F0F5"),FontFamily=new FontFamily("Segoe UI"),FontSize=14,
                WindowStartupLocation=WindowStartupLocation.CenterOwner,ShowInTaskbar=false};
            Window.Resources[typeof(Button)]=(Style)XamlReader.Parse(@"<Style xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' TargetType='Button'><Setter Property='Template'><Setter.Value><ControlTemplate TargetType='Button'><Border x:Name='Surface' xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml' Background='{TemplateBinding Background}' CornerRadius='7' BorderBrush='#42616D' BorderThickness='1' Padding='{TemplateBinding Padding}'><ContentPresenter HorizontalAlignment='Center' VerticalAlignment='Center'/></Border><ControlTemplate.Triggers><Trigger Property='IsEnabled' Value='False'><Setter TargetName='Surface' Property='Opacity' Value='0.45'/></Trigger><Trigger Property='IsMouseOver' Value='True'><Setter TargetName='Surface' Property='BorderBrush' Value='#47D9C4'/></Trigger><Trigger Property='IsKeyboardFocused' Value='True'><Setter TargetName='Surface' Property='BorderBrush' Value='#47D9C4'/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>");
            // Keep the modal controls reachable on a high-DPI desktop with a small logical work area.
            var work=SystemParameters.WorkArea;
            if(work.Width>0&&work.Height>0){double width=Math.Max(1,work.Width-16),height=Math.Max(1,work.Height-16);Window.MinWidth=Math.Min(Window.MinWidth,width);Window.MinHeight=Math.Min(Window.MinHeight,height);Window.Width=Math.Min(Window.Width,width);Window.Height=Math.Min(Window.Height,height);}
            var layout=new Grid{Margin=new Thickness(24),Background=Color("#101B24")};
            layout.RowDefinitions.Add(new RowDefinition{Height=GridLength.Auto});
            layout.RowDefinitions.Add(new RowDefinition{Height=new GridLength(1,GridUnitType.Star)});
            layout.RowDefinitions.Add(new RowDefinition{Height=GridLength.Auto});
            layout.RowDefinitions.Add(new RowDefinition{Height=GridLength.Auto});
            var header=new StackPanel();
            header.Children.Add(new TextBlock{Text="Условия и конфиденциальность",FontSize=24,FontWeight=FontWeights.SemiBold,TextWrapping=TextWrapping.Wrap});
            header.Children.Add(new TextBlock{Text="Редакция "+document.Version+" · "+document.Date,Margin=new Thickness(0,6,0,8),Foreground=Color("#9FB2C0")});
            if(!acceptanceMode)header.Children.Add(new TextBlock{Text=acceptedRevision==null?"Сохранённое принятие не найдено.":"Сохранённая редакция: "+acceptedRevision,Margin=new Thickness(0,0,0,8),Foreground=Color("#9FB2C0")});
            header.Children.Add(new TextBlock{Text=!document.Published?"Проект не утверждён. Подключение в этой тестовой сборке недоступно.":alreadyAccepted?"Эта редакция уже принята на этом устройстве.":acceptanceMode?"Прочитайте условия. Подключение начнётся только после явного согласия.":"Эта редакция ещё не принята на этом устройстве. Принятие доступно при подключении.",
                TextWrapping=TextWrapping.Wrap,Foreground=Color(document.Published?"#9FB2C0":"#FFD39A"),Margin=new Thickness(0,0,0,14)});
            layout.Children.Add(header);
            Document=new TextBox{Text=document.Text,IsReadOnly=true,AcceptsReturn=true,TextWrapping=TextWrapping.Wrap,
                VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled,
                Background=Color("#182933"),Foreground=Color("#E8F0F5"),BorderBrush=Color("#344B58"),Padding=new Thickness(16)};
            Grid.SetRow(Document,1);layout.Children.Add(Document);
            Consent=new CheckBox{Content=new TextBlock{Text="Я ознакомился и принимаю условия",TextWrapping=TextWrapping.Wrap},
                IsChecked=false,IsEnabled=canAccept,Foreground=Color("#E8F0F5"),Margin=new Thickness(0,16,0,10),Visibility=acceptanceMode?Visibility.Visible:Visibility.Collapsed};
            Grid.SetRow(Consent,2);layout.Children.Add(Consent);
            var buttons=new StackPanel{Orientation=Orientation.Horizontal,HorizontalAlignment=HorizontalAlignment.Right,Margin=new Thickness(0,8,0,0)};
            Cancel=new Button{Content=acceptanceMode?"Отмена":"Закрыть",IsCancel=true,IsDefault=false,MinWidth=104,Padding=new Thickness(16,10,16,10),Margin=new Thickness(0,0,10,0),
                Background=Color("#293F4B"),Foreground=Color("#E8F0F5"),BorderThickness=new Thickness(0)};
            Accept=new Button{Content="Принять и подключиться",IsEnabled=false,IsDefault=false,Padding=new Thickness(16,10,16,10),
                Background=Color("#147D72"),Foreground=Brushes.White,BorderThickness=new Thickness(0),Visibility=acceptanceMode?Visibility.Visible:Visibility.Collapsed};
            Consent.Checked+=(s,e)=>Accept.IsEnabled=canAccept&&Consent.IsChecked==true;
            Consent.Unchecked+=(s,e)=>Accept.IsEnabled=false;
            Accept.Click+=(s,e)=>{if(canAccept&&Consent.IsChecked==true)Window.DialogResult=true;};
            Cancel.Click+=(s,e)=>Window.Close();
            buttons.Children.Add(Cancel);buttons.Children.Add(Accept);Grid.SetRow(buttons,3);layout.Children.Add(buttons);Window.Content=layout;
        }
    }
}

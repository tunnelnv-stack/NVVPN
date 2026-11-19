using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Windows;

namespace FinlandVPN
{
    internal enum StartupAction { Open, Elevate, Reject }

    internal static class Startup
    {
        // Keep asInvoker: installer helpers and offline diagnostics must not request UAC.
        internal static StartupAction Decide(bool admin, string expectedSid, string currentSid)
        {
            if (expectedSid != null)
                return admin && String.Equals(expectedSid, currentSid, StringComparison.Ordinal) ? StartupAction.Open : StartupAction.Reject;
            return admin ? StartupAction.Open : StartupAction.Elevate;
        }

        internal static bool Prepare(string expectedSid, string selectedProfile)
        {
            string sid = WindowsIdentity.GetCurrent().User.Value;
            var action = Decide(Engine.Admin, expectedSid, sid);
            if (action == StartupAction.Reject)
                throw new UserError("Откройте NVVPN с повышением прав той же учётной записи Windows. Профили другой учётной записи недоступны. Подключение не запускалось.");
            if (action == StartupAction.Open) return true;
            // Serialize requests while the Windows consent dialog is open, without taking the UI mutex from the child.
            bool created;
            using (var gate = new Mutex(false, @"Local\NeverVPN.Launch", out created)) {
                if (!created) return false;
                try {
                    string arguments = "--elevated " + sid + (selectedProfile == null ? "" : " " + selectedProfile);
                    using (var child = Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, arguments) {
                        UseShellExecute = true, Verb = "runas", WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
                    })) {
                        if (child == null) throw new UserError("Не удалось открыть NVVPN с правами администратора.");
                    }
                } catch (Win32Exception e) {
                    if (e.NativeErrorCode != 1223) throw;
                    MessageBox.Show("Запуск отменён. Для работы NVVPN нужны права администратора. VPN не включался. Программу можно открыть снова.", "NVVPN", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                return false;
            }
        }

        internal static bool AlreadyOpen()
        {
            try { using (Mutex.OpenExisting(@"Local\NeverVPN.UI")) return true; }
            catch (WaitHandleCannotBeOpenedException) { return false; }
            catch (UnauthorizedAccessException) { return true; }
        }

        internal static void ExplainAlreadyOpen()
        {
            MessageBox.Show("NVVPN уже запущен. Откройте его двойным щелчком по значку NV в трее. Для смены версии сначала выберите «Выход» в работающем приложении.", "NVVPN", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}

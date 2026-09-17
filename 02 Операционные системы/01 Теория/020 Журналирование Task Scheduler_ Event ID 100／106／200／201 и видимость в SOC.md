# Журналирование планировщика задач Windows: ключевые события и видимость в SOC

## Контекст: канал TaskScheduler/Operational как источник событий безопасности

Планировщик задач Windows (Task Scheduler) — штатный компонент операционной системы, ответственный за выполнение программ или скриптов по расписанию, в ответ на системные события или при входе пользователя. В инфраструктуре предприятия он обеспечивает автоматизацию обслуживания, применение обновлений и запуск фоновых процессов. Одновременно эта же функциональность широко эксплуатируется злоумышленниками: согласно отчётам Red Canary, вредоносное использование запланированных задач стабильно входит в число наиболее распространённых техник закрепления (persistence) и выполнения кода с повышенными привилегиями [Scheduled Task | Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/scheduled-task). Технике присвоен идентификатор MITRE ATT&CK **T1053.005 (Scheduled Task)**.

С точки зрения SOC критически важно регистрировать факты создания, изменения и выполнения задач. Основным источником таких сведений служит специализированный канал журнала Windows: **Microsoft-Windows-TaskScheduler/Operational**. Он предоставляет детализированные события о жизненном цикле задачи и её действий, однако по умолчанию **отключён**. Активация журнала выполняется вручную или централизованно через групповые политики, и без неё мониторинг планировщика практически слеп.

Параллельно в журнале **Security** могут записываться события аудита, если включена политика «Аудит создания запланированных задач» (события с кодами 4698, 4702 и т.д.). Эти события содержат меньше технических подробностей о самом действии задачи, но регистрируют факт создания или изменения с указанием учётной записи и XML-определения задачи. Для полноценной картины в SOC оба канала должны собираться и коррелироваться.

Ниже представлена сравнительная характеристика двух основных журнальных источников и ключевых событий, фигурирующих в теме.

| Источник / Код события | Описание события | Условия генерации | Значение для SOC |
|------------------------|-------------------|--------------------|-------------------|
| **Microsoft-Windows-TaskScheduler/Operational** (Event ID 100) | Task Started — запущен экземпляр задачи | Задача переходит в состояние выполнения по любому триггеру | Фиксирует начало работы задачи; позволяет отследить незапланированные запуски |
| **Microsoft-Windows-TaskScheduler/Operational** (Event ID 106) | Task registered — задача зарегистрирована в системе | Создание новой задачи (локально или удалённо) | Основной индикатор появления новой запланированной задачи, критично для обнаружения персистенции |
| **Microsoft-Windows-TaskScheduler/Operational** (Event ID 200) | Action started — запущено действие в рамках задачи | Начало выполнения конкретного действия (запуск процесса, скрипта) | Показывает, какой именно исполняемый файл или команда была запущена; ключевое событие для анализа вредоносной активности |
| **Microsoft-Windows-TaskScheduler/Operational** (Event ID 201) | Action completed — действие завершено | Завершение выполнения действия с указанием кода возврата | Позволяет оценить успешность выполнения и сопоставить время действия с другими артефактами |
| **Security** (Event ID 4698) | A scheduled task was created | Создание задачи при включённом аудите создания задач | Документирует факт создания с указанием пользователя и XML; полезен для аудита административных действий |
| **Security** (Event ID 4702) | A scheduled task was updated | Изменение существующей задачи | Аналогично 4698, но для модификаций |

Как видно из таблицы, детальная информация о действиях (action) доступна только в канале Operational, тогда как журнал Security даёт более формализованный учёт операций регистрации. В SOC-аналитике события 106, 200, 201 образуют костяк для выявления подозрительных запланированных задач, а событие 100 часто служит связующим звеном при восстановлении хронологии.

Важно различать уровни «задача» (task) и «действие» (action). Задача — это контейнер, содержащий триггеры, условия и набор действий. Одна задача может включать несколько действий, и каждое из них будет порождать собственные события 200 и 201. Событие 100 фиксирует старт задачи как целого, а событие 200 — старт отдельного действия. В контексте злонамеренной активности аналитика чаще всего интересует именно содержимое события 200, так как оно раскрывает командную строку и путь к исполняемому файлу.

Таким образом, аспект журналирования (Event ID 100, 106, 200, 201) неразрывно связан с аспектом видимости в SOC: только при включённом и собираемом журнале Operational можно обеспечить детектирование техники T1053.005 и проводить расследования.

## Внутреннее устройство событий: структура Event ID 100, 106, 200, 201

Каждое событие в канале TaskScheduler/Operational имеет стандартную XML-структуру системного журнала Windows, где в элементе `System` фиксируются временная метка, код события, уровень, а в элементе `EventData` — специфичные для планировщика поля. Для SOC-аналитика первостепенное значение имеют имена задачи, пути к исполняемым файлам и аргументы командной строки.

### Event ID 106 – «Task registered»

Генерируется при создании новой задачи в любой пользовательской или системной ветке планировщика. Срабатывает как при локальном создании через `taskschd.msc` или `schtasks.exe`, так и при импорте XML-определения. В параметрах события передаются:

- **TaskName** – полный путь к задаче в иерархии планировщика, например `\Microsoft\Windows\UpdateOrchestrator\Reboot_AC`.
- **UserContext** – учётная запись, от имени которой зарегистрирована задача (может быть пустым для системных задач).
- **InstanceId** – GUID экземпляра процесса регистрации.

Примерная иллюстративная структура (поля `EventData`):

```
- TaskName: \Microsoft\Windows\WDI\ResolutionHost
- UserContext: NT AUTHORITY\SYSTEM
- InstanceId: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
```

Для задач злоумышленников характерно размещение в корне или в папках с названиями, маскирующимися под легитимные (`\Microsoft\Windows\Update` и т.п.). Событие 106 — первое звено в цепочке закрепления.

### Event ID 100 – «Task Started»

Отражает старт экземпляра задачи, вызванного любым триггером (по расписанию, событию, входу пользователя и т.д.). Этот код появляется в логе даже в случае последующего отказа запуска действия. Событие содержит:

- **TaskName** – имя задачи.
- **InstanceId** – идентификатор конкретного экземпляра запуска.
- **UserContext** – учётная запись, под которой работает задача.
- **ProcessId** – идентификатор процесса хоста задачи (taskhostw.exe или Task Scheduler engine).

Структура EventData (иллюстративная):

```
- TaskName: \Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser
- InstanceId: {YYYYYYYY-YYYY-YYYY-YYYY-YYYYYYYYYYYY}
- UserContext: NT AUTHORITY\SYSTEM
- ProcessId: 1234
```

SOC-аналитики используют событие 100 для подтверждения факта запуска и как точку синхронизации при построении таймлайна. Однако само по себе оно не раскрывает вредоносной нагрузки, поэтому требуется корреляция с событиями 200.

### Event ID 200 – «Action started»

Событие генерируется, когда запланированная задача начинает выполнять одно из своих действий. Оно содержит наиболее ценные для расследования данные:

- **TaskName** – родительская задача.
- **ActionName** – понятное имя действия (обычно совпадает с именем задачи).
- **TaskInstanceId** – GUID экземпляра задачи (соответствует InstanceId из события 100).
- **EnginePID** – PID процесса Task Scheduler engine.
- **ActionType** – тип действия: «Execute» (запуск процесса), «ComHandler» или другие.
- **Command** – исполняемый файл и аргументы командной строки.
- **WorkingDirectory** – рабочий каталог (часто пустой у вредоносных задач).

Иллюстративная схема полей:

```
- TaskName: \Persistence\Updater
- ActionName: Updater
- TaskInstanceId: {ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ}
- EnginePID: 5678
- ActionType: Execute
- Command: "C:\Users\user\AppData\Roaming\payload.exe"
- WorkingDirectory:
```

Именно прочтение поля `Command` позволяет выявить запуск вредоносного файла, скрипта PowerShell или cmd.exe с подозрительными аргументами. В случае легитимных действий путь обычно указывает на системный каталог (`System32`) и подписанный исполняемый файл.

### Event ID 201 – «Action completed»

Завершающее событие цепочки. Фиксирует код возврата запущенного процесса. Поля:

- **TaskName** – задача.
- **ActionName** – имя действия.
- **TaskInstanceId** – GUID экземпляра.
- **ResultCode** – HRESULT или код завершения процесса (например, 0x0 — успех).

Структура:

```
- TaskName: \Persistence\Updater
- ActionName: Updater
- TaskInstanceId: {ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ}
- ResultCode: 0x0
```

Событие 201 помогает отличить успешно отработавшую вредоносную нагрузку от сбойной, а также позволяет зафиксировать завершение действия и, таким образом, временные рамки активности.

Дополнительно в журнале присутствуют Event ID 140 (Task registration updated) и 141 (Task registration deleted), которые фиксируют изменения и удаление задач. Они могут дополнять картину, однако основной четвёрки (100/106/200/201) обычно достаточно для выявления большинства вредоносных сценариев.

Ниже приведена сводная таблица ключевых полей для быстрого сопоставления:

| Код события | Ключевые поля в EventData | Типичный индикатор в SOC |
|-------------|---------------------------|---------------------------|
| 106 | TaskName, UserContext | Появление новой задачи с подозрительным именем или в нестандартной ветке |
| 100 | TaskName, InstanceId, ProcessId | Фиксация запуска задачи; сопоставление InstanceId с событиями 200/201 |
| 200 | TaskName, Command, ActionType | Запуск процесса из пользовательских временных каталогов, cmd.exe с закодированной строкой и т.п. |
| 201 | TaskName, ResultCode | Успешное завершение (0x0) после подозрительного действия подтверждает выполнение |

Таким образом, структурное понимание каждого события позволяет выстраивать цепочки детектирования и корреляции.

## Применение в SOC: сбор, детектирование и расследование

Практическая работа SOC с журналом TaskScheduler начинается с его **включения**. В корпоративной среде это делается через групповые политики: `Computer Configuration → Administrative Templates → Windows Components → Task Scheduler → Turn on logging for task registration` (включает события 106, 200, 201) [Microsoft Windows - Wirespeed](https://docs.wirespeed.co/integrations/microsoft-windows). Также можно активировать весь канал Operational через PowerShell командой `wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true` или через GUI Event Viewer.

Сбор событий реализуется агентами (Winlogbeat, NXLog, агент SIEM) с указанием источника `Microsoft-Windows-TaskScheduler/Operational` и формата XML или текстового. В Splunk, например, используется sourcetype `XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational` [Detection: WinEvent Windows Task Scheduler Event Action Started | Splunk Security Content](https://research.splunk.com/endpoint/b3632472-310b-11ec-9aab-acde48001122). Важно настроить парсинг полей `EventData` для извлечения `TaskName`, `Command`, `ResultCode` и т.д.

### Правила детектирования

Построение детектов основывается на анализе известных злонамеренных шаблонов: запуск из `AppData\Roaming`, `Temp`, использование `cmd.exe /c`, `powershell -enc` и т.п. Ниже приведён пример поискового запроса Splunk (SPL), регистрирующего запуски действий с подозрительным командным путём. Артефакт:

```spl
`wineventlog_task_scheduler` EventCode=200
| eval Command=coalesce(EventData_Xml.EventData.Data[@Name="Command"], EventData.Data)
| search Command IN ("*\\AppData\\*", "*\\Temp\\*", "*cmd.exe*", "*powershell*")
| stats count by TaskName, Command, Computer
| where count > 0
| sort - count
```

Этот запрос опирается на макрос `wineventlog_task_scheduler`, определённый в Splunk Security Content как `(source="XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational" OR source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational")`. Он извлекает события с кодом 200 и фильтрует те, у которых значение поля `Command` содержит характерные подстроки. Результат — список подозрительных задач и их команд.

В качестве дополнения можно использовать правило для обнаружения регистрации новой задачи (Event ID 106) в сочетании с аномальными именами:

```spl
`wineventlog_task_scheduler` EventCode=106
| regex TaskName="(?i)(update|helper|sync|svc|google|microsoft)" 
| table _time, TaskName, UserContext, Computer
```

Такой поиск выявляет задачи, маскирующиеся под системные, особенно если они создаются пользователями с низкими привилегиями.

### Типичные workflow расследования в SOC

При поступлении алерта на подозрительное событие 200 аналитик выполняет следующие шаги:

1. **Извлечь подробности задачи**: по `TaskName` за короткий период ищутся события 106, 100, 200, 201. Определяется, когда задача была создана, кем, и что именно она запускала.
2. **Проверить путь и хеш**: команда из Event 200 сопоставляется с репутационными базами (VirusTotal, внутренние списки). Если путь лежит в пользовательском профиле, это сильный индикатор вредоносности.
3. **Восстановить цепочку выполнения**: по PID из события 200 и журналу Sysmon (Event ID 1) прослеживаются дочерние процессы, сетевые соединения и т.д.
4. **Оценить масштаб**: запрос на другие хосты с аналогичным `TaskName` или `Command` определяет, является ли инцидент массовым.
5. **Задокументировать IOC**: имя задачи, путь к файлу, хеш, аргументы командной строки.

### Ложные срабатывания и тонкая настройка

Основной источник ложноположительных срабатываний — легитимные задачи, запускающие программы из временных каталогов при установке обновлений (например, `%TEMP%\microsoft_edge_update.exe`). Частично фильтрация выполняется через списки исключений, как показано в макросе `winevent_windows_task_scheduler_event_action_started_filter` Splunk, который по умолчанию пуст и может наполняться аналитиками [Detection: WinEvent Windows Task Scheduler Event Action Started | Splunk Security Content](https://research.splunk.com/endpoint/b3632472-310b-11ec-9aab-acde48001122). Рекомендуется вести таблицу разрешённых путей и хешей, обновляемую по мере выявления легитимных активностей.

Дополнительный контекст дают события Security 4698/4702, позволяющие определить, кто именно создал или изменил задачу, что бывает критично при расследовании инсайдерских угроз.

Таким образом, журналирование Task Scheduler с фокусом на коды 100, 106, 200, 201 обеспечивает эффективную видимость в SOC, позволяя детектировать технику T1053.005 на стадии закрепления и исполнения, а также восстанавливать полную картину атаки.

## Сквозной практический пример: расследование подозрительной запланированной задачи

### Исходные условия

Рабочая станция Windows 11, входящая в домен. Логи канала `Microsoft-Windows-TaskScheduler/Operational` собираются агентом в SIEM (Splunk). Аналитик уровня L1 получает уведомление о срабатывании правила на событие 200 с запуском из каталога `C:\Users\jdoe\AppData\Roaming\`. Необходимо проверить, является ли активность вредоносной.

### Шаг 1: Идентификация создания задачи (Event ID 106)

Действие: поиск события регистрации задачи с именем, связанным с инцидентом. Аналитик выполняет запрос в SIEM за прошедшие сутки:

```spl
`wineventlog_task_scheduler` EventCode=106 TaskName="*Roaming*"
| table _time, TaskName, UserContext, Computer
```

**Артефакт (иллюстративное событие 106):**

```text
_time: 2026-04-05T02:15:30.000Z
EventCode: 106
TaskName: \Microsoft\Windows\Update\SyncHelper
UserContext: DOMAIN\jdoe
Computer: WS-JDOE.domain.local
Message: User "DOMAIN\jdoe" registered Task Scheduler task "\Microsoft\Windows\Update\SyncHelper".
```

**Результат:** Зафиксировано создание задачи с именем, маскирующимся под системное обновление, пользователем jdoe. Папка `\Microsoft\Windows\Update\` не является стандартной для данного типа обновлений (легитимные задачи размещаются в `\Microsoft\Windows\UpdateOrchestrator`). Подозрительно.

### Шаг 2: Подтверждение запуска задачи (Event ID 100)

Действие: поиск запусков задачи для определения InstanceId и времени активности.

```spl
`wineventlog_task_scheduler` EventCode=100 TaskName="\\Microsoft\\Windows\\Update\\SyncHelper"
| table _time, TaskName, InstanceId, ProcessId
```

**Артефакт:**

```text
_time: 2026-04-05T02:30:00.000Z
EventCode: 100
TaskName: \Microsoft\Windows\Update\SyncHelper
InstanceId: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
ProcessId: 8765
```

**Результат:** Задача запускалась через 15 минут после создания (триггер, вероятно, при входе пользователя). Идентификатор InstanceId позволит связать с последующими действиями.

### Шаг 3: Анализ запущенного действия (Event ID 200)

Действие: выгрузка подробностей события 200 для того же InstanceId или TaskName.

```spl
`wineventlog_task_scheduler` EventCode=200 TaskName="\\Microsoft\\Windows\\Update\\SyncHelper"
| table _time, Command, TaskInstanceId, EnginePID
```

**Артефакт:**

```text
_time: 2026-04-05T02:30:01.000Z
EventCode: 200
TaskName: \Microsoft\Windows\Update\SyncHelper
ActionName: SyncHelper
TaskInstanceId: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
EnginePID: 8765
Command: "cmd.exe" /c "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\jdoe\AppData\Roaming\sync.ps1"
```

**Результат:** Выявлен запуск cmd.exe, который, в свою очередь, вызывает PowerShell со скриптом из пользовательского Roaming. Это типовая картина загрузчика или бэкдора. Командная строка включает параметры скрытого окна и обхода политики выполнения.

### Шаг 4: Проверка завершения действия (Event ID 201)

Действие: поиск записи о завершении для оценки успешности и времени завершения.

```spl
`wineventlog_task_scheduler` EventCode=201 TaskInstanceId="{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
| table _time, ResultCode
```

**Артефакт:**

```text
_time: 2026-04-05T02:30:25.000Z
EventCode: 201
TaskName: \Microsoft\Windows\Update\SyncHelper
TaskInstanceId: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
ResultCode: 0x0
```

**Результат:** Действие завершилось с кодом 0x0 (успех). Вредоносный скрипт отработал.

### Ожидаемый вывод

На основании цепочки событий 106→100→200→201 установлено, что пользователь jdoe создал запланированную задачу, которая запускает PowerShell-скрипт из скрытого профиля. Такая активность соответствует технике закрепления T1053.005 и требует немедленной эскалации для изоляции хоста и дальнейшего анализа скрипта. Пример демонстрирует, как рассмотренные Event ID обеспечивают видимость на каждом этапе жизненного цикла вредоносной задачи.

## Источники

- [Ultimate Guide to Windows Task Scheduler Hardening | CalCom](https://calcomsoftware.com/task-scheduler-windows-hardening-guide)
- [Windows Task Scheduler | NXLog Documentation](https://docs.nxlog.co/integrate/windows-task-scheduler.html)
- [Scheduled Task | Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/scheduled-task)
- [Detection: WinEvent Windows Task Scheduler Event Action Started | Splunk Security Content](https://research.splunk.com/endpoint/b3632472-310b-11ec-9aab-acde48001122)
- [Enable or Disable Task Scheduler History | NinjaOne](https://www.ninjaone.com/blog/enable-or-disable-task-scheduler-history)
- [Windows - Local persistence user-scoped | artifacts.help](https://artefacts.help/tag_windows_local_persistence_user.html)
- [Microsoft Windows - Wirespeed](https://docs.wirespeed.co/integrations/microsoft-windows)
- [Windows Task Scheduler - Custom Event Filters · GitHub](https://gist.github.com/gucu112/8b97e7821fab9eb98488749a8273a3d0)
- [Schedule not working well on Task Scheduler - Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/472121/schedule-not-working-well-on-task-scheduler)
- [Task Scheduler Event IDs – mnaoumov.NET](https://mnaoumov.wordpress.com/2014/05/15/task-scheduler-event-ids)
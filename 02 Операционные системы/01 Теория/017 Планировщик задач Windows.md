# Планировщик задач Windows: архитектура, эксплуатация и мониторинг

## 1. Ключевые понятия и место в системе

Планировщик задач (Task Scheduler) — системная служба Windows, обеспечивающая автоматический запуск программ, скриптов и системных действий по расписанию или в ответ на события. Служба работает в контексте `svchost.exe` под учётной записью `SYSTEM` и управляет жизненным циклом задач от момента регистрации до завершения действия. Каждая задача представляет собой объединение триггеров (расписание или системное событие), действий (запуск программы, отправка сообщения, вызов COM-объекта), принципала (учётная запись, от имени которой выполняется действие) и набора дополнительных условий и параметров безопасности.

Задачи хранятся в нескольких представлениях. Основной контейнер — XML-файлы в `%windir%\System32\Tasks`. Иерархия папок планировщика отражается в файловой структуре этого каталога. Параллельно с файловым представлением существует зеркальная иерархия в реестре: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`. Именно реестр используется службой для быстрого доступа к свойствам задач, и его манипуляции позволяют влиять на видимость и поведение задач в обход стандартного API. При создании задачи через `schtasks.exe`, PowerShell или GUI одновременно обновляются XML-файл, ключи реестра и генерируется событие журнала безопасности Event ID 4698 (Security) или 106 (Microsoft-Windows-TaskScheduler/Operational). Эта синхронизация не является атомарной, чем пользуются злоумышленники: прямое изменение реестра без соответствующей записи журнала позволяет скрыть факт создания задачи.

В отличие от Unix-аналогов (`cron`, `systemd.timer`), планировщик Windows глубоко интегрирован с моделью безопасности операционной системы: поддерживает разделение привилегий через User Account Control (UAC), предоставляет каждой задаче уникальный идентификатор безопасности (task SID) для точной настройки доступа, а также может ограничивать набор доступных привилегий через параметр `RequiredPrivileges`. Это делает его одновременно мощным средством автоматизации и привлекательной целью для атак — злоумышленник, получивший выполнение кода на хосте, может злоупотребить планировщиком для закрепления, повышения привилегий или маскировки вредоносной активности [Scheduled Task | Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/scheduled-task).

С точки зрения SOC аналитика первого уровня (L1) важно различать штатные системные задачи, легитимные административные задачи пользователя и аномалии, характерные для вредоносной активности. В таблице ниже приведены ключевые способы взаимодействия с планировщиком и их типичные индикаторы с точки зрения мониторинга.

| Способ управления задачами               | Типичный контекст использования        | Основные артефакты / индикаторы                                                           |
|------------------------------------------|----------------------------------------|---------------------------------------------------------------------------------------------|
| `schtasks.exe` в командной строке        | Администрирование, скрипты, атака      | Командная строка в событии создания процесса (4688/1), параметры `/create`, `/ru`, `/sc` и т.д. |
| PowerShell ScheduledTasks (модуль)       | Администрирование, вредоносные скрипты | Объекты `ScheduledTask`, `ScheduledJob`; журнал PowerShell ScriptBlock Logging (4104)           |
| GUI Management Console (`taskschd.msc`)   | Интерактивное администрирование        | Запуск mmc.exe с параметром; не оставляет прямых следов командной строки                     |
| COM API / Task Scheduler Interface       | Сторонние приложения, вредоносный код  | Часто не генерирует событий 4698, если использовать методы прямой записи в реестр             |
| Прямая модификация реестра               | Вредоносные техники обхода             | Создание ключей под `TaskCache\Tree\<TaskName>` без соответствующих записей в Security логе   |

Для аналитика уровня L1 особенно важно понимать, что планировщик задач используется злоумышленниками как минимум для трёх тактик: **закрепление (Persistence)**, **выполнение (Execution)** и **повышение привилегий (Privilege Escalation)**. В терминологии MITRE ATT&CK этим целям соответствует техника [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053) и её подтехники. Успешное обнаружение подозрительной задачи требует не только анализа журналов событий, но и периодического аудита реестра, поскольку прямые манипуляции с ключами `SD`, `Author` и другими могут полностью скрыть задачу от стандартных средств, включая `schtasks /query` и оснастку GUI [Diving into Hidden Scheduled Tasks - Binary Defense](https://binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks).

## 2. Внутреннее устройство и архитектура безопасности

Планировщик задач Windows построен вокруг службы `Schedule`, работающей в процессе `svchost.exe -k netsvcs`. Она управляет регистрацией, хранением и диспетчеризацией задач на основе триггеров. Архитектура может быть описана через четыре ключевых хранилища и их взаимодействие:

1. **XML-файлы задач** в `%windir%\System32\Tasks` — полное представление задачи в формате Task Scheduler Schema. Включает триггеры, действия, принципала, условия, настройки безопасности.
2. **Ветви реестра `TaskCache`** — быстродействующий кэш, используемый службой при запуске и при операциях с задачами. Состоит из трёх основных поддеревьев:
   - `TaskCache\Tree\<TaskName>` — содержит значения `Id`, `Index`, `SD` (Security Descriptor), `Author`, `Triggers` (сериализованный бинарный объект), `Actions` и другие.
   - `TaskCache\Tasks\{GUID}` — сопоставление идентификатора задачи (GUID) с её ключом в Tree.
   - `TaskCache\<TriggerType>\{GUID}` — группировка задач по типу триггера (`Logon`, `Boot`, `Time`, `Idle` и т.д.) для быстрого поиска.
3. **Журналы событий** — каналы `Microsoft-Windows-TaskScheduler/Operational` (события 106, 107, 200, 201 и др.) и `Security` (событие 4698 «A scheduled task was created», 4699 «A scheduled task was deleted», 4700–4702 для включения/отключения/обновления).
4. **COM-интерфейс** (`ITaskService`, `ITaskDefinition` и др.) — программный API, доступный как для легитимных приложений, так и для вредоносного кода.

Визуализация потоков данных при создании задачи (упрощённая ASCII-диаграмма):
```text
[ schtasks.exe / PowerShell / GUI ] 
         │
         ▼
[ Task Scheduler Service (svchost) ] 
         │
         ├──► [ Создание XML-файла в %windir%\System32\Tasks\<Folder>\<Name> ]
         ├──► [ Обновление реестра: Tree\<Name>, Tasks\{GUID}, <TriggerType>\{GUID} ]
         └──► [ Генерация событий: Security Event 4698 + Operational Event 106 ]
```

При прямом создании ключей в реестре (минуя API) XML-файл может не создаваться, а события не регистрируются — именно этот метод используется вредоносным ПО вроде Tarrask [Diving into Hidden Scheduled Tasks - Binary Defense](https://binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks). Обнаружение подобных артефактов требует аудита реестра.

### Модель безопасности задачи

Каждая задача имеет собственный контекст безопасности, определяемый несколькими элементами:

- **Принципал (`Principal`)** — учётная запись, под которой выполняется действие. Задаётся через `/ru` в `schtasks` или поле `UserId` в XML. Может быть локальной учётной записью, доменной, `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`. Поддержка групповых управляемых учётных записей (gMSA) и виртуальных учётных записей.
- **Уровень выполнения (`RunLevel`)** — может быть `LeastPrivilege` (по умолчанию) или `HighestAvailable` (эквивалент запуска с правами администратора при включённом UAC). Определяется в XML как `<RunLevel>HighestAvailable</RunLevel>` или ключом `/rl` в команде.
- **RequiredPrivileges** — список привилегий, которые должны быть включены в маркере процесса. Если привилегия не указана, она удаляется из маркера (SE_PRIVILEGE_REMOVED). По умолчанию, если элемент отсутствует, используются привилегии учётной записи принципала, но с удалённой `SeImpersonatePrivilege` [Task Security Hardening - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-security-hardening).
- **ProcessTokenSidType** — определяет, будет ли задача получать уникальный SID. Значение `Unrestricted` (по умолчанию) назначает задаче SID, производный от полного пути задачи. Например, задача `\Microsoft\Windows\RAC\RACTask` получит SID с именем `Microsoft-Windows-RAC-RACTask` и группу `NT TASK\<это_имя>`. Этот SID добавляется в группы маркера процесса и позволяет точно настраивать разрешения для конкретной задачи, не повышая права учётной записи [Task Security Hardening - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-security-hardening).

Схема реестрового ключа `Tree\<TaskName>` (иллюстративная структура, значения зависят от среды):
```json
{
  "SD": "<бинарное представление дескриптора безопасности>",
  "Author": "<строковое значение, например 'Administrators'>",
  "Triggers": "<сериализованный объект триггеров>",
  "Actions": "<сериализованный объект действий>",
  "Id": "<GUID задачи>",
  "Index": "<числовой индекс>",
  "Path": "<полный путь задачи>",
  "URI": "<URI задачи>"
}
```

Значение `SD` критически важно для аудита. Если оно отсутствует или установлено так, что запрещает чтение текущему контексту, стандартные инструменты (включая `schtasks /query`) не могут перечислить задачу. Злоумышленники могут либо удалить `SD` полностью (как это делает Tarrask), либо заменить его на SDDL-строку, разрешающую доступ только `SYSTEM`, а затем удалить права на чтение для администраторов, что приведёт к невидимости задачи для GUI и оснастки. Эта техника манипуляции дескриптором безопасности классифицируется как Defense Evasion: Impair Defenses [T1070.001](https://attack.mitre.org/techniques/T1070/001) [Diving into Hidden Scheduled Tasks - Binary Defense](https://binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks).

### Триггеры и их связь с поведением

Планировщик поддерживает несколько типов триггеров, каждый из которых определяет момент запуска. На уровне реестра они группируются по поддеревьям `Logon`, `Boot`, `Time`, `Idle` и т.д. Аналитику L1 важно обращать внимание на экзотические интервалы (например, запуск каждые 30 секунд) и нестандартные типы, такие как `OnIdle` или `AtTaskStartup`, которые редко используются в легитимном администрировании и могут указывать на вредоносную активность.

Ниже представлена сравнительная таблица наиболее распространённых типов триггеров и их типичных применений в контексте SOC.

| Тип триггера (XML элемент)   | Реестровая группировка | Типичное легитимное использование        | Потенциальные индикаторы злоупотреблений                               |
|------------------------------|------------------------|------------------------------------------|------------------------------------------------------------------------|
| `TimeTrigger`                | `Time`                | Ежедневное обслуживание, обновления      | Запуск каждые несколько минут, разовое задание в прошлом               |
| `LogonTrigger`               | `Logon`               | Запуск программ при входе пользователя   | Задача с SYSTEM привилегиями, срабатывающая при входе любого пользователя |
| `BootTrigger`                | `Boot`                | Драйверы, службы                         | Редко используется; в сочетании с вредоносным действием — очевидный IOC|
| `IdleTrigger`                | `Idle`                | Фоновое обслуживание при бездействии     | Злоумышленники практически не применяют, но возможна маскировка        |
| `RegistrationTrigger`        | – (как `Time`)        | Запуск сразу при создании задачи         | Создание с одновременным запуском вредоносного кода одной командой     |
| `OnSessionStateChange`       | –                     | Действия при блокировке/разблокировке    | Слежка за активностью пользователя, повод для эскалации привилегий     |

Анализ триггеров — один из простейших способов быстрого выявления аномалий на уровне L1: любое сочетание `BootTrigger` или `LogonTrigger` с действием, запускающим исполняемый файл из пользовательских каталогов (`AppData\Roaming`, `TEMP`), должно немедленно эскалироваться как подозрительное.

## 3. Применение, злоупотребление и типичные артефакты

### Легитимные операции и команды мониторинга

Администраторы и автоматизированные системы используют планировщик через утилиту командной строки `schtasks.exe`, модуль PowerShell `ScheduledTasks` (командлеты с префиксом `*-ScheduledTask*`) или COM-объекты. Наиболее частые команды, попадающие в поле зрения SOC:

- **Создание задачи**:  
  ```powershell
  # schtasks
  schtasks /create /tn "MyApp\Cleanup" /tr "C:\scripts\cleanup.bat" /sc daily /st 02:00 /ru SYSTEM /rl HIGHEST
  ```
  В журнале безопасности регистрируется событие 4698 с XML-представлением задачи. Командная строка родительского процесса может быть зафиксирована в Sysmon Event ID 1.

- **Запуск задачи вручную**: `schtasks /run /tn "MyApp\Cleanup"`.  
  В операционном журнале появляется событие 200 (начало действия) и 201 (завершение действия). Аналитик должен обращать внимание на запуск задач из нестандартных расположений.

- **Удаление задачи**: `schtasks /delete /tn "taskname" /f`.  
  Событие 4699 в Security. Злоумышленники часто очищают следы; удаление множества задач за короткий промежуток может быть симптомом заметания следов.

- **Запрос списка задач**: `schtasks /query /fo LIST /v` — стандартный метод инвентаризации. При скрытии задачи путём удаления `SD` эта команда не покажет задачу; в выводе будет пустая строка или ошибка доступа.

### Злоумышленное использование и техники обхода

Злоумышленники применяют планировщик для двух основных, часто пересекающихся целей: персистентность и повышение привилегий. Наиболее распространённые паттерны:

1. **Персистентность через запуск вредоносного файла**:  
   ```cmd
   schtasks /create /sc onlogon /tn "WindowsUpdateTask" /tr "C:\Users\<user>\AppData\Local\malware.exe" /ru SYSTEM /rl highest /f
   ```
   Здесь путь `AppData\Local` является пользовательским и не должен содержать легитимных задач от `SYSTEM`. Такие аномалии — немедленный сигнал тревоги.

2. **Повышение привилегий через UAC bypass с использованием Batch Logon**:  
   Уязвимости, описанные в ряде CVE (включая CVE-2023-21726 и более свежие), позволяют локальному администратору выполнить код от `SYSTEM` без UAC-запроса, создав задачу с аутентификацией через Batch Logon (`/ru` и `/rp`), а не через интерактивный токен [Windows Task Scheduler Vulnerabilities – Rescana](https://www.rescana.com/post/windows-task-scheduler-vulnerabilities-exploitation-and-mitigation-strategies). Такая задача выполняется с флагом `SE_PRIVILEGE_UP` и не отображает диалог UAC. Атакующий может использовать заранее известный пароль администратора или переданный NTLMv2-хэш.

3. **Скрытие задачи через реестр (Defense Evasion)**:  
   Техника, задокументированная Microsoft для вредоносного ПО Tarrask, заключается в удалении значения `SD` из ключа `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>`. После этого задача становится невидимой для `schtasks /query`, Autoruns и оснастки GUI. Для ещё большей скрытности злоумышленник может напрямую создать ключи реестра, минуя регистрацию XML и запись в Event Log. Пример создания «скрытой» задачи с помощью PowerShell (иллюстративная схема, не рекомендуется к выполнению):
   ```powershell
   # Прямая запись в реестр для создания задачи без генерации события 4698
   $taskName = "HiddenTask"
   $guid = [System.Guid]::NewGuid().ToString()
   $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$taskName"
   New-Item -Path $path -Force
   New-ItemProperty -Path $path -Name "Id" -Value $guid -PropertyType String
   New-ItemProperty -Path $path -Name "Index" -Value 0x00000001 -PropertyType DWord
   # SD не создаётся намеренно
   ```
   Такая задача не будет видна в стандартных выводах, но оставит артефакт в реестре: ключ существует, а значение `SD` отсутствует.

4. **Манипуляция метаданными и журналом событий**:  
   В XML-файле задачи поле `Author` можно изменить на `Administrator`, чтобы ввести в заблуждение защитника. При атаке «Event Log Poisoning» злоумышленник целенаправленно переполняет журнал безопасности (CWE-117, CWE-400), чтобы скрыть записи о создании задачи. Это достигается генерацией массы ложных событий 4698 через легитимные скрипты, пока журнал не будет перезаписан [Windows Task Scheduler Vulnerabilities – Rescana](https://www.rescana.com/post/windows-task-scheduler-vulnerabilities-exploitation-and-mitigation-strategies).

### Аудит и детектирование

Для эффективного мониторинга на уровне L1 аналитик должен иметь доступ к следующим источникам данных и уметь применять базовые скрипты проверки:

- **Журнал безопасности**: события 4698 (создание), 4702 (обновление), 4699 (удаление). Необходим аудит включения политики «Audit Object Access» и «Audit Security Group Management» для получения информации о создателях.
- **Журнал операционного канала TaskScheduler**: предоставляет подробности о запуске задач (Event ID 200/201), ошибках (301), изменении состояния (129).
- **Sysmon / EDR**: Event ID 1 (создание процесса) с аргументом `schtasks` или процессами, запущенными из папок `Tasks`, а также регистрация изменений реестра (Event ID 13).
- **Аудит реестра вручную**: использование скриптов для поиска задач без `SD` или с подозрительно малым количеством записей. Один из таких скриптов, разработанный ARC Labs, может быть адаптирован для проверки значений `SD` [Diving into Hidden Scheduled Tasks - Binary Defense](https://binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks).

Ниже приведён фрагмент PowerShell-скрипта для выявления задач, в ключах которых отсутствует значение `SD` (иллюстративный):
```powershell
$tasks = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree" -Recurse -ErrorAction SilentlyContinue
foreach ($task in $tasks) {
    $sd = Get-ItemProperty -Path $task.PSPath -Name "SD" -ErrorAction SilentlyContinue
    if (-not $sd) {
        Write-Output "Hidden task suspected: $($task.PSChildName)"
    }
}
```
Вывод этого скрипта должен проверяться при расследовании инцидентов, связанных с планировщиком.

### Уязвимости класса Elevation of Privilege

Помимо UAC bypass, планировщик периодически страдает от уязвимостей в ядре, позволяющих локальное повышение привилегий. Примером является [CVE-2025-33067](https://windowsforum.com/threads/understanding-and-mitigating-cve-2025-33067-windows-task-scheduler-privilege-escalation-vulnerability.369766), связанная с неправильной обработкой маркеров при взаимодействии ядра и планировщика. Такой вектор позволяет локальному непривилегированному пользователю выполнить произвольный код с правами `SYSTEM`, что делает своевременное патчирование критичным. Несмотря на то, что детальное техническое исследование таких CVE — задача старших аналитиков, L1 должен знать о потенциальных возможностях эксплуатации и эскалировать подозрительное поведение, особенно если задача подписана цифровой подписью Microsoft, но запускается нестандартным способом.

## 4. Сквозной практический пример: скрытая задача Tarrask-стиля и её обнаружение

**Исходные условия**. Рабочая станция Windows 10 Pro, аналитик L1 имеет права администратора и доступ к командной строке PowerShell. Подразумевается, что вредоносное ПО уже получило права `SYSTEM` (например, через успешный эксплойт) и использовало прямой доступ к реестру для создания скрытой задачи без генерации событий в журнале безопасности. Задачи аналитика — выявить аномалию, используя аудит реестра.

**Шаг 1. Эмуляция создания скрытой задачи через реестр.**  
Злоумышленник (в нашем случае — тестовая консоль от `SYSTEM`) создаёт ключи реестра для задачи `EvilTask` без добавления `SD` и без записи в XML. Также регистрируется GUID задачи в `Tasks` и в поддереве `Logon` для триггера при входе.

```powershell
# Запуск от имени SYSTEM (psexec -s -i powershell) или через task scheduler от имени SYSTEM
$taskName = "EvilTask"
$guid = [System.Guid]::NewGuid().ToString()
$treePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$taskName"
$tasksPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$guid"
$logonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\$guid"

# Создаем ключ Tree без значения SD
New-Item -Path $treePath -Force | Out-Null
New-ItemProperty -Path $treePath -Name "Id" -Value $guid -PropertyType String
New-ItemProperty -Path $treePath -Name "Index" -Value 0x00000001 -PropertyType DWord
New-ItemProperty -Path $treePath -Name "Author" -Value "Administrator" -PropertyType String

# Создаем ключ Tasks
New-Item -Path $tasksPath -Force | Out-Null
New-ItemProperty -Path $tasksPath -Name "Path" -Value "\EvilTask" -PropertyType String
New-ItemProperty -Path $tasksPath -Name "Actions" -Value ([byte[]]@(0x00,0x01,0x02)) -PropertyType Binary

# Добавляем в Logon для запуска при входе
New-Item -Path $logonPath -Force | Out-Null
New-ItemProperty -Path $logonPath -Name "Id" -Value $guid -PropertyType String
```

**Ожидаемый результат**: в реестре появляется запись `Tree\EvilTask` без `SD`. Стандартная команда `schtasks /query /tn EvilTask` возвращает ошибку или отсутствие данных, так как у процесса нет прав на чтение без `SD`.

**Шаг 2. Проверка невидимости для штатного инструмента.**  
Открываем консоль от имени администратора и пытаемся отобразить задачу:

```cmd
schtasks /query /tn EvilTask /fo LIST /v
```

Вывод (иллюстративная схема):
```text
ERROR: The system cannot find the path specified.
```
Аналогично в PowerShell:
```powershell
Get-ScheduledTask -TaskName "EvilTask" -ErrorAction SilentlyContinue
```
Никакого вывода не будет, так как задача не представлена через API (отсутствует в XML и SD блокирует чтение).

**Шаг 3. Аудит реестра: поиск задач без SD.**  
Аналитик L1 запускает скрипт для перебора всех задач и проверки наличия значения `SD`:

```powershell
$key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
$children = Get-ChildItem -Path $key -Recurse | Where-Object { $_.PSChildName -notlike "*\{*" }  # исключаем GUID-поддеревья
foreach ($taskKey in $children) {
    $taskPath = $taskKey.PSPath
    $sd = Get-ItemProperty -Path $taskPath -Name "SD" -ErrorAction SilentlyContinue
    if (-not $sd) {
        # Дополнительно проверим, есть ли соответствующий XML-файл
        $taskName = $taskKey.PSChildName
        $xmlPath = Join-Path "$env:WINDIR\System32\Tasks" $taskName
        $xmlExists = Test-Path $xmlPath
        $props = @{
            TaskName = $taskName
            SD_Exists = $false
            XML_Exists = $xmlExists
            Author = (Get-ItemProperty -Path $taskPath -Name "Author" -ErrorAction SilentlyContinue).Author
        }
        [pscustomobject]$props
    }
}
```

**Ожидаемый вывод** (иллюстративный):
```text
TaskName   SD_Exists XML_Exists Author
--------   --------- ---------- ------
EvilTask    False     False     Administrator
```

В выводе мы видим задачу `EvilTask` без `SD` и без соответствующего XML-файла, что однозначно указывает на ручное создание, типичное для атаки Tarrask. Поле `Author` — `Administrator` — дополнительно создаёт впечатление легитимной задачи, хотя запись о её создании (`Account Name`) в журнале безопасности отсутствует.

**Шаг 4. Окончательная верификация и реакция.**  
Аналитик L1, обнаружив такую задачу, должен немедленно эскалировать инцидент, предоставив артефакты. Для уточнения деталей он может попытаться восстановить сериализованные данные триггеров из свойства `Triggers` (бинарное значение) при помощи соответствующих утилит, но это выходит за рамки L1. Основной вывод: использование аудита реестра позволяет выявить скрытые задачи, невидимые для стандартных инструментов, что критически важно при расследовании атак с использованием T1053.005 и T1070.001.

Этот пример демонстрирует, как злоумышленник может закрепиться в системе без генерации событий 4698 и скрыться от поверхностного мониторинга. SOC аналитик L1, владеющий методикой прямого аудита реестра, способен обнаружить подобные индикаторы и предотвратить дальнейшее развитие атаки.

## Источники

- [Windows Task Scheduler Vulnerabilities: Exploitation and Mitigation Strategies – Rescana](https://www.rescana.com/post/windows-task-scheduler-vulnerabilities-exploitation-and-mitigation-strategies)
- [Diving into Hidden Scheduled Tasks - Binary Defense](https://binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks)
- [Scheduled Task | Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/scheduled-task)
- [Understanding and Mitigating CVE-2025-33067: Windows Task Scheduler Privilege Escalation Vulnerability | Windows Forum](https://windowsforum.com/threads/understanding-and-mitigating-cve-2025-33067-windows-task-scheduler-privilege-escalation-vulnerability.369766)
- [Scheduled Task/Job, Technique T1053 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1053)
- [Task Security Hardening - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-security-hardening)
- [Monitoring Scheduled Task - MP question - Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/123803/monitoring-scheduled-task-mp-question) (контекст мониторинга через Management Pack)
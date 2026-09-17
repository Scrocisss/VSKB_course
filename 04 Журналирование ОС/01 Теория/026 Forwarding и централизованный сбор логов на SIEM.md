# Пересылка и централизованный сбор логов на SIEM

## 1. Роль транспортировки логов в конвейере мониторинга безопасности

Ключевая задача начального уровня SOC — обеспечить поступление событий от всех контролируемых систем в платформу анализа. Журналирование операционных систем, сетевых устройств и приложений создаёт локальные записи, но само по себе оно не гарантирует ни сохранности, ни доступности этих данных для централизованного поиска угроз. Процесс передачи логов с хоста-источника на выделенный коллектор или напрямую в SIEM называют **forwarding** (пересылкой, перенаправлением). Централизованный сбор — это архитектурный принцип, согласно которому все логи, независимо от их происхождения, стекаются в единую платформу, способную выполнять корреляцию, долговременное хранение и аналитику. В совокупности forwarding и централизация образуют транспортный уровень системы мониторинга безопасности.

Различие между этими и смежными понятиями удобно зафиксировать таблицей.

| Понятие | Суть | Типичное воплощение | Роль в SOC-конвейере |
|----------|------|---------------------|----------------------|
| Локальное журналирование | Запись событий на самом устройстве в файлы, журналы Windows Event Log, journald | `/var/log/syslog`, Security Event Log | Первичная фиксация; без forwarding’а остаётся изолированной |
| Forwarding | Транспортировка логов с источника на внешний приёмник по сети | rsyslog, nxlog, Windows Event Forwarding, Elastic Agent | Связующее звено между источником и центральным хранилищем |
| Централизованный сбор | Архитектурный подход, при котором все логи попадают в одно или несколько централизованных хранилищ | SIEM-платформа (Splunk, Elastic, QRadar) либо syslog-сервер | Обеспечивает единое окно поиска и корреляции |
| SIEM | Программная система, выполняющая не только сбор, но и нормализацию, корреляцию, алертинг и визуализацию логов | Splunk Enterprise Security, Microsoft Sentinel, Elastic Security | Конечный потребитель логов; использует централизованный сбор как подсистему |

Forwarding не является отдельной сущностью, противопоставленной централизованному сбору. Это два взаимосвязанных аспекта одной задачи: forwarding описывает *как* движется событие, а централизованный сбор — *куда* и в какой модели. В практике SOC L1 инженер обязан понимать оба слоя.

Потребность в пересылке обосновывается фундаментальными свойствами инцидентов. При компрометации хоста злоумышленник часто заметает следы, очищая локальные журналы [*] . Вынос логов на выделенный, изолированный коллектор защищает целостность улик. Помимо безопасности, централизация решает проблему производительности: непрерывная запись чужеродных событий на самом устройстве потребляет дисковый и процессорный ресурс, тогда как пересылка по сети сбрасывает нагрузку. В высоконагруженных средах это особенно актуально: производители сетевого оборудования часто реализуют syslog-рассылки именно для разгрузки управляющего процессора.

Архитектура доставки логов в современном SOC тяготеет к двухэтапной модели, зафиксированной в отраслевых методиках (например, руководство CISA по приоритетным логам для SIEM [https://media.defense.gov/2025/May/27/2003722069/-1/-1/0/Priority-logs-for-SIEM-ingestion-Practitioner-guidance.PDF] ). Первый этап — сбор и передача от источников к промежуточной точке концентрации (центральному syslog-серверу, брокеру сообщений, Logstash-узлу). Второй этап — фильтрация, нормализация и вброс в аналитическое ядро SIEM. Такая модель развязывает жизненные циклы источников и приёмника: коллектор может буферизовать всплески, применять правила отбрасывания малоценных событий и унифицировать форматы до того, как данные попадут в дорогостоящий корреляционный движок.

В SOC первого уровня специалист работает с **результатом** этой цепочки — с уже собранными и нормализованными событиями на консоли SIEM. Тем не менее понимание forwarding’а необходимо, потому что отсутствие событий от части хостов или некорректная временна́я метка часто сигнализируют о проблемах именно на транспортном уровне.

## 2. Протоколы, агенты и архитектурные паттерны доставки логов

Транспортировка логов в корпоративной среде опирается на несколько технологических семейств. Их выбор диктуется типом источника, требованиями к надёжности и доступным инструментарием.

### 2.1 Протоколы syslog

Протокол syslog — исторически первый и наиболее распространённый механизм пересылки событий. Он стандартизирован в RFC 3164 (старая версия, часто называемая BSD syslog) и RFC 5424 (IETF syslog, вводящий структурированные данные). Сообщение syslog содержит приоритет (Facility и Severity), временну́ю метку, имя хоста, тег приложения и текстовое содержимое. По сети оно передаётся, как правило, поверх UDP (порт 514) или TCP (порт 514 или 6514 для TLS-защищённого syslog). UDP-доставка не требует установки соединения и создаёт минимальную задержку, но не гарантирует доставку — при перегрузке сети сообщения могут теряться без уведомления отправителя. TCP-over-TLS решает эту проблему, обеспечивая надёжную потоковую передачу и взаимную аутентификацию, что критически важно для compliance-регуляций (PCI DSS, GDPR).

Многие поставщики SIEM (Splunk, Elastic, IBM QRadar) и выделенные syslog-серверы (rsyslog, syslog-ng, LogRhythm System Monitor) поддерживают обе транспортные разновидности [https://docs.logrhythm.com/lrsiem/docs/syslog-collection] . При использовании TCP с шифрованием требуется корректная работа с сертификатами: syslog-клиент должен доверять серверу, а при взаимной аутентификации — предъявлять клиентский сертификат, запрошенный через CSR, как описано в документации Trend Micro Deep Security [https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog.html].

### 2.2 Windows Event Forwarding (WEF) и встроенные возможности Windows

Для Windows-сред существует нативный механизм, основанный на подписках (subscriptions) и использовании протокола WinRM. Модель WEF предполагает, что клиентские машины посылают события на выделенный коллектор (Windows Event Collector), который затем может быть интегрирован с SIEM через агент или syslog-шлюз. В отличие от push-модели syslog, WEF работает по pull-принципу: коллектор инициирует сбор событий, опрашивая источники согласно фильтрам подписки.

Этот подход удобен в доменной среде Windows: позволяет централизованно управлять составом собираемых событий без установки стороннего ПО на конечные системы. Однако он требует настройки групповых политик для включения WinRM и задания подписок. На практике для гибридных сред чаще применяют специальные агенты — о них ниже.

### 2.3 Агенты сбора

Агент — это лёгкая служба, устанавливаемая непосредственно на источнике событий. Агенты решают несколько задач: читают локальные журналы (файлы, Windows Event Log, journald), парсят их, обогащают метаданными (имя хоста, тэги) и отправляют в центральный коллектор по выбранному транспорту. Популярные примеры: Elastic Agent / Winlogbeat, NXLog, Splunk Universal Forwarder, Logstash, Fluentd (особенно в Kubernetes-средах). Агенты предоставляют широкие возможности по буферизации, сжатию, TLS-шифрованию и балансировке нагрузки. Splunk Universal Forwarder, например, способен кэшировать события на диске при недоступности индексеров, исключая потерю данных.

### 2.4 Облачные и API-интеграции

С ростом числа SaaS-приложений и облачных инфраструктур (AWS, Azure, Google Cloud) появляются методы пересылки, не требующие классического агента. Облачные сервисы предоставляют REST API (например, Microsoft Graph API для логов Office 365) или потоковые шины (Amazon SNS, Azure Event Hub). Для SIEM, развёрнутых в облаке (Microsoft Sentinel, Splunk Cloud), native-коннекторы подписываются на эти потоки напрямую. Локальный агент в этом сценарии заменяется облачным сборщиком.

Для сравнения ключевых характеристик перечисленных механизмов составлена таблица.

| Механизм / протокол | Модель доставки | Типичная среда | Надёжность | Аутентификация | Пример реализации |
|---------------------|-----------------|----------------|------------|----------------|-------------------|
| Syslog UDP | Push, без установки соединения | Linux, сетевые устройства, принтеры | Низкая (возможны потери) | Отсутствует (доверие по IP) | rsyslog на центральном коллекторе слушает 514/udp |
| Syslog TCP/TLS | Push, потоковое соединение | Linux, устройства, требующие гарантии доставки | Высокая (TCP) или очень высокая (TLS + буфер) | Сертификаты X.509 (одно- или двусторонняя) | NXLog отправляет в LogRhythm по TCP 6514 [https://docs.logrhythm.com/lrsiem/docs/syslog-collection] |
| Windows Event Forwarding | Pull (коллектор запрашивает) | Домен Windows, Active Directory | Высокая (WinRM устойчив) | Kerberos / NTLM в рамках домена | Windows Event Collector с подпиской на Security-канал |
| Агент (Elastic, Splunk UF) | Push, агент управляет буфером | Универсальная (Windows, Linux) | Очень высокая (дисковые очереди) | TLS с общими или собственными сертификатами | Winlogbeat → Logstash → Elasticsearch |
| REST API / Брокеры сообщений | Pull/Push через HTTP/Kafka | Облачные сервисы, SaaS | Высокая (гарантируется платформой) | OAuth 2.0, API-ключи, SASL | Azure Event Hub → Microsoft Sentinel |

### 2.5 Архитектурная схема централизованного сбора

Типовая архитектура, иллюстрирующая движение логов от источника к SIEM, представлена ниже.

```text
[Рабочие станции Windows] ──(WEF/WinRM)──▶ [Windows Event Collector]
                                              │
                                              ├─(NXLog/syslog)──▶ [Центральный syslog-сервер] ──(syslog TLS)──▶ [SIEM]
[Серверы Linux] ──(rsyslog TCP/TLS)───────────┘
[Сетевые устройства] ──(syslog UDP)───────────┘
[Облачные SaaS] ──(REST API)──▶ [Logstash/брокер] ──(JSON)──▶ [SIEM]
```

На схеме явно видны два этапа: концентрация на промежуточном syslog-сервере (или коллекторе) и последующая доставка в SIEM. Такая конструкция позволяет размещать syslog-сервер в демилитаризованной зоне, не открывая прямой доступ извне к ядру SIEM, а также буферизировать и фильтровать данные до попадания в аналитическое хранилище.

### 2.6 Внутреннее устройство syslog-сообщения и нормализация

Сообщение syslog содержит структурированные и неструктурированные части. Пример с разбором полей по RFC 3164:

```
<13>Oct 11 22:14:15 myhost su: 'su root' failed for lonvick on /dev/pts/8
```
- `<13>` — приоритет: facility = 1 (user), severity = 5 (Notice).
- `Oct 11 22:14:15` — временная метка, которую источник формирует локально.
- `myhost` — имя хоста.
- `su:` — тег приложения.
- Оставшийся текст — содержимое события.

При получении SIEM-система или syslog-сервер модифицирует сообщение: добавляет принятую временную метку (если удалось распарсить исходную), IP-адрес источника и, возможно, преобразует приоритет в читаемый вид. Документация LogRhythm описывает, как после применения relay regex и timestamp parsing сообщение обогащается:

```text
10 11 2025 22:14:15 10.1.1.164 <USER:NOTICE> Oct 11 22:14:15 myhost su: ...
```
[https://docs.logrhythm.com/lrsiem/docs/syslog-collection]

Нормализация приводит события к единой схеме (Common Event Format, JSON, LEEF), что критически важно для корреляции в SIEM. Именно поэтому этап пересылки часто сопрягается с переформатированием: агент NXLog или модуль Logstash парсит сырой syslog и выдаёт структурированный JSON, готовый к индексации.

Таким образом, внутреннее устройство forwarding-системы складывается из выбора протокола, конфигурации надёжности (UDP/TCP/TLS), буферизации на источнике и правил нормализации, которые превращают поток разнородных строк в согласованную модель данных.

## 3. Эксплуатация каналов доставки логов: настройка, контроль и типовые ошибки

На уровне SOC L1 специалисту не обязательно разворачивать всю архитектуру с нуля, однако он должен уметь диагностировать неисправности тракта пересылки и выполнять базовые операции по подключению новых источников. В этом разделе рассматриваются практические приёмы с примерами конфигураций.

### 3.1 Типовая настройка syslog-форвардинга на Linux

В дистрибутивах Linux повсеместно используется `rsyslog` — высокопроизводительный демон, способный принимать локальные сообщения и пересылать их вовне. Настройка отправки всех событий на удалённый SIEM по TCP/TLS выполняется в файле `/etc/rsyslog.conf` (или отдельном файле в `/etc/rsyslog.d/`). Пример конфигурации пересылки по TCP с использованием TLS-шифрования:

```bash
# Загружаем модуль TCP-пересылки
module(load="omfwd")
# Настраиваем транспорт
*.* action(type="omfwd"
           target="siem-collector.company.local"
           port="6514"
           protocol="tcp"
           StreamDriver="gtls"
           StreamDriverMode="1"    # требуем TLS
           StreamDriverAuthMode="x509/name"
           StreamDriverPermittedPeers="siem-collector.company.local"
           ResendLastMSGOnReconnect="on"
           queue.filename="fwdQueue"
           queue.maxDiskSpace="1g"
           queue.saveOnShutdown="on"
           queue.type="LinkedList")
```

Комментарий к директивам: `StreamDriver="gtls"` включает TLS, `StreamDriverAuthMode` задаёт проверку подлинности сервера по сертификату, `PermittedPeers` ограничивает допустимое DN (Distinguished Name) сертификата SIEM. Дисковый очередь `queue.filename` с ограничением в 1 Гбайт гарантирует, что при временной недоступности коллектора события не пропадут, а запишутся на диск и будут отправлены после восстановления связи.

Аналогичная логика реализуется и в альтернативе — `syslog-ng`, где используется драйвер `syslog()` с флагами `transport("tls")`.

### 3.2 Настройка Windows Event Forwarding (WEF)

Для доменных машин Windows создание подписки на сбор событий выглядит так (команды выполняются на коллекторе с правами администратора):

```powershell
# Создание подписки, собирающей события входа (EventID 4624) с определённых компьютеров
$subscription = @{
    SubscriptionName     = "SecurityLogins"
    SourceDomainComputers = "OUs=Workstations,DC=company,DC=local"
    EventLog             = "Security"
    Query                = "*[System[EventID=4624]]"
    DestinationLog       = "ForwardedEvents"
    SubscriptionType     = "SourceInitiated"
    Enabled              = $true
}
wecutil cs $subscription.SubscriptionName /c:$subscription.SourceDomainComputers /e:$subscription.EventLog /q:"$($subscription.Query)" /d:$subscription.DestinationLog /t:$subscription.SubscriptionType
```

Здесь `wecutil cs` создаёт подписку с заданным XML-фильтром. События будут поступать на коллектор в журнал `ForwardedEvents`. Далее агент (NXLog) может забирать этот журнал и отправлять в SIEM.

### 3.3 Использование агентов: пример NXLog для Windows

Многие SIEM-платформы поставляют собственные лёгкие форвардеры, но в мультивендорных средах часто применяют универсальное решение. NXLog умеет читать Windows Event Log и отправлять структурированный вывод по syslog или в прямой JSON-поток. Пример конфигурации `nxlog.conf` для отправки событий безопасности в SIEM:

```conf
Panic Soft
define ROOT C:\Program Files\nxlog
Moduledir %ROOT%\modules
CacheDir  %ROOT%\data
Pidfile   %ROOT%\data\nxlog.pid
SpoolDir  %ROOT%\data

<Input in>
    Module      im_msvistalog
    Query       <QueryList><Query Id="0"><Select Path="Security">*</Select></Query></QueryList>
    Exec        $EventReceivedTime = integer($EventReceivedTime) / 1000000; $SourceModuleType = "windows_snare_syslog";
</Input>

<Output out>
    Module      om_tcp
    Host        siem.company.local
    Port        5140
    Exec        to_json();
</Output>

<Route 1>
    Path        in => out
</Route>
```

Блок `Exec to_json();` превращает структуру события Windows в JSON, который передаётся по TCP на порт 5140 коллектора SIEM. Встроенный `im_msvistalog` читает журнал напрямую, минуя WEF, что удобно при отсутствии инфраструктуры Windows Event Collector.

### 3.4 Приоритизация и фильтрация на уровне форвардера

Следуя рекомендациям CISA, нельзя направлять в SIEM абсолютно все логи — это приводит к информационному шуму и неоправданным затратам на лицензирование по объёму (EPS/GB) [https://media.defense.gov/2025/May/27/2003722069/-1/-1/0/Priority-logs-for-SIEM-ingestion-Practitioner-guidance.PDF]. Фильтрацию желательно выполнять на наиболее раннем этапе — на агенте или syslog-сервере. Например, rsyslog позволяет отбрасывать сообщения по содержимому:

```bash
if $msg contains 'debug mode' then {
    stop
}
```

В NXLog можно добавить условие:

```conf
<Route 1>
    Path in => out
    Exec if $Severity == 'INFO' drop();
</Route>
```

Однако фильтрация требует осторожности: SOC-аналитик должен согласовать отбрасываемые категории с владельцами систем, чтобы не потерять действительно важные маркеры компрометации.

### 3.5 Типичные ошибки в каналах пересылки

Наиболее часто встречающиеся проблемы, видимые с первого уровня:

- **Конфликт порта на коллекторе**: локальный syslog-демон (например, система Linux сама слушает 514/udp) не позволяет агенту SIEM занять этот порт. В логах агента появляется сообщение `Failed to bind to syslog TCP socket (10.1.1.164:514) - the address and/or port may already be in use`, как задокументировано у LogRhythm [https://docs.logrhythm.com/lrsiem/docs/syslog-collection]. Решение — остановить локальный rsyslog или перенастроить приёмник на другой порт.
- **Несовпадение временных зон и форматов**: источник передаёт метку времени в локальном времени без смещения, а SIEM ожидает UTC. В результате события могут отображаться со сдвигом на несколько часов. Для компенсации применяют relay regex или перезаписывают метку на коллекторе с добавлением источника времени (Received Time).
- **Обрыв соединения TLS из-за недоверенного сертификата**: агент не может проверить сертификат SIEM и прекращает отправку. Консольные ошибки типа `certificate verify failed` лечатся добавлением корневого сертификата в доверенные хранилища агента.
- **Потеря событий без буферизации**: при использовании UDP или TCP без дисковых очередей всплеск нагрузки или кратковременная недоступность сети ведут к потере логов. Настройка spool-директорий (как в NXLog) или очередей rsyslog обязательна для сколько-нибудь ответственного мониторинга.

Диагностика этих сбоев составляет повседневную практику L1-инженера: просмотр логов самого агента, проверка достижимости порта, анализ статистики очередей и сопоставление количества отправленных и принятых событий.

## 4. Сквозной практический пример: доставка событий с Windows Server на SIEM Elastic Stack

**Исходные условия:** инфраструктура содержит Windows Server 2019 (член домена), на котором ведётся аудит входа/выхода пользователей. В качестве SIEM применяется Elastic Stack: Logstash выполняет роль центрального коллектора (прослушивает TCP-порт 6514 с SSL), данные индексируются в Elasticsearch, визуализация через Kibana. Необходимо настроить доставку событий безопасности на SIEM с использованием агента NXLog, обеспечив шифрование трафика и структурированный формат.

**Реализация разбита на четыре шага.**

### Шаг 1. Установка и конфигурация NXLog на Windows Server

Устанавливаем NXLog Community Edition и создаём конфигурационный файл `C:\Program Files\nxlog\conf\nxlog.conf`. Конфигурация читает журнал Security, преобразует каждую запись в JSON и отправляет на Logstash по TLS.

```conf
Panic Soft
define ROOT C:\Program Files\nxlog
Moduledir %ROOT%\modules
CacheDir  %ROOT%\data
Pidfile   %ROOT%\data\nxlog.pid
SpoolDir  %ROOT%\data

<Extension json>
    Module xm_json
</Extension>

<Input security>
    Module im_msvistalog
    Query <QueryList><Query Id="0"><Select Path="Security">*</Select></Query></QueryList>
    Exec $EventReceivedTime = integer($EventReceivedTime) / 1000000;
    Exec to_json();
</Input>

<Output logstash>
    Module om_tcp
    Host logstash.internal.net
    Port 6514
    CAFile %ROOT%\cert\ca.pem
    CertFile %ROOT%\cert\client.pem
    CertKeyFile %ROOT%\cert\client.key
    AllowUntrusted FALSE
    OutputType raw
</Output>

<Route 1>
    Path security => logstash
</Route>
```

Конфигурация предполагает, что сертификаты (`ca.pem`, `client.pem`, `client.key`) уже размещены в папке `cert`; Logstash требует проверки клиентского сертификата.

### Шаг 2. Настройка Logstash для приёма syslog

Создаём конфигурацию Logstash (`/etc/logstash/conf.d/syslog-input.conf`):

```ruby
input {
  tcp {
    port => 6514
    ssl_enable => true
    ssl_cert => "/etc/logstash/certs/logstash.pem"
    ssl_key  => "/etc/logstash/certs/logstash.key"
    ssl_verify => true
    codec => json_lines
    type => "windows-security"
  }
}

filter {
  if [type] == "windows-security" {
    date {
      match => ["EventTime", "ISO8601"]
      target => "@timestamp"
    }
    mutate {
      add_field => { "[observer][ingress][zone]" => "dmz-collector" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch.internal.net:9200"]
    index => "logs-windows-security-%{+YYYY.MM.dd}"
    user => "logstash_writer"
    password => "${LS_ES_PASSWORD}"
    ssl => true
    cacert => "/etc/logstash/certs/elastic-ca.pem"
  }
}
```

Данный пайплайн принимает JSON-сообщения, парсит поле `EventTime` для установки временной метки индекса и пересылает в Elasticsearch в ежедневный индекс.

### Шаг 3. Генерация контрольного события и проверка получения

На Windows Server выполняем вход пользователя с последующим выходом (штатная активность). Через минуту в Kibana выполняем запрос:

```json
GET /logs-windows-security-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "EventID": 4624 } },
        { "range": { "@timestamp": { "gte": "now-5m" } } }
      ]
    }
  },
  "size": 1
}
```

Возможный ответ (иллюстративная схема, значения зависят от среды):

```json
{
  "hits": {
    "hits": [
      {
        "_index": "logs-windows-security-2025.10.12",
        "_source": {
          "EventID": 4624,
          "TargetUserName": "jdoe",
          "IpAddress": "10.2.3.4",
          "EventTime": "2025-10-12T09:15:22Z",
          "@timestamp": "2025-10-12T09:15:22.000Z",
          "observer": { "ingress": { "zone": "dmz-collector" } },
          "message": "An account was successfully logged on..."
        }
      }
    ]
  }
}
```

Наличие записи подтверждает, что событие покинуло Windows-сервер, прошло через NXLog и Logstash и попало в Elasticsearch.

### Шаг 4. Анализ сквозной целостности

Убедимся, что событие не было подменено и содержит исходные ключевые поля Windows Event: `EventID`, `TargetUserName`, `IpAddress`. Сравнив с локальным журналом Security на сервере (через Event Viewer), видим идентичность данных. Логи NXLog (`%ROOT%\data\nxlog.log`) содержат запись об успешной отправке:

```text
2025-10-12 09:15:24 INFO Connecting to logstash.internal.net:6514
2025-10-12 09:15:24 INFO Successfully established SSL connection
2025-10-12 09:15:24 INFO Successfully sent 1280 bytes
```

На стороне Logstash в `/var/log/logstash/logstash-plain.log` видим:

```text
[2025-10-12T09:15:24,123][INFO ][logstash.inputs.tcp     ] Received connection from 10.1.6.45
```

Эти артефакты демонстрируют, что транспортный слой функционирует корректно, шифрование и аутентификация пройдены успешно, а структурирование позволяет SIEM немедленно индексировать поля, необходимые для корреляции (например, для правила на подозрительные входы).

**Вывод примера:** сквозная цепочка «Windows Security Event → NXLog (TLS JSON) → Logstash (SSL) → Elasticsearch» реализует централизованный сбор, обеспечивает надёжность за счёт буферизации на агенте и целостность подтверждения, а также пригодна для любых масштабируемых инфраструктур.

## Источники

- [Implementing a SIEM detailed Guide. SHREYASH SALKADE](https://www.linkedin.com/posts/shreyash-salkade-396778166_implementing-a-siem-detailed-guide-1business-activity-7283205409488728065-p-LV)
- [Forward Deep Security events to a Syslog or SIEM server (Trend Micro)](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog.html)
- [Syslog forwarding: 10 best practices to forward logs securely (ManageEngine)](https://www.manageengine.com/products/eventlog/logging-guide/syslog/syslog-forwarding.html)
- [Syslog Collection (LogRhythm SIEM)](https://docs.logrhythm.com/lrsiem/docs/syslog-collection)
- [SIEM Log Collection Explained: Sources, Methods, and Key Strategies (SearchInform)](https://searchinform.com/articles/cybersecurity/measures/siem/analytics/log-management/log-collection)
- [SIEM Log Management: Log Management in the Future SOC (Exabeam)](https://www.exabeam.com/explainers/siem/siem-log-management-log-management-in-the-future-soc)
- [SIEM: Security Information & Event Management Explained (Splunk)](https://www.splunk.com/en_us/blog/learn/siem-security-information-event-management.html)
- [What is Centralized Log Management (CLM)? (Cribl)](https://cribl.io/glossary/centralized-log-management)
- [Enable log forwarding (SolarWinds SEM)](https://documentation.solarwinds.com/en/success_center/sem/content/admin_guide/new_in_6_5/sem-log-forwarding.htm)
- [Priority logs for SIEM ingestion: practitioner guidance (CISA)](https://media.defense.gov/2025/May/27/2003722069/-1/-1/0/Priority-logs-for-SIEM-ingestion-Practitioner-guidance.PDF)
- [What is Syslog? An introduction to the system log protocol (PandoraFMS)](https://pandorafms.com/en/it-topics/what-is-syslog-an-introduction-to-the-system-log-protocol)
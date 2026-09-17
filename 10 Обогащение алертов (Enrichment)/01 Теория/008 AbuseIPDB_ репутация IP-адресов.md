# AbuseIPDB: репутация IP-адресов

## 1. Место AbuseIPDB в экосистеме обогащения алертов

Обогащение (enrichment) — одна из ключевых операций уровня SOC L1, превращающая «сырой» алерт в инцидент, готовый к приоритизации и эскалации. IP-адрес источника или назначения — самый массовый индикатор, извлекаемый из событий безопасности, и его контекстное наполнение напрямую определяет скорость реагирования. AbuseIPDB — специализированный community-driven сервис репутации IP-адресов, предоставляющий по API оценку уверенности в злонамеренности IP на основе сводных отчётов тысяч участников.

В отличие от полнофункциональных платформ threat intelligence, AbuseIPDB не оперирует доменами, URL или файловыми хэшами. Его единственная сущность — IP (v4 и v6), а источник данных — добровольные сообщения системных администраторов, honeypot-ловушек, межсетевых экранов и других средств обнаружения. Такой подход обеспечивает простоту интеграции и низкий порог входа, но одновременно накладывает ограничения по глубине контекста.

Путаница между внешне схожими терминами «репутация IP» и «индикатор компрометации» (IoC) требует чёткого разграничения. IoC — это артефакт, наблюдаемый в конкретной атаке (хэш файла, C2-домен, сигнатура YARA); он уникален для кампании и быстро теряет актуальность. Репутация IP, напротив, агрегирует поведение адреса на длительном интервале: сколько раз и по каким категориям его наблюдали в злонамеренной активности. AbuseIPDB трансформирует множество разрозненных отчётов в единую метрику — **Abuse Confidence Score** (оценка от 0% до 100%).

Ниже представлена сравнительная таблица, фиксирующая принципиальные отличия AbuseIPDB от смежных сервисов, с которыми его часто сравнивают в SOC-пайплайнах. Данные основаны на информации из [блога isMalicious](https://ismalicious.com/posts/ismalicious-vs-abuseipdb-ip-domain-reputation) и [статьи Cryptsus](https://cryptsus.com/blog/sentinel-siem-abuseipdb-logic-app-soar.html).

| Сервис                           | Типы индикаторов                     | Основной источник данных                                   | Бесплатный лимит (запросов/сутки) | Стоимость коммерческого использования (на 2025 г.) | Уникальные возможности в сравнении с AbuseIPDB          |
| -------------------------------- | ------------------------------------ | ---------------------------------------------------------- | --------------------------------- | -------------------------------------------------- | ------------------------------------------------------ |
| **AbuseIPDB**                    | Только IP (IPv4/IPv6)                | Crowdsourcing (сообщество)                                 | 1 000 (до 3 000 при верификации)  | от $228/год (10 000 запросов/сутки)                | Специализированная репутация IP, категории abuse-типов |
| **VirusTotal**                   | IP, домены, URL, хэши файлов         | ~70 антивирусных движков + сообщество                      | 500 (некоммерческое использование) | от $75 000/год                                      | Мультииндикаторная проверка, детектирование по сигнатурам |
| **Microsoft Defender TI (MDTI)** | IP, домены, URL, сертификаты, WHOIS | Microsoft Security Graph, пассивный DNS, краулеры          | Ограниченный бесплатный фид       | от $43 000/год                                      | Глубокая интеграция в экосистему Microsoft, пассивный DNS |
| **isMalicious**                  | IP, домены, URL, email               | 500+ курируемых threat-фидов, honeypot, автоматический анализ | 30 запросов/месяц                 | от $99/месяц                                        | Единый API для IP, доменов и URL, Webhooks, мониторинг |

Таблица демонстрирует, что AbuseIPDB выигрывает по cost-efficiency в сценариях, где задача сужается исключительно до быстрой оценки репутации IP. Если же требуется многофакторный анализ (домен + хэш + пассивный DNS), его необходимо дополнять другими решениями или выбирать платформу уровня VirusTotal/MDTI.

AbuseIPDB также важно отличать от простых чёрных списков (DNSBL/RBL). Чёрный список — бинарное решение (есть/нет), не отражающее степень угрозы. AbuseIPDB выдаёт гранулярную оценку, сопровождаемую категориями (DDoS, брутфорс, фишинг и т.п.) и временем последнего отчёта. Аналитик SOC L1 может настроить порог реагирования: например, автоматически блокировать IP со Score > 90 и категорией «SSH Brute‑Force» за последние сутки, а при Score 50–89 — отправлять на ручную верификацию.

Таким образом, AbuseIPDB занимает нишу «лёгкого», массового IP-репутационного слоя, который легко встраивается в SOAR-плейбуки, SIEM-корреляции и скрипты автоматизации первого уровня без необходимости дорогостоящих подписок. Понимание его места относительно других сервисов — фундамент для грамотного проектирования конвейера обогащения.

## 2. API и модель данных AbuseIPDB

Ядро взаимодействия с AbuseIPDB — RESTful API v2, аутентифицируемый ключом, передаваемым в HTTP-заголовке `Key`. Все ответы возвращаются в формате JSON. В контексте SOC L1 наиболее востребован конечный эндпоинт `/api/v2/check`, реализующий запрос репутации конкретного IP. Дополнительные эндпоинты (`/report` для отправки отчёта, `/blacklist` для получения списка злонамеренных IP) используются реже — главным образом, для обратной связи и периодической выгрузки индикаторов.

Структура запроса к `/api/v2/check` включает три параметра (обязательный `ipAddress` и опциональные `maxAgeInDays`, `verbose`). Аутентификационный ключ передаётся в заголовке `Key`, тип контента — `Accept: application/json`. Типичный curl-запрос иллюстрирует механику (значения API-ключа и IP заменены на плейсхолдеры, зависящие от среды):

```bash
curl -X GET "https://api.abuseipdb.com/api/v2/check" \
  -G \
  --data-urlencode "ipAddress=<IP-адрес>" \
  --data-urlencode "maxAgeInDays=90" \
  --data-urlencode "verbose=true" \
  -H "Key: ваш_api_ключ" \
  -H "Accept: application/json"
```

Параметр `maxAgeInDays` ограничивает окно учитываемых отчётов (от 1 до 365 дней). Уменьшение окна повышает актуальность скора, но снижает полноту для редко встречающихся IP. Параметр `verbose` управляет включением детализированного массива отчётов, содержащего идентификаторы категорий и временные метки.

Ответ API представляет собой JSON-объект верхнего уровня с единственным ключом `data`, внутри которого сосредоточены репутационные метаданные. Ниже приведена таблица ключевых полей ответа (на основе спецификации из [документации MCP-сервера](https://mcpservers.org/servers/salmanwz/mcp-abuseipdb) и открытой документации AbuseIPDB):

| Поле                    | Тип         | Описание                                                                             |
| ----------------------- | ----------- | ------------------------------------------------------------------------------------ |
| `ipAddress`             | string      | Запрошенный IP‑адрес (IPv4 или IPv6)                                                 |
| `abuseConfidenceScore`  | integer     | Процент уверенности в злонамеренности IP (0–100). Рассчитывается на основе частоты, свежести и числа уникальных репортёров |
| `totalReports`          | integer     | Общее количество отчётов об этом IP, попавших в выбранный временной интервал          |
| `lastReportedAt`        | string|null | Временная метка последнего отчёта в ISO‑8601 или `null`, если отчётов нет             |
| `isp`                   | string      | Название интернет-провайдера, которому принадлежит IP                                 |
| `usageType`             | string      | Категория использования IP (Data Center/Web Hosting, Fixed Line ISP, Mobile ISP и т.д.) |
| `domain`                | string|null | Ассоциированное с IP доменное имя (PTR-запись), если доступно                          |
| `countryCode`           | string|null | Двухбуквенный код страны по ISO 3166-1 alpha‑2                                       |
| `isWhitelisted`         | boolean     | Признак нахождения IP в белом списке AbuseIPDB (обычно `false` для проверяемых адресов) |
| `isTor`                 | boolean     | Флаг Tor exit node                                                                    |
| `reports`               | array       | Массив объектов отчётов (только при `verbose=true`), каждый содержит `reportedAt`, `comment`, `categories` (массив числовых идентификаторов категорий злоупотребления) |

**Формирование Abuse Confidence Score.** В отличие от простого усреднения, алгоритм использует взвешенную модель, где больший вес имеют свежие отчёты и отчёты от уникальных репортёров. Точная формула является закрытой, но известно, что она учитывает количество отчётов за разные периоды (1, 7, 30, 90, 365 дней) и снижает вес адресов, зарегистрированных в исторических спам-кампаниях, но неактивных в текущем окне. Это позволяет избегать «вечного клейма» для IP, которые были скомпрометированы, но позже очищены. Практический результат: IP с 100 отчётами за последние сутки получит Score ~95-99, а тот же IP с 100 отчётами, растянутыми на год, — около 50-70.

**Категории злоупотреблений.** В ответе `reports` каждый отчёт содержит массив `categories` — чисел от 1 до 31, соответствующих фиксированному перечню типов активности. Наиболее релевантные для SOC L1 категории:

- 4 — DDoS Attack
- 14 — Port Scan
- 18 — Brute-Force
- 19 — Bad Web Bot
- 21 — Web App Attack
- 22 — SSH/Telnet Brute-Force
- 25 — Spam (email)

Полный список доступен в официальной документации и не дублируется здесь. Именно комбинация высокого Score и присутствия определённых категорий даёт наиболее точный сигнал: например, IP с Score 100 и категориями [18, 22] практически гарантированно участвует в автоматизированном переборе учётных данных.

**Ограничения API и кэширование.** Бесплатный ключ ограничен 1 000 запросами в сутки (до 3 000 при верификации домена). При превышении лимита API возвращает HTTP 429 (Too Many Requests), после чего запросы блокируются до истечения суточного окна. Платные тарифы стартуют с $228/год за 10 000 запросов/сутки. В SOC-интеграциях эти лимиты диктуют обязательное кэширование результатов. Типичная практика — кэш на 3–6 часов для IP, уже проверенных в рамках потока алертов. В [руководстве по настройке Graylog](https://community.graylog.org/t/how-to-abuseipdb-lookup-setup/32508) показан пример кэша с expire after access 3 часа. Такой подход снижает нагрузку на API и ускоряет отклик системы обогащения.

**Потоковая модель сообщества.** AbuseIPDB не курирует профессиональные фиды; любой пользователь может отправить отчёт через API `POST /api/v2/report` или через веб-интерфейс. Модерация присутствует, но в основном направлена на борьбу со спам-отчётами, а не на экспертную валидацию. Это порождает известный недостаток — возможную «шумиху» вокруг популярных публичных IP (например, выходные узлы Tor или IP крупных облачных провайдеров), что приводит к завышенному Score без реальной угрозы. Аналитик должен учитывать этот фактор, анализируя контекст (принадлежность IP хостинг-провайдеру, дата‑центру, VPN-сервису) и при необходимости понижать приоритет.

Таким образом, API AbuseIPDB предоставляет простой, но достаточно информативный интерфейс, позволяющий за несколько миллисекунд превратить безликий IP в многомерный профиль риска. Понимание структуры ответа и внутренней механики скора необходимо для корректной интерпретации данных автоматизированными правилами.

## 3. Интеграция AbuseIPDB в процессы SOC

Использование AbuseIPDB в SOC L1 разворачивается по трём основным паттернам: ручная проверка аналитиком, автоматическое обогащение в SIEM/SOAR и прямая блокировка на периметре. Каждый паттерн имеет свои особенности, инструменты и подводные камни.

**Ручная проверка.** Наиболее простой сценарий, применяемый при расследовании единичных подозрительных IP в условиях отсутствия настроенных автоматических интеграций. Аналитик копирует IP из алерта, выполняет скрипт (Python, PowerShell) или отправляет curl-запрос к API, мгновенно получая Score и категории. Пример на Python, демонстрирующий вызов с обработкой ошибок (адаптирован из [практического руководства по автоматизации](https://medium.com/@onmouse0ver/part-four-a-practical-guide-to-automate-threat-analysis-abuse-ipdb-combining-the-scripts-1a1b3b03b222)):

```python
import requests

ABUSEIPDB_API_KEY = "ваш_api_ключ"
BASE_URL = "https://api.abuseipdb.com/api/v2/check"

def abuseipdb_check(ip: str, max_age_days: int = 90) -> dict:
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": True
    }
    try:
        r = requests.get(BASE_URL, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException:
        return None

# Применение: аналитик передаёт IP из алерта
result = abuseipdb_check("192.0.2.15")
if result:
    data = result["data"]
    print(f"Score: {data['abuseConfidenceScore']}%, Reports: {data['totalReports']}, Categories: {[r['categories'] for r in data['reports']]}")
```

Такой подход хорош для ad‑hoc расследований, но не масштабируется на поток из сотен алертов в час.

**Автоматическое обогащение в SIEM/SOAR.** Основной промышленный сценарий. Логика: триггер на новый инцидент/алерт → извлечение IP → обращение к AbuseIPDB → дополнение события полями `abuse_score`, `categories` → корреляция/приоритизация.

Реализации варьируются от встроенных data adapter до кастомных playbooks:

- **Microsoft Sentinel** — через [Azure Logic App Playbook](https://cryptsus.com/blog/sentinel-siem-abuseipdb-logic-app-soar.html). Триггер `Microsoft Sentinel incident` запускает логическое приложение, которое action `Entities – Get IPs` извлекает IP, затем HTTP-экшен отправляет GET-запрос к AbuseIPDB, и полученные Score, ISP, категории добавляются в комментарий и теги инцидента. Преимущества: безотказное восстановление после превышения лимита (Logic App автоматически повторяет упавшие шаги).
- **Graylog** — конфигурация Lookup Table, подробно описанная [в сообществе Graylog](https://community.graylog.org/t/how-to-abuseipdb-lookup-setup/32508). Data Adapter с URL `https://api.abuseipdb.com/api/v2/check?ipAddress=${key}` и JSONPath `$.data` позволяет бесшовно добавить поля `abuseConfidenceScore`, `isp` к каждому сообщению. Pipeline rule:

  ```text
  rule "AbuseIPDB_Lookup"
  when has_field("src_ip")
  then
      let abuse = lookup("abuseipdb_lookup", to_string($message.src_ip));
      set_field("abuse_confidence_score", abuse["abuseConfidenceScore"]);
      set_field("abuse_categories", abuse["reports"]);
  end
  ```

- **Wazuh** — через кастомную интеграцию на Python, как показано в [руководстве Wazuh](https://wazuh.com/blog/detecting-known-bad-actors-with-wazuh-and-abuseipdb). Сценарий: скрипт `/var/ossec/integrations/custom-abuseipdb.py` читает `alerts.json`, извлекает IP и вызывает Check API, возвращая результат в stdout, который Wazuh разбирает и дополняет алерт. В `ossec.conf` добавляется блок:

  ```xml
  <integration>
    <name>custom-abuseipdb.py</name>
    <hook_url>api.abuseipdb.com</hook_url>
    <rule_id>100002,100003</rule_id>
    <alert_format>json</alert_format>
  </integration>
  ```

  Затем локальные правила в `local_rules.xml` могут триггериться на `abuseConfidenceScore > 90`.

- **Splunk** — официальное [приложение AbuseIPDB](https://splunkbase.splunk.com/app/7040) обеспечивает lookup-команду для встраивания в поисковые запросы.
- **Palo Alto Cortex XSOAR** — готовый интеграционный пакет [AbuseIPDB](https://xsoar.pan.dev/docs/reference/integrations/abuse-ipdb) с командами `!ip`, `!abuseipdb-report-ip`, упрощающими включение в playbooks без написания кода.
- **Cortex Analyzer** для TheHive — автоматический запуск при анализе observable типа IP (как [описано в документации](https://thehive-project.github.io/Cortex-Analyzers/analyzers/AbuseIPDB/)), возвращает Score прямо в карточку инцидента.

**Прямая блокировка.** Некоторые организации используют AbuseIPDB для автоматического наполнения чёрных списков на межсетевых экранах (FortiGate, pfSense, CSF) и WordPress-плагинах (например, [Advanced IP Blocker](https://advaipbl.com/abuseipdb-integration-guide)). Здесь критичен выбор порога Score; обычно рекомендуется ≥90 для минимизации ложных срабатываний. Однако даже при высоком пороге существует риск блокировки легитимных IP, принадлежащих облачным провайдерам, — поэтому в production среде блокировку часто предваряют проверкой `usageType` и `isp` для исключения дата‑центровых диапазонов.

**Типичные ошибки и ограничения.**
- *Слепая вера в Score.* Без анализа категорий и ISP высокий Score может быть вызван единичным всплеском отчётов о спаме с адреса, который также используется легитимным почтовым сервером. Рекомендуется всегда комбинировать Score с другими источниками (внутренняя статистика, GeoIP, ThreatConnect).
- *Игнорирование ограничения на домены.* AbuseIPDB **не** проверяет домены. Попытка отправить в `/check` доменное имя вернёт ошибку, а не IP-резолв. Для доменов необходимо использовать другие сервисы (VirusTotal, isMalicious).
- *Превышение лимита без кэша.* Даже 10 000 запросов/сутки могут быть исчерпаны в крупном SOC за несколько часов. Отсутствие кэширования приводит к отказу в обслуживании API и потере данных обогащения.
- *Ложноположительные срабатывания для инфраструктурных IP.* Tor-выходные узлы, VPN-серверы и прокси-сервисы часто имеют высокий Score, не отражая конкретной атаки на организацию. Флаг `isTor` позволяет их фильтровать, но не снимает проблему полностью.

**Рекомендации по внедрению в SOC-пайплайн:**
1. Настроить кэширующий слой на 1–3 часа для каждого проверенного IP.
2. Определить комбинированные правила эскалации: `abuseConfidenceScore > 80 AND category in [14,18,22] AND NOT isTor` → автоматический маппинг на High severity.
3. Интегрировать AbuseIPDB как первый быстрый шаг обогащения; при необходимости — дополнять более дорогими источниками (VirusTotal, пассивный DNS) только для подозрительных IP.
4. Регулярно мониторить остаток API-лимита через заголовок ответа `X-RateLimit-Remaining` и оповещать при приближении к исчерпанию.

## 4. Сквозной практический пример: автоматическое обогащение инцидента Sentinel данными AbuseIPDB

**Исходные условия.** Организация использует Microsoft Sentinel в качестве SIEM и настроила аналитическое правило, генерирующее инцидент при обнаружении пяти неудачных попыток SSH-аутентификации с одного внешнего IP за 10 минут. SOC-аналитик L1 должен в течение 5 минут оценить угрозу, обогатить инцидент репутационной информацией и принять решение о блокировке. Для автоматизации развёрнут Logic App Playbook, описанный в [Cryptsus Blog](https://cryptsus.com/blog/sentinel-siem-abuseipdb-logic-app-soar.html). Ниже — пошаговая демонстрация с ключевыми артефактами.

**Шаг 1: Получение инцидента и извлечение IP.** Playbook триггерится при создании инцидента Sentinel. Первое действие — `Entities – Get IPs (Preview)` — извлекает все IP-адреса, распознанные в инциденте. В нашем кейсе это единственный адрес `203.0.113.42`. Артефакт — фрагмент тела HTTP-запроса, который Logic App отправляет к Sentinel API (иллюстративная схема):

```json
{
  "incidentArmId": "/subscriptions/.../providers/Microsoft.SecurityInsights/incidents/<incident-guid>",
  "entities": [
    {
      "type": "Ip",
      "address": "203.0.113.42",
      "location": {
        "Address": "203.0.113.42",
        "ipAddress": "203.0.113.42"
      }
    }
  ]
}
```

**Шаг 2: Запрос к AbuseIPDB Check API.** Logic App выполняет HTTP-экшен с методом GET к `https://api.abuseipdb.com/api/v2/check` и параметрами `ipAddress=203.0.113.42&maxAgeInDays=30&verbose=true`. Артефакт — эквивалентный curl, который позволил бы аналитику воспроизвести проверку вручную:

```bash
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=203.0.113.42&maxAgeInDays=30&verbose=true" \
  -H "Key: $ABUSEIPDB_API_KEY" \
  -H "Accept: application/json"
```

**Шаг 3: Анализ ответа и принятие решения.** Сервер возвращает структуру:

```json
{
  "data": {
    "ipAddress": "203.0.113.42",
    "abuseConfidenceScore": 97,
    "totalReports": 145,
    "lastReportedAt": "2025-03-15T14:22:00+00:00",
    "isWhitelisted": false,
    "isTor": false,
    "isp": "Contoso Cloud Services",
    "usageType": "Data Center/Web Hosting",
    "countryCode": "US",
    "reports": [
      {
        "reportedAt": "2025-03-15T14:22:00+00:00",
        "categories": [14, 18, 22],
        "comment": "SSH brute-force detected by honeypot"
      }
    ]
  }
}
```

Аналитик видит: Score 97, категории 14 (Port Scan), 18 (Brute-Force), 22 (SSH/Telnet Brute-Force), ISP — облачный провайдер, IP не Tor. Вывод — с высокой вероятностью адрес участвует в автоматизированной атаке перебора паролей. Ложноположительный сценарий (легитимный сервер администрирования) исключён, так как IP принадлежит дата‑центру и не связан с корпоративной инфраструктурой организации.

**Шаг 4: Обновление инцидента Sentinel.** Playbook добавляет в инцидент комментарий и теги `AbuseIPDB_High`, `Score_97`, `SSH_BruteForce`, обогащая алерт для L2-аналитиков. Соответствующий API-вызов (PATCH к инциденту Sentinel) выглядит так (иллюстративно):

```json
PATCH https://management.azure.com/.../incidents/<incident-guid>?api-version=2023-02-01

{
  "properties": {
    "severity": "High",
    "labels": [
      {"labelName": "AbuseIPDB_High", "labelType": "User"},
      {"labelName": "Score_97", "labelType": "User"},
      {"labelName": "SSH_BruteForce", "labelType": "User"}
    ]
  },
  "additionalData": {
    "comments": [
      {
        "message": "AbuseIPDB enrichment: Score 97 (reports: 145, categories: 14,18,22). ISP: Contoso Cloud. Recommendation: block IP and escalate."
      }
    ]
  }
}
```

**Шаг 5: Автоматическая блокировка (опционально).** В настроенном плейбуке после обогащения может следовать действие по добавлению IP в Network Security Group (NSG) или отправке на межсетевой экран через FortiGate API. В нашей схеме при Score ≥90 и категории 22 происходит вызов REST API брандмауэра для динамического чёрного списка. Артефакт (иллюстративная команда для FortiOS 7.x):

```bash
curl -s -k -X POST "https://<fortigate-ip>/api/v2/monitor/ipv4/address" \
  -H "Authorization: Bearer <forti_token>" \
  -d '{"name":"AutoBlock_203.0.113.42","subnet":"203.0.113.42/32","comment":"AbuseIPDB Score 97 - SSH brute-force"}'
```

**Ожидаемый вывод.** Сквозной пример демонстрирует, как за считанные секунды абстрактный алерт о подозрительном IP проходит путь от сырого события до детерминированного решения с автоматической блокировкой. AbuseIPDB выступает ключевым звеном обогащения, обеспечивая необходимый контекст без задержек, типичных для глубинного анализа вредоносного ПО. Для SOC L1 такой конвейер сокращает время реакции с десятков минут до секунд, освобождая человеческий ресурс для более сложных инцидентов.

## Источники

- [isMalicious vs AbuseIPDB: IP Reputation and Beyond](https://ismalicious.com/posts/ismalicious-vs-abuseipdb-ip-domain-reputation)
- [Integrations | AbuseIPDB](https://www.abuseipdb.com/integrations)
- [Sentinel IP Incident Automation with AbuseIPDB Logic App — Cryptsus Blog](https://cryptsus.com/blog/sentinel-siem-abuseipdb-logic-app-soar.html)
- [IP reputation ELK integration — Discuss the Elastic Stack](https://discuss.elastic.co/t/ip-reputation-elk-integration/265959)
- [AbuseIpDB MCP Server | Awesome MCP Servers](https://mcpservers.org/servers/salmanwz/mcp-abuseipdb)
- [Detecting known bad actors with Wazuh and AbuseIPDB | Wazuh](https://wazuh.com/blog/detecting-known-bad-actors-with-wazuh-and-abuseipdb)
- [AbuseIPDB Integration Guide | Advanced IP Blocker](https://advaipbl.com/abuseipdb-integration-guide)
- [HOW TO: AbuseIPDB lookup setup - Graylog Community](https://community.graylog.org/t/how-to-abuseipdb-lookup-setup/32508)
- [AbuseIPDB Enrichment | ThreatConnect](https://knowledge.threatconnect.com/docs/abuseipdb-enrichment)
- [Part Four — A Practical Guide to Automate Threat Analysis: Abuse IPDB & Combining the Scripts](https://medium.com/@onmouse0ver/part-four-a-practical-guide-to-automate-threat-analysis-abuse-ipdb-combining-the-scripts-1a1b3b03b222)
- [Abuse IPDB - Marketplace and Integrations | Dataminr](https://www.dataminr.com/integration-partners/abuse-ipdb)
- [Enrich observables with AbuseIPDB threat intelligence | Dynatrace](https://www.dynatrace.com/news/blog/enrich-observables-with-abuseipdb-threat-intelligence)
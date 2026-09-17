# systemd journal и его отличие от syslog

## От syslog к journald: эволюция системного журналирования Linux

Протокол **syslog**, разработанный в 1980-х годах, долгое время оставался стандартным механизмом централизованного сбора и маршрутизации сообщений в Unix-подобных системах. Он определяет формат сообщения, уровни важности (severity) и категории источников (facility), описываемые в RFC 3164 и RFC 5424. Классический демон `syslogd` принимал сообщения через Unix-сокет `/dev/log` и раскладывал их в текстовые файлы каталога `/var/log/` согласно правилам, заданным в `/etc/syslog.conf`.  
Современные Linux-дистрибутивы почти повсеместно заменили устаревший `syslogd` на высокопроизводительные реализации — **rsyslog** и **syslog-ng**, которые добавили поддержку TCP/TLS, фильтрацию, модули ввода-вывода и возможность парсинга сообщений в структурированные форматы, например JSON. Тем не менее фундаментальная модель осталась прежней: лог — это одна текстовая строка с минимальным набором стандартных полей, а поиск и анализ сводятся к применению `grep`, `awk` и `tail`.

С внедрением **systemd** как системного менеджера (PID 1) появился новый компонент — **systemd-journald** (далее journald). Его задача — собрать все журнальные сообщения, порождённые системой, в единую индексированную базу, обеспечив при этом богатый контекст каждого события. Journald был представлен как ответ на потребности инициализации: сервисы, запускаемые systemd, пишут в stdout/stderr, и journald прозрачно перехватывает эти потоки, автоматически обогащая запись идентификатором юнита, PID, cgroup и другой сервисной метаинформацией. В отличие от классического syslog, journald хранит логи в **бинарном формате**, что позволяет быстро перемещаться по записям, фильтровать по множеству полей и гарантировать целостность с помощью криптографических подписей (опционально).

Ключевое различие между двумя системами лежит не в функциональном противостоянии, а в разделении ролей: journald — это локальный коллектор с мощным контекстным поиском, тогда как syslog-демоны (rsyslog, syslog-ng) традиционно фокусируются на маршрутизации, централизованном сборе и долгосрочном хранении логов. На практике они сосуществуют: journald принимает сообщения первым, а затем, если настроена опция `ForwardToSyslog=yes`, перенаправляет их в rsyslog для записи в классические текстовые файлы или отправки на удалённый SIEM. Таким образом, аспект «отличие от syslog» — это не вопрос выбора одного вместо другого, а понимание различий в архитектуре, форматах и моделях использования.

Ниже приведена сводка основных характеристик, по которым обычно проводят сравнение (таблица 1).

**Таблица 1. Сравнение systemd journal и традиционного syslog**

| Характеристика | Традиционный syslog (rsyslog/syslog-ng) | systemd journal (journald) |
|----------------|----------------------------------------|----------------------------|
| Формат хранения | Текстовые файлы (`/var/log/messages`, `secure`, …) | Бинарный журнал (индексные файлы в `/var/log/journal/`) |
| Структура записи | Одна строка: `<timestamp> <host> <tag>[<pid>]: <message>` | Набор полей ключ-значение (JSON-подобная структура, более 20 стандартных полей) |
| Поиск и фильтрация | `grep`, `awk`, `sed` — медленный линейный обход | `journalctl` с индексами, быстрый поиск по любому полю |
| Метаданные | Ограничены (facility, severity, PID, имя программы) | Обширные: unit, cgroup, SELinux-контекст, UID/GID, boot ID, machine ID, invocation ID и др. |
| Источники | Только сообщения, отправленные через `syslog()` API | Перехват stdout/stderr сервисов systemd, `/dev/kmsg`, syslog-сокет, sd-journal API, контейнеры |
| Целостность и безопасность | Не предусмотрена (хотя rsyslog может использовать TLS при передаче) | Опциональные криптографические подписи (FSS), контроль целостности журнала |
| Передача на удалённый узел | Встроена в rsyslog/syslog-ng (UDP/TCP/TLS, RELP) | Только через отдельный сервис `systemd-journal-remote` (экспериментальный) или пересылку через syslog |
| Ротация и управление размером | Внешний инструмент `logrotate` | Встроенный механизм с параметрами `SystemMaxUse`, `MaxRetentionSec`, `MaxFileSec` |
| Типичный сценарий использования | Централизованный сбор с множества устройств, долговременное хранение | Локальный интерактивный анализ, траблшутинг сервисов, форензика |

Исторически сложилась практика совместной работы: journald принимает логи, а rsyslog забирает их для записи в текстовые файлы и отправки во внешние системы. На многих дистрибутивах по умолчанию включён модуль `imjournal`, который заставляет rsyslog читать журнал напрямую, минуя простой syslog-сокет, что позволяет сохранить часть структурированных полей.

## Архитектура systemd-journald: источники, хранение и структура записей

Сервис `systemd-journald.service` запускается на раннем этапе загрузки и функционирует как универсальная шина для всех сообщений системы. Его архитектура строится вокруг нескольких каналов входящих данных и централизованной базы-журнала (рис. 1).

```text
[stdout/stderr сервисов] ──▶┐
[/dev/kmsg (ядро)] ────────▶┤
[syslog API (сокет)]  ────▶┤ systemd-journald ──▶ бинарные файлы журнала (/var/log/journal)
[sd-journal API (приложения)]─▶┤                │
[Контейнеры (Docker/Podman)] ─▶┘                │
                                          ┌──────┘ (при ForwardToSyslog=yes)
                                          ▼
                                     [/run/systemd/journal/syslog] ──▶ rsyslog ──▶ текстовые файлы /var/log
```

**Рис. 1. Потоки сообщений в journald**

`systemd-journald` собирает логи из пяти основных источников:
1. **Стандартные потоки сервисов** (`_TRANSPORT=stdout`): когда systemd запускает юнит, он подключает `stdout` и `stderr` процесса к сокету журнала, поэтому любое приложение, выводящее текст в консоль, автоматически логируется. В запись добавляются поля `_SYSTEMD_UNIT`, `_SYSTEMD_CGROUP`, `_PID`, `_COMM`.
2. **Кольцевой буфер ядра** (`_TRANSPORT=kernel`): journald читает устройство `/dev/kmsg`, получая сообщения ядра — от старта оборудования до ошибок драйверов. Это заменяет традиционную утилиту `klogd`.
3. **Syslog-совместимый сокет** (`_TRANSPORT=syslog`): для совместимости с программами, использующими вызов `syslog()` или команду `logger`, journald слушает сокет `/run/systemd/journal/syslog` (символическая ссылка на `/dev/log`). Сообщения, поступающие по этому пути, обогащаются полями `SYSLOG_FACILITY`, `SYSLOG_IDENTIFIER`.
4. **SD-Journal API** (`_TRANSPORT=journal`): приложения могут напрямую отправлять структурированные записи через библиотеку `libsystemd`, указывая произвольные поля. Это обеспечивает максимальную детализацию.
5. **Контейнеры**: при использовании драйвера `journald` в Docker или Podman вывод контейнеров также попадает в журнал с дополнительными полями `CONTAINER_ID`, `CONTAINER_NAME`.

### Структура записи журнала

Каждая запись представляет собой набор пар ключ-значение. В отличие от плоской текстовой строки syslog, запись содержит десятки полей, многие из которых заполняются автоматически. Пример структуры в формате JSON, экспортированном через `journalctl -o json` (поля приведены из реальной выдачи на действующей системе, см. источник Righteous IT):

```json
{
  "_EXE" : "/usr/sbin/sshd",
  "_SYSTEMD_UNIT" : "ssh.service",
  "_SYSTEMD_CGROUP" : "/system.slice/ssh.service",
  "_UID" : "0",
  "_GID" : "0",
  "_PID" : "1304",
  "_COMM" : "sshd",
  "_HOSTNAME" : "LAB",
  "_MACHINE_ID" : "47b59f088dc74eb0b8544be4c3276463",
  "_BOOT_ID" : "5c57e83c3abd457c95d0695807667c9e",
  "_SYSTEMD_INVOCATION_ID" : "70a0b99512864d22a8f8b10752ad6537",
  "PRIORITY" : "6",
  "SYSLOG_FACILITY" : "4",
  "SYSLOG_IDENTIFIER" : "sshd",
  "MESSAGE" : "Accepted password for lab from 192.168.10.1 port 56280 ssh2",
  "_TRANSPORT" : "syslog",
  "__REALTIME_TIMESTAMP" : "1721560922218814",
  "_SOURCE_REALTIME_TIMESTAMP" : "1721560922218786",
  "__MONOTONIC_TIMESTAMP" : "265429588",
  "__CURSOR" : "s=743db8433dcc46ca9b9cecd7a4272061;i=1d6f;b=5c57e83c3abd457c95d0695807667c9e;m=fd22254;t=61dc0233a613e;x=31ff9c313be9c36f"
}
```

**Таблица 2. Основные поля journald**

| Поле | Назначение |
|------|------------|
| `MESSAGE` | Текстовое сообщение (аналог body в syslog) |
| `_HOSTNAME` | Имя хоста, сгенерировавшего запись |
| `_PID`, `_UID`, `_GID` | Идентификаторы процесса, пользователя и группы |
| `_COMM` | Имя исполняемого файла |
| `_SYSTEMD_UNIT` | Имя юнита systemd, к которому относится процесс |
| `_BOOT_ID` | Уникальный идентификатор загрузки (меняется после перезагрузки) |
| `_MACHINE_ID` | Уникальный ID машины (из `/etc/machine-id`) |
| `__REALTIME_TIMESTAMP` | Время события в формате Unix epoch с микросекундами (UTC) |
| `__MONOTONIC_TIMESTAMP` | Монотонное время с момента загрузки |
| `__CURSOR` | Непрозрачная строка, уникально идентифицирующая запись (используется для позиционирования) |
| `PRIORITY` | Числовой уровень важности (0–7) |
| `SYSLOG_FACILITY` | Категория syslog (если сообщение пришло через syslog-сокет) |
| `_TRANSPORT` | Как запись попала в журнал (`kernel`, `syslog`, `stdout`, `journal`) |

Помимо перечисленных, могут присутствовать поля `CODE_FILE`, `CODE_LINE`, `CODE_FUNC`, добавленные через API, а также `COREDUMP_*` при записи core-дампов. Таким образом, journald обеспечивает структурированный контекст, недоступный в классическом syslog, где извлекать ту же информацию пришлось бы разбором сообщения регулярными выражениями.

### Хранение и управление размером

Journald хранит записи в бинарных файлах специального формата, расположенных в каталоге `/var/log/journal/<machine-id>/` (при постоянном хранении). Файлы организованы как индексы: есть файлы журнала с суффиксами `.journal`, и они не требуют ротации `logrotate` — вместо этого встроенный механизм автоматически удаляет старые записи при превышении порогов, задаваемых в `/etc/systemd/journald.conf`:

- `SystemMaxUse=` — максимальный лимит дискового пространства для всех файлов журнала (например, 10% файловой системы);
- `RuntimeMaxUse=` — лимит для временного хранилища в `/run/log/journal` (если не создан постоянный каталог);
- `MaxRetentionSec=` — максимальное время хранения записей;
- `MaxFileSec=` — максимальное время до ротации одного файла.

Если каталог `/var/log/journal` отсутствует, journald работает в volatile-режиме, храня журнал только в `/run/log/journal` (в оперативной памяти), и записи теряются при перезагрузке.

### Взаимодействие с syslog-демонами

Классические syslog-демоны подключаются к journald двумя способами:
1. Через **совместимый сокет** `/run/systemd/journal/syslog`: если параметр `ForwardToSyslog=yes` в `journald.conf`, journald копирует поступающие сообщения в этот сокет. Rsyslog может читать его с помощью модуля `imuxsock`. При этом передаются только минимальные поля (timestamp, facility, severity, идентификатор, сообщение) — структурированная информация теряется.
2. Через **модуль imjournal**: rsyslog напрямую читает бинарный журнал, получая доступ ко всем полям, и может использовать их для фильтрации и маршрутизации. Например, в `/etc/rsyslog.conf` может быть добавлено:

```bash
# Загрузка модулей
module(load="imuxsock")   # поддержка локального syslog-сокета
module(load="imjournal")  # чтение из журнала systemd
module(load="mmjsonparse") # парсинг JSON

# Направление сообщений от systemd в отдельный файл
if $syslogtag startswith "systemd" then /var/log/systemd.log
```

При использовании `imjournal` отпадает необходимость в `ForwardToSyslog`, и журнал остаётся основным хранилищем. Такой режим рекомендован Red Hat и другими поставщиками для серверных систем.

## Практическая работа с журналами: команды, конфигурация и интеграция

### Команда journalctl: основные возможности

`journalctl` — основной инструмент для чтения и фильтрации записей journald. В отличие от `grep` по текстовым логам, он использует индексы и позволяет задавать сложные критерии без сканирования всего файла. Ключевые опции:

- `journalctl` — показать все записи текущей загрузки (аналог `-b`).
- `journalctl -b -1` — журнал предыдущей загрузки (если включено постоянное хранение).
- `journalctl -u ssh.service` — только сообщения от указанного юнита.
- `journalctl -p err` — сообщения с приоритетом `err` и выше (`err`, `crit`, `alert`, `emerg`). Можно комбинировать: `-p 3` равнозначно.
- `journalctl --since "2025-12-19 10:00:00" --until "10:30:00"` — временной диапазон.
- `journalctl -f` — режим follow (аналог `tail -f`).
- `journalctl -o verbose` — вывод всех полей в блочном формате.
- `journalctl -o json` — экспорт в JSON (удобен для скриптов и SIEM).

Примеры использования в контексте SOC L1:

```bash
# Просмотр всех ошибок sshd за текущий день
journalctl -u ssh.service -p err --since today

# Поиск конкретного пользователя в сообщениях
journalctl _COMM=sshd | grep -i "invalid user"

# Найти записи по PID
journalctl _PID=1304
```

Благодаря полям `_SYSTEMD_UNIT` и `_COMM` можно моментально сузить круг анализа без разбора регулярными выражениями.

### Конфигурация journald

Файл `/etc/systemd/journald.conf` управляет поведением демона. Основные параметры, важные для специалиста SOC:

```ini
[Journal]
Storage=persistent        # Хранить логи в /var/log/journal
SystemMaxUse=500M         # Максимальный размер на диске
MaxRetentionSec=2week     # Хранить не дольше двух недель
ForwardToSyslog=yes       # Дублировать сообщения в syslog
Compress=yes              # Сжимать большие сообщения (например, core dumps)
```

После изменений требуется перезапуск `systemd-journald.service`. Проверка активных значений выполняется командой:

```bash
systemd-analyze cat-config systemd/journald.conf
```

### Интеграция с rsyslog для централизованного сбора

В SOC часто стоит задача передавать логи с рабочих станций в SIEM. Journald сам по себе не имеет надёжного удалённого транспорта (сервис `systemd-journal-remote` считается экспериментальным), поэтому для передачи используется связка journald → rsyslog → удалённый сервер. Типовой конфигурационный сниппет на стороне клиента:

```bash
# /etc/rsyslog.d/journald-forward.conf
module(load="imjournal")
module(load="omfwd")      # модуль пересылки

# Правило: все сообщения от systemd на центральный сервер
*.* action(
  type="omfwd"
  target="192.168.1.10"
  port="514"
  protocol="tcp"
)
```

Журнал при этом можно оставить volatile (не создавать `/var/log/journal`) или отключить постоянное хранение (`Storage=none`), чтобы дисковое пространство использовалось только rsyslog.

### Экспорт в JSON и взаимодействие с внешними инструментами

Для передачи в SIEM часто используют вывод `journalctl -o json`. В сочетании с утилитой `jq` можно строить сложные запросы:

```bash
journalctl -u ssh.service --since "1 hour ago" -o json | jq 'select(.__REALTIME_TIMESTAMP > "1721560922218814") | {msg: .MESSAGE, pid: ._PID, uid: ._UID}'
```

Также возможно настроить прямую пересылку через `systemd-journal-upload`, но в продакшене чаще применяют rsyslog или специализированные агенты (например, Logagent).

### Сравнение подходов к поиску: grep versus journalctl

Традиционный анализ `/var/log/secure` или `/var/log/auth.log` выглядит как:

```bash
grep "Failed password" /var/log/auth.log | grep "sshd" | awk '{print $1,$2,$3,$11}'
```

Такой способ:
- требует знания формата файла и его ротации,
- чувствителен к изменению формата syslog,
- не даёт точной временной выборки без дополнительных команд,
- не раскрывает контекст (например, идентификатор юнита).

С journalctl эквивалентная операция может выглядеть так:

```bash
journalctl -u ssh.service -p info --since "2025-12-19" | grep "Failed password"
```

Но более точно — использование фильтра по полям (хотя поле с IP всё ещё внутри MESSAGE, поэтому grep неизбежен). Однако сочетание `-u` уже ограничивает записи только ssh, что резко сужает область поиска.

## Сквозной практический пример: расследование инцидента SSH-брутфорса

**Исходные условия**: на сервере Ubuntu 24.04 LTS, входящем в зону мониторинга SOC, сработал алерт SIEM о множественных неудачных попытках аутентификации. Оператор L1 должен провести первичный анализ, используя локальные журналы. Сервер работает под управлением systemd, journald включён в режиме постоянного хранения, также настроена пересылка в rsyslog для долговременного архива в текстовых логах `/var/log/auth.log`. Оператор имеет SSH-доступ с правами sudo.

**Шаг 1. Получить список последних событий, связанных со службой SSH, за последний час.**

```bash
journalctl -u ssh.service --since "1 hour ago"
```

Ожидаемый вывод (фрагмент):

```
Dec 19 10:15:22 srv-lab sshd[1304]: Accepted password for admin from 192.168.100.5 port 52341 ssh2
Dec 19 10:15:45 srv-lab sshd[1304]: Received disconnect from 192.168.100.5 port 52341:11: disconnected by user
Dec 19 10:16:01 srv-lab sshd[1402]: Failed password for invalid user root from 10.20.30.40 port 60222 ssh2
Dec 19 10:16:03 srv-lab sshd[1402]: Failed password for invalid user root from 10.20.30.40 port 60222 ssh2
...
```

**Шаг 2. Детализировать структурированный контекст одной подозрительной записи.**

```bash
journalctl -u ssh.service -o json --since "1 hour ago" | jq 'select(._PID==1402) | {timestamp: .__REALTIME_TIMESTAMP, message: .MESSAGE, pid: ._PID, uid: ._UID, transport: ._TRANSPORT, unit: ._SYSTEMD_UNIT}' | head -5
```

Ожидаемый вывод:

```json
{
  "timestamp": "1734600961881234",
  "message": "Failed password for invalid user root from 10.20.30.40 port 60222 ssh2",
  "pid": "1402",
  "uid": "0",
  "transport": "syslog",
  "unit": "ssh.service"
}
```

Это показывает, что процесс работал от root (обычное поведение sshd), информация пришла через syslog-сокет, и мы сразу видим, что инцидент связан с юнитом `ssh.service`. Таймстемп с микросекундной точностью позволяет коррелировать с сетевыми логами или IDS.

**Шаг 3. Сравнить с традиционным чтением из auth.log.**

```bash
grep "Failed password" /var/log/auth.log | tail -5
```

Вывод:

```
Dec 19 10:16:01 srv-lab sshd[1402]: Failed password for invalid user root from 10.20.30.40 port 60222 ssh2
Dec 19 10:16:03 srv-lab sshd[1402]: Failed password for invalid user root from 10.20.30.40 port 60222 ssh2
...
```

Для получения того же списка атак оператору пришлось бы вручную просматривать весь файл, фильтруя по службе через grep. В случае ротированных файлов потребовалось бы выполнять grep по `auth.log.1`, `auth.log.2.gz` и т.д. Journalctl же прозрачно объединяет все активные и архивные файлы журнала.

**Шаг 4. Выделить уникальные IP-адреса, использовавшиеся при атаке, и посчитать количество попыток.**

```bash
journalctl -u ssh.service -p info --since "1 hour ago" | grep "Failed password" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
```

(Примечание: аналитический обход текста сообщения всё ещё использует awk, но журнал обеспечивает точную фильтрацию по службе и времени.)

**Шаг 5. Проверить период действия: когда началась атака по монотонному времени относительно времени загрузки.**

```bash
journalctl -u ssh.service --since "1 hour ago" -o verbose | grep -E "MESSAGE|__MONOTONIC_TIMESTAMP" | head -10
```

Вывод (иллюстративная схема):

```
MESSAGE=Failed password for invalid user root from 10.20.30.40 port 60222 ssh2
__MONOTONIC_TIMESTAMP=265429588
MESSAGE=Failed password for invalid user root from 10.20.30.40 port 60222 ssh2
__MONOTONIC_TIMESTAMP=265429634
...
```

Монотонные метки позволяют судить о временных интервалах между событиями без влияния перевода часов.

**Ожидаемый вывод**: пример демонстрирует, что использование journald существенно ускоряет первичный триаж инцидента благодаря встроенной фильтрации по юниту и времени, а также предоставляет структурированный контекст (PID, UID, boot ID), который невозможно получить из плоского syslog-файла без дополнительного парсинга. В то же время совместимость с традиционным syslog сохраняется: при необходимости более сложной аналитики или отправки в SIEM журнал может быть экспортирован в JSON или передан через rsyslog.

## Источники

- [Syslog vs. Journald: Understanding Linux Logging Systems](https://www.manageengine.com/products/eventlog/logging-guide/syslog/syslog-vs-journald.html)
- [Understanding Linux Logs: Types & Features | NinjaOne](https://www.ninjaone.com/blog/understanding-linux-logs-overview-with-examples)
- [System Logging: syslog, journald, and logger | Penguin Gym Linux](https://penguin-gym-linux.com/en/articles/lpic/system-logging)
- [Systemd Journal and journalctl – Righteous IT](https://righteousit.com/2024/08/06/systemd-journal-and-journalctl)
- [Logging w/ journald: Why use it & how it performs vs syslog](https://sematext.com/blog/journald-logging-tutorial)
- [Is rsyslog redundant on when using journald? - Server Fault](https://serverfault.com/questions/959982/is-rsyslog-redundant-on-when-using-journald)
- [can any one give me more details about journald and syslog - Stack Overflow](https://stackoverflow.com/questions/69849481/can-any-one-give-me-more-details-about-journald-and-syslog)
- [How is syslog entangled with journald? - Unix & Linux Stack Exchange](https://unix.stackexchange.com/questions/735922/how-is-syslog-entangled-with-journald)
- [Managing Systemd Logs on Linux with Journalctl · Dash0](https://www.dash0.com/guides/systemd-logs-linux-journalctl)
- [Why Journald?](https://www.loggly.com/blog/why-journald)
- [Systemd-journald vs. syslog-ng - Blog - syslog-ng Community](https://www.syslog-ng.com/community/b/blog/posts/systemd-journald-vs-syslog-ng)
# /var/log/auth.log — журнал аутентификации Linux

## 1. Роль и положение auth.log в системе журналирования Linux

`/var/log/auth.log` — основной репозиторий событий аутентификации и авторизации в Debian-подобных дистрибутивах Linux (Ubuntu, Debian, Mint). В RHEL-совместимых ОС (CentOS, AlmaLinux, Rocky) его аналогом выступает `/var/log/secure` [— источник WafaTech](https://wafatech.sa/blog/linux/linux-security/analyzing-pam-logs-strategies-for-monitoring-linux-server-activity). Файл содержит записи, порождаемые Pluggable Authentication Module (PAM), демоном `sshd`, командами `sudo` и `su`, системой управления пользователями (`useradd`, `passwd`), и другими компонентами, требующими проверки подлинности.

Путаница между auth.log и смежными лог-файлами — одна из частых ошибок начинающих администраторов SOC. Ниже приведено сопоставление файлов, с которыми auth.log часто пересекается.

| Файл (Debian) | Аналог (RHEL) | Ключевая роль | Типичные события (в отличии от auth.log) |
|---------------|---------------|---------------|------------------------------------------|
| `/var/log/auth.log` | `/var/log/secure` | Аутентификация и авторизация | Входы/выходы, `sudo`, `su`, создание пользователей, смена паролей |
| `/var/log/syslog` | `/var/log/messages` | Общие системные события | Запуск/остановка служб, ошибки ядра (не‑аутентификационные), сообщения демонов |
| `/var/log/audit/audit.log` | — | Низкоуровневый аудит (системные вызовы) | Доступ к файлам, выполнение команд, изменение прав (если настроено); события, не проходящие через PAM |
| `/var/log/kern.log` | `/var/log/dmesg` | Сообщения ядра | Инициализация модулей, аппаратные исключения, ошибки диска |
| `journalctl -u ssh` | — | Бинарный журнал systemd | SSH-события, дублирующиеся с auth.log, но дополнительно содержат метаданные юнита |

На практике инцидент‑респондер не замыкается только на auth.log: для полной картины он коррелирует его с syslog, auditd‑записями и выводом journalctl [— источник NXLog](https://nxlog.co/news-and-blog/posts/linux-security-logging-with-nxlog-platform). Отличие auth.log в том, что он фокусируется на **пользовательских действиях, требующих проверки учётных данных или прав**, в то время как audit.log может регистрировать обращения к файлам без явной PAM-сессии.

## 2. Внутреннее устройство записей auth.log

Записи auth.log имеют унифицированный формат, унаследованный от syslog, но их содержание сильно зависит от вызвавшего события модуля PAM или сервиса. Стандартная структура строки включает следующие поля, разделённые пробелами:

```text
<timestamp> <hostname> <service>[<PID>]: <PAM-module> <message>
```

- **timestamp** — дата‑время в локальном формате syslog (например, `Feb 10 15:45:14`).
- **hostname** — имя узла, сгенерировавшего запись.
- **service** — демон или утилита, зарегистрировавшая событие (`sshd`, `sudo`, `login`, `cron`), с идентификатором процесса в скобках.
- **PAM-module** — модуль PAM, участвовавший в проверке (`pam_unix`, `pam_tally2`, `pam_rootok` и пр.), либо `sudo`, `su`.
- **message** — текстовое описание события, включающее IP‑адрес, порт, имя пользователя и результат.

Для SOC L1 критически важно уметь разбирать message‑часть, так как именно она содержит IoC (индикаторы компрометации): IP‑адреса, имена учётных записей, статусы ошибок. Ниже приведена таблица типовых событий, извлекаемых из auth.log, с поясняющими полями и примерами индикаторов.

| Тип события | Шаблон message | Ключевые поля для анализа | Примеры индикаторов (иллюстративная схема) |
|-------------|---------------|---------------------------|--------------------------------------------|
| Неудачная парольная аутентификация SSH | `Failed password for <user> from <IP> port <port> ssh2` | `user`, `IP`, `port` | IP источника, частота попыток, несуществующие пользователи (invalid user) |
| Успешный вход по паролю | `Accepted password for <user> from <IP> port <port> ssh2` | `user`, `IP`, `port` | Легитимный IP сотрудника, необычное время или геолокация |
| Успешный вход по ключу | `Accepted publickey for <user> from <IP> port <port> ssh2` | `user`, `IP` | Отсутствие пароля — полезно для детекта утечки ключа |
| Завершение сеанса (отключение) | `Received disconnect from <IP> port <port>: …` / `Disconnected from user <user> <IP> port <port>` | `IP`, `user` | Аномально короткие сессии после успешного входа, частые разъединения |
| Неудача PAM (общая) | `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=<IP>  user=<user>` | `rhost`, `user`, `uid` | PAM-модуль добавляет поля `rhost` (удалённый хост), `user` |
| Использование sudo | `sudo: <user> : TTY=<tty> ; PWD=<dir> ; USER=<target> ; COMMAND=<command>` | `user`, `target`, `COMMAND` | Попытки выполнения подозрительных команд (`/bin/bash`, `rm -rf /`) |
| Использование su | `su[<PID>]: + /dev/<tty> <user>-<target>` или `Authentication failure` | `user`, `target` | Переход в root без оснований |
| Создание/удаление пользователя | `useradd[<PID>]: new user: name=<user>, UID=<uid>…` / `userdel[<PID>]: delete user '<user>'` | `user`, `UID` | Несанкционированное создание привилегированного пользователя |
| Смена пароля | `passwd[<PID>]: password for <user> changed by <actor>` | `user`, `actor` | Изменение пароля root без заявки |

Помимо PAM-событий, auth.log может содержать сообщения от `cron` при выполнении задач от имени конкретного пользователя (`pam_unix(cron:session): session opened for user root by (uid=0)`), а также от `polkit` при запросе привилегий.

Для SOC‑аналитика важно понимать разницу между событиями `Failed password for invalid user admin` и `Failed password for root`: первое — попытка подбора несуществующего аккаунта (типично для широкого сканирования), второе — целенаправленная атака на привилегированную учётную запись. Частота появления `invalid user` в сочетании с большим количеством неудач с одного IP — верный признак брутфорса [— источник BetterStack](https://betterstack.com/community/guides/logging/monitoring-linux-auth-logs).

## 3. Применение и работа с auth.log на практике

Работа с auth.log на позиции SOC L1 складывается из трёх основных направлений: ручной оперативный анализ при расследовании алертов, автоматизированный мониторинг и корреляция.

**Ручной анализ.** Для быстрой оценки обстановки используют стандартные утилиты GNU Coreutils и grep. Ниже приведены базовые команды, которые должен знать каждый аналитик.

Просмотр последних событий в реальном времени (команда остаётся в интерактивном режиме, новые строки добавляются без перезапроса):

```bash
sudo tail -f /var/log/auth.log
```

Поиск всех неудачных попыток SSH с подсчётом строк:

```bash
sudo grep "Failed password" /var/log/auth.log | wc -l
```

Вывод списка IP, с которых пытались зайти, с сортировкой по частоте:

```bash
sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
```

Запись `$(NF-3)` зависит от структуры строки; в ряде дистрибутивов поле IP может располагаться на другом месте, поэтому предпочтительнее использовать `grep -oP` с регулярным выражением:

```bash
sudo grep "Failed password" /var/log/auth.log | grep -oP 'from \K\S+' | sort | uniq -c | sort -nr
```

Такая команда даёт список адресов-лидеров по числу неудач — прямой кандидат на блокировку или дальнейший анализ.

Фильтрация событий только за последний час (учит текущее время):

```bash
sudo grep "$(date --date='1 hour ago' '+%b %e %H:')" /var/log/auth.log | grep -E "(Failed|Invalid)"
```

При расследовании успешных входов полезно вывести сессии с указанием времени и IP:

```bash
sudo grep "Accepted" /var/log/auth.log | awk '{print $1, $2, $3, $4, $9, $11}'
```

**Автоматизированный мониторинг.** Для продакшн-сред набирают популярность как легковесные решения, так и коммерческие SIEM-системы.

- `fail2ban` — анализирует auth.log в режиме реального времени и динамически блокирует IP через iptables/nftables при превышении порога неудачных попыток. Это не столько инструмент SOC, сколько превентивная мера, но он сокращает «шум» в логах, отсеивая массовое сканирование.
- `OSSEC` / `Wazuh` — HIDS-решения, способные разбирать auth.log, генерировать алерты на подозрительные события (например, `sudo` от непривилегированного пользователя) и отправлять их на центральный сервер.
- **Centralized logging** — с помощью `rsyslog` или `syslog-ng` сообщения auth.log пересылаются в центральное хранилище (Graylog, ELK, Splunk). В Splunk, например, можно написать поиск: `index=os sourcetype=linux_secure "Failed password" | stats count by src_ip, user | sort -count`.
- **Скрипты на bash или Python** — базовый скрипт, который каждые 5 минут ищет аномалии (например, более 10 неудач с одного IP) и отправляет письмо администратору. Пример такого скрипта описан в источнике [Аренда-сервер.cloud](https://arenda-server.cloud/blog/kak-monitorit-logi-autentifikacii-v-ubuntu).

**Корреляция с другими источниками.** Для верификации подозрительной активности аналитик сопоставляет auth.log с журналом оболочки (`.bash_history` пользователя), с логами `auditd` (файловые операции) и сетевыми логами (NetFlow). Например, успешный вход по SSH с нестандартного IP сам по себе может быть легитимным, но если одновременно в audit.log фиксируется обращение к `/etc/shadow`, это триггерит эскалацию инцидента.

Важно помнить, что auth.log на диске может ротироваться (`logrotate` обычно настроен на ежедневную или еженедельную замену). Для анализа старых событий нужно просматривать архивированные файлы `/var/log/auth.log.1.gz`, используя `zgrep` или аналогичные инструменты. С 2025 года в некоторых дистрибутивах также используется переход на структурированные бинарные журналы systemd; доступ к тем же событиям возможен через `journalctl -u sshd --since "1 hour ago"`, но формат может отличаться от классического syslog.

## 4. Сквозной практический пример: выявление и документирование попытки брутфорса SSH

**Исходные условия.** Сервер Ubuntu 22.04, роль аналитика SOC L1. Поступил автоматический алерт от системы мониторинга о всплеске неудачных попыток входа. Необходимо оперативно оценить масштаб атаки, идентифицировать источник и зафиксировать индикаторы для последующей блокировки.

### Шаг 1. Первичная оценка — подсчёт неудачных попыток за последние 10 минут

Определяем время начала окна анализа (10 минут назад) и фильтруем auth.log на наличие ошибок.

```bash
SINCE=$(date --date='10 min ago' '+%b %e %H:%M')
sudo grep "$SINCE" /var/log/auth.log | grep -i 'Failed password'
```

**Ожидаемый вывод (фрагмент, иллюстративная схема):**
```text
Dec 15 09:23:45 server sshd[47341]: Failed password for invalid user admin from 172.30.5.12 port 54321 ssh2
Dec 15 09:23:47 server sshd[47341]: Failed password for invalid user root from 172.30.5.12 port 54321 ssh2
Dec 15 09:23:49 server sshd[47341]: Failed password for invalid user test from 172.30.5.12 port 54321 ssh2
Dec 15 09:23:50 server sshd[47342]: Failed password for root from 172.30.5.12 port 54322 ssh2
... (всего 120 записей за 2 минуты)
```

Вывод показывает массовое переборное сканирование с одного IP-адреса.

### Шаг 2. Определение агрессивного источника и перечня атакованных учётных записей

Считаем количество попыток на каждый IP и извлекаем список уникальных имён пользователей.

```bash
# Топ-5 IP по числу неудач
sudo grep "Failed password" /var/log/auth.log | grep -oP 'from \K\S+' | sort | uniq -c | sort -nr | head -5
# Список атакованных аккаунтов (с учётом invalid user)
sudo grep "Failed password" /var/log/auth.log | grep -oP 'for (invalid user )?\K\S+' | sort -u
```

**Ожидаемый вывод (иллюстративная схема):**
```text
   350 172.30.5.12
     2 192.168.1.100
```
```text
admin
root
test
alex
john
```

Становится очевидно, что основной источник — `172.30.5.12`, и он пытается подобрать пароли к широкому спектру учётных записей.

### Шаг 3. Проверка успешных входов с подозрительного IP для исключения компрометации

Обязательно проверяем, не увенчалась ли атака успехом, иначе инцидент переходит в категорию «возможная утечка».

```bash
sudo grep "Accepted" /var/log/auth.log | grep "172.30.5.12"
```

**Ожидаемый вывод:** если строка отсутствует, атака была безуспешной. В противном случае мы бы увидели запись типа:
```text
Dec 15 09:25:10 server sshd[47400]: Accepted password for alex from 172.30.5.12 port 54344 ssh2
```
В нашем кейсе вывод пуст — компрометации не произошло.

### Шаг 4. Фиксация временных рамок атаки и подготовка отчёта

Определяем первую и последнюю запись от атакующего IP:

```bash
sudo grep "sshd.*172.30.5.12" /var/log/auth.log | head -1
sudo grep "sshd.*172.30.5.12" /var/log/auth.log | tail -1
```

**Ожидаемый вывод:**
```text
Dec 15 09:23:42 server sshd[47340]: Connection from 172.30.5.12 port 54320 on 192.168.1.10 port 22 rdomain ""
Dec 15 09:27:33 server sshd[47395]: Connection closed by 172.30.5.12 port 54501 [preauth]
```

Интервал активности: ~4 минуты. В отчёте фиксируем:

- Источник: 172.30.5.12 (внешний или внутренний — зависит от среды).
- Тип атаки: dictionary brute‑force с перебором несуществующих пользователей.
- Затронутые учётные записи: admin, root, test, alex, john.
- Успешных входов: 0.
- Рекомендация: внести IP в бан-лист, проверить настройку fail2ban, уведомить администратора безопасности.

**Ожидаемый вывод по примеру:** демонстрируется полный цикл анализа auth.log — от обнаружения до документирования, с чёткой привязкой к командам и структуре записей.

## Источники

- [Analyzing PAM Logs: Strategies for Monitoring Linux Server Activity - WafaTech Blogs](https://wafatech.sa/blog/linux/linux-security/analyzing-pam-logs-strategies-for-monitoring-linux-server-activity)
- [Linux Security Logs: Complete Guide for DevOps and SysAdmins - Last9](https://last9.io/blog/linux-security-logs)
- [AuthLogParser: Open-source tool for analyzing Linux authentication logs - Help Net Security](https://www.helpnetsecurity.com/2024/01/08/authlogparser-open-source-analyzing-linux-authentication-logs)
- [Как мониторить логи аутентификации в Ubuntu - Советы от СисАдмина Линукс](https://arenda-server.cloud/blog/kak-monitorit-logi-autentifikacii-v-ubuntu)
- [Monitoring Linux Authentication Logs: A Practical Guide - Better Stack Community](https://betterstack.com/community/guides/logging/monitoring-linux-auth-logs)
- [Understanding Log Management and Analysis Tools for Linux - LinuxSecurity.com](https://linuxsecurity.com/features/linux-log-analysis)
- [Identify Unusual Login Activities in Linux Using Log Analysis](https://linuxsecurity.com/howtos/secure-my-network/understand-failed-authentication-patterns-linux-logs)
- [Both Audit and Auth Logs - Medium](https://medium.com/@iramjack8/both-audit-and-auth-logs-4a1d479c3325)
- [Linux security monitoring with NXLog Platform - NXLog Blog](https://nxlog.co/news-and-blog/posts/linux-security-logging-with-nxlog-platform)
- [Как защитить Linux-сервер: чеклист базовой безопасности - Statuser](https://statuser.cloud/blog/kak-zashhitit-linux-server-cheklist-bazovoj-bezopasnosti)
- [Detecting Unauthorized Access With Linux Security Logs - Liberty Center One](https://www.libertycenterone.com/blog/linux-security-logs)
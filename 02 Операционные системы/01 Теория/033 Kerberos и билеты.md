# Kerberos и билеты в Windows: протокол, типы билетов и обнаружение атак

## 1. Протокол Kerberos и классификация билетов в Active Directory

Kerberos — сетевой протокол аутентификации, построенный на доверенной третьей стороне – центре распределения ключей (KDC). В доменах Microsoft Active Directory роль KDC выполняет каждый контроллер домена, начиная с Windows 2000. Протокол обеспечивает взаимную аутентификацию, защиту от повторного воспроизведения и делегирование учётных данных, а также исключает передачу пароля по сети после начального входа пользователя. [Microsoft Learn: Kerberos authentication overview] [Introduction to Microsoft Entra Kerberos]

Основу Kerberos составляет система билетов (tickets). Пользователь не предъявляет пароль каждому сервису; вместо этого он получает временные криптографические токены, доказывающие его личность перед конкретной службой. Этот подход реализуется через два ключевых типа билетов: **TGT (Ticket-Granting Ticket)** и **сервисный билет** (Service Ticket, иногда называемый TGS-билетом). [Stanford UIT: How Kerberos Works] [Ticket-Granting Tickets - Win32 apps]

В инфраструктуре Active Directory используется версия 5 протокола Kerberos с рядом проприетарных расширений Microsoft (KILE), добавляющих, среди прочего, проверку привилегий через **PAC (Privilege Attribute Certificate)**. [4768(S,F) A Kerberos authentication ticket (TGT) was requested.] PAC встраивается в билеты и содержит идентификатор безопасности пользователя (SID), членство в группах и другую авторизационную информацию. Именно манипуляция с PAC лежит в основе таких атак, как Golden Ticket и MS14-068.

В отличие от устаревшего протокола NTLM, Kerberos обеспечивает взаимную аутентификацию, невосприимчив к relay-атакам (при корректной настройке) и не требует от сервера обращаться к контроллеру домена для каждой аутентификации. [The Kerberos Authentication Process in Windows Environments] В современных версиях Windows 11 и Windows Server 2025 NTLM постепенно выводится из эксплуатации, делая Kerberos де-факто единственным протоколом аутентификации в домене. [Там же]

Типы билетов и их назначение представлены в таблице:

| Элемент | Назначение | Ключ шифрования | Типичное время жизни | Участник, выдающий билет |
|---------|------------|-----------------|----------------------|---------------------------|
| TGT (Ticket-Granting Ticket) | Удостоверяет факт аутентификации пользователя; предъявляется TGS для получения сервисных билетов | Зашифрован на хеш пароля учётной записи **krbtgt** (мастер-ключ KDC) | По умолчанию 10 часов (настраивается политикой) | Authentication Service (AS) |
| Service Ticket (TGS Ticket) | Даёт доступ к конкретному сервису (файловому серверу, веб-серверу и т.п.) | Зашифрован на хеш пароля **целевой учётной записи службы** | По умолчанию 10 часов (может быть продлён) | Ticket Granting Service (TGS) |
| Облачный TGT (Cloud TGT) | Используется в Microsoft Entra Kerberos для доступа к облачным ресурсам Kerberos | Выдаётся Entra ID, работающим как KDC для области `KERBEROS.MICROSOFTONLINE.COM` | Ограничен сроком действия PRT и политиками Entra | Microsoft Entra ID (облачный KDC) |

Разница между TGT и сервисным билетом фундаментальна: TGT является «удостоверением личности» на всю сессию, а сервисный билет — «разовым пропуском» к отдельному ресурсу. Компрометация krbtgt-хеша позволяет атакующему фабриковать TGT с произвольными пользователями и правами (Golden Ticket), а компрометация хеша сервисной учётной записи — подделывать сервисные билеты (Silver Ticket). [Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket) Use in Active Directory]

## 2. Процесс аутентификации и внутренняя структура билетов

Аутентификация Kerberos в Windows состоит из трёх парных обменов: AS Exchange (клиент–AS), TGS Exchange (клиент–TGS) и AP Exchange (клиент–сервер приложений). Каждая фаза использует различные симметричные ключи, предотвращая раскрытие долговременного пароля пользователя. [How Kerberos Works | University IT] [The Kerberos Authentication Process in Windows Environments]

На следующей ASCII-схеме показаны участники и сообщения:

```text
[Клиент]                                  [KDC (AS + TGS)]                            [Сервер приложений]
   |                                                |                                         |
   |---(1) AS-REQ (шифр. временная метка)---------->|                                         |
   |                                                |--- проверка пароля, извлечение ключей   |
   |<--(2) AS-REP (TGT + сеансовый ключ)-----------|                                         |
   |                                                |                                         |
   |---(3) TGS-REQ (TGT + аутентификатор + SPN)---->|                                         |
   |                                                |--- проверка TGT, создание сервисного   |
   |                                                |    билета (ST)                          |
   |<--(4) TGS-REP (ST + новый сеансовый ключ)-----|                                         |
   |                                                                                         |
   |---(5) AP-REQ (ST + аутентификатор)----------------------------------------------------->|
   |                                                                   проверка билета       |
   |<--(6) AP-REP (при необходимости взаимная аутентификация)---------------------------------|
```

**Фаза 1: AS-REQ / AS-REP**  
Клиент шифрует текущую временную метку хешем своего пароля (NT-Hash) и отправляет на AS контроллера домена. AS расшифровывает пакет тем же хешем, хранящимся в Active Directory, и убеждается, что пароль верен. Затем AS генерирует сеансовый ключ «клиент-TGS» и TGT. TGT шифруется мастер-ключом KDC – хешем учётной записи **krbtgt**. Сеансовый ключ и TGT возвращаются клиенту в AS-REP. Клиент, обладая хешем своего пароля, способен извлечь сеансовый ключ, но не может прочитать содержимое TGT. [Ticket-Granting Tickets - Win32 apps] [Detecting Forged Kerberos Ticket]

**Фаза 2: TGS-REQ / TGS-REP**  
Когда клиенту нужен доступ к сервису, он формирует TGS-REQ: предъявляет TGT (который сам не читает), аутентификатор (свежая временная метка, зашифрованная сеансовым ключом «клиент-TGS») и запрашиваемый Service Principal Name (SPN), например `cifs/server01.domain.com`. TGS открывает TGT с помощью ключа krbtgt, извлекает сеансовый ключ и идентификационные данные пользователя (включая PAC). Проверив аутентификатор, TGS генерирует сервисный билет (Service Ticket), зашифрованный на хеш пароля целевой учётной записи (например, хеш компьютера `server01$`), и новый сеансовый ключ «клиент-сервер», который шифруется старым сеансовым ключом. Оба отправляются клиенту в TGS-REP. [The Kerberos Authentication Process in Windows Environments] [Research: Windows Authentication Series (Part2. Kerberos)]

**Фаза 3: AP-REQ / AP-REP**  
Клиент передаёт целевому серверу сервисный билет и аутентификатор, зашифрованный новым сеансовым ключом. Сервер расшифровывает билет своим хешем, извлекает сеансовый ключ и PAC, проверяет подпись и временную метку. Если всё верно – доступ разрешён. При необходимости сервер может ответить AP-REP для взаимной аутентификации (например, при жёсткой политике UNC Hardening). [Там же]

**Структура билета Kerberos**  
Билет содержит зашифрованную серверную часть и открытую клиентскую часть. Иллюстративная JSON-схема полей серверной части билета (на основе описания KILE):

```json
{
  "ticket": {
    "tkt_vno": 5,
    "realm": "DOMAIN.LOCAL",
    "sname": {"name_type": 1, "name_string": ["cifs", "server01.domain.local"]},
    "enc_part": {
      "etype": 18,  // e.g. AES256-CTS-HMAC-SHA1-96
      "kvno": 2,
      "cipher": "<зашифрованные данные>"
    }
  },
  "encrypted_part_plaintext": {
    "flags": 0x40810010,       // битовая маска флагов (forwardable, renewable, initial...)
    "key": "<сеансовый ключ>",
    "crealm": "DOMAIN.LOCAL",
    "cname": {"name_type": 1, "name_string": ["username"]},
    "authtime": "2025-03-01T08:30:00Z",
    "starttime": "2025-03-01T08:30:00Z",
    "endtime": "2025-03-01T18:30:00Z",
    "renew_till": "2025-03-08T08:30:00Z",
    "authorization_data": [
      {
        "ad_type": 128,         // PAC
        "ad_data": "<PAC-структура: SID, группы, подписи сервера и KDC>"
      }
    ]
  }
}
```

Поле `flags` кодирует свойства билета. Наиболее значимые флаги, определённые в RFC 4120 и расширенные Microsoft, перечислены в таблице (выборочно, на основе данных из [4768(S,F) A Kerberos authentication ticket (TGT) was requested] и [Ticket-Granting Tickets - Win32 apps]):

| Флаг (бит) | Название | Значение |
|------------|----------|----------|
| 0x00000010 | `forwardable` | TGT может быть переадресован (делегирование) |
| 0x00000020 | `forwarded` | Билет был получен в результате переадресации |
| 0x00000040 | `proxiable` | Билет можно использовать как прокси-билет |
| 0x00000080 | `proxy` | Билет является прокси |
| 0x00100000 | `renewable` | Билет может быть продлён без повторной аутентификации |
| 0x00400000 | `initial` | Билет выдан AS-службой (признак TGT) |
| 0x00800000 | `pre_authent` | Клиент успешно прошёл предварительную аутентификацию |
| 0x01000000 | `hw_authenticated` | Аппаратная аутентификация (например, смарт-карта) |

В нормальных условиях TGT, выданный после входа с паролем, имеет флаги `forwardable`, `proxiable`, `renewable`, `initial` и `pre_authent` (см. следующий раздел для детектирования аномалий). Билеты, созданные атакующим (Golden Ticket), часто имеют нестандартные или неполные наборы флагов.

Особо важной частью билетов является **PAC (Privilege Attribute Certificate)** – структура, подписанная ключами целевого сервера и KDC. PAC содержит SID пользователя, членство в группах и в современных версиях — данные для проверки целостности (PAC Requestor, PAC Attributes). Атака MS14-068 позволяла подделать подпись PAC, вынуждая KDC выдать TGT с повышенными привилегиями. Современные защищённые PAC (с проверкой подписей) внедрены начиная с обновлений безопасности 2014 года. [Detecting Forged Kerberos Ticket]

## 3. Работа с билетами и практический мониторинг для SOC L1

В повседневной работе SOC-аналитику первого уровня требуется понимание как нормального поведения Kerberos, так и признаков компрометации, связанных с поддельными билетами. В Windows работа с билетами осуществляется через командную утилиту `klist`, а аудит событий Kerberos обеспечивается политикой аудита входа/выхода и Kerberos-службы.

Основные команды `klist`:

- `klist tgt` – показать все TGT в текущем сеансе.
- `klist tickets` – показать все кешированные билеты (как TGT, так и сервисные).
- `klist purge` – очистить кэш билетов (требуется при устранении залипших сессий, но не для удаления следов компрометации; вредоносные программы часто очищают билеты).

Пример вывода `klist tgt` на рабочей станции доменного пользователя:

```powershell
PS C:\> klist tgt

Current LogonId is 0:0x1a3b4

Cached Tickets: (1)

#0>     Client: user1 @ DOMAIN.LOCAL
        Server: krbtgt/DOMAIN.LOCAL @ DOMAIN.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 3/1/2025 8:30:11 (local)
        End Time:   3/1/2025 18:30:11 (local)
        Renew Time: 3/8/2025 8:30:11 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
```

(Значения флагов и времени приведены для иллюстрации нормального билета.)

SOC-аналитик должен знать, какие события аудита генерируются при операциях с билетами. Основными являются:

- **4768**: запрос TGT (AS-REQ). Содержит имя учётной записи, источник (IP), тип шифрования, result code (0x0 – успех, иные коды означают ошибки), а также Ticket Options (флаги запрошенного билета). [4768(S,F) A Kerberos authentication ticket (TGT) was requested.]
- **4769**: запрос сервисного билета (TGS-REQ). Фиксирует имя запрошенной службы (SPN), учётную запись, IP-клиента, тип шифрования билета, Time Skew.
- **4770**: обновление (renew) TGT – важный индикатор долгоживущих сессий.
- **4771**: неудачная предварительная аутентификация (аналог неправильного пароля в Kerberos).

Аналитик может извлечь эти события с помощью PowerShell. Например, для выборки недавних запросов TGT:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} -MaxEvents 20 |
    Select-Object TimeCreated,
        @{n='Account';e={$_.Properties[0].Value}},
        @{n='ClientAddress';e={$_.Properties[6].Value}},
        @{n='TicketOptions';e={('0x{0:X}' -f $_.Properties[11].Value)}},
        @{n='ResultCode';e={('0x{0:X}' -f $_.Properties[10].Value)}}
```

(Иллюстративная команда; вывод зависит от окружения.)

**Обнаружение поддельных билетов (Golden Ticket / Silver Ticket)**  
Исследования Sean Metcalf (ADSecurity.org) и других экспертов выявили ряд аномалий в событиях, характерных для использования поддельных билетов, сгенерированных утилитами типа Mimikatz. До обновления Mimikatz в январе 2016 года доменное поле в билете часто содержало статическую строку “eo.oe”. После исправления Mimikatz начал корректно заполнять NetBIOS-имя домена, что усложнило детектирование. Однако остались другие индикаторы: [Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket)]

- **Ticket Options (флаги билета) в событии 4768:** нормальные запросы TGT обычно включают флаги `forwardable`, `renewable`, `initial`, `pre_authent`. У билетов, созданных атакующим без предварительной аутентификации, часто бит `pre_authent` (0x00800000) отсутствует, а могут быть добавлены нестандартные комбинации, например, `0x40810010` (включает `hw_authenticated` без наличия смарт-карты). Сравнение с легитимными билетами пользователя позволяет выявить расхождение.
- **Время жизни билета:** инструментарий Golden Ticket часто устанавливает срок действия TGT на 10 лет (например, `End Time` далеко за пределами политики домена по умолчанию – 10 часов). Появление события с временем жизни > 10 часов (особенно в случае привилегированных учётных записей) должно насторожить.
- **Учётная запись krbtgt в запросах TGT:** событие 4768 для учётной записи `krbtgt` (если не используется делегирование) почти всегда аномально – Golden Ticket может генерироваться под этим именем.
- **Несоответствие типов шифрования:** современные домены предпочитают AES. Появление билетов, зашифрованных RC4-HMAC (тип 23) для учётных записей, которые обычно используют AES, может указывать на атаку, хотя само по себе не является строгим признаком.
- **Аномалии в событии 4769:** поддельные сервисные билеты могут иметь необычные SPN (например, отсутствие точки в имени хоста) или нестандартные значения поля `Ticket Encryption Type` (например, 0x0 – неизвестный). Также может наблюдаться отсутствие предшествующего TGT-запроса в логах.

Для автоматизации поиска такие проверки обычно формализуются в SIEM-правилах (например, в формате Sigma). SOC L1, получив алерт, должен уметь сопоставить данные события с контекстом: откуда пришёл запрос (IP), какой пользователь, совпадает ли время с рабочими часами. При подозрении на Golden Ticket необходимо эскалировать инцидент на уровень L2 для подтверждения и изоляции.

Полезной практикой является периодический аудит хешей krbtgt и политик жизненного цикла билетов (настройка MaxTicketAge, MaxServiceTicketAge). Сброс пароля krbtgt дважды (с интервалом) — признанная контрмера при компрометации домена, так как старые TGT, подписанные старым хешем, становятся недействительными.

## 4. Сквозной практический пример: обнаружение аномального TGT (Golden Ticket)

**Исходные условия:**  
SOC-аналитик L1 получает тикет от SIEM‑системы о подозрительном входе в систему сервера DC01 под учётной записью администратора домена с неизвестной рабочей станции. Рабочий инструментарий аналитика: консоль PowerShell с правами чтения журналов безопасности на контроллере домена, знание нормальных профилей пользователей. Необходимо проверить, не использованы ли поддельные билеты Kerberos.

**Шаг 1: Поиск событий запроса TGT (4768) для учётной записи Administrator за последний час**

Выполняется команда на контроллере домена или через удалённый сеанс с доступом к журналу безопасности:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768; StartTime=(Get-Date).AddHours(-1)} |
    Where-Object { $_.Properties[0].Value -eq 'Administrator' } |
    Select-Object TimeCreated,
        @{n='ClientIP';e={$_.Properties[6].Value}},
        @{n='TicketOptions';e={'0x{0:X}' -f $_.Properties[11].Value}},
        @{n='ResultCode';e={'0x{0:X}' -f $_.Properties[10].Value}},
        @{n='EncryptionType';e={$_.Properties[16].Value}}
```

Вывод (иллюстративный):

```text
TimeCreated          ClientIP       TicketOptions ResultCode EncryptionType
-----------          --------       ------------- ---------- --------------
01.03.2025 15:10:05  10.20.30.101   0x40810010    0x0        0x17 (RC4-HMAC)
01.03.2025 14:55:22  10.20.30.101   0x40810010    0x0        0x17
```

**Шаг 2: Анализ флагов билета (TicketOptions)**  
Значение `0x40810010` необычно для нормального входа с паролем. Ожидаемые флаги для обычного интерактивного входа: `0x40e10000` (forwardable, renewable, initial, pre_authent). Здесь отсутствует бит `pre_authent` (0x00800000) и присутствуют биты `hw_authenticated` (0x01000000) и `name_canonicalize` (0x00010000). Это характерно для Golden Ticket, созданного без предварительной аутентификации и эмулирующего аутентификацию смарт-карты. [Detecting Forged Kerberos Ticket]

**Шаг 3: Проверка времени жизни TGT**  
Дополнительно аналитик смотрит время жизни билета, извлекая данные из события 4768 (поля не включены в вывод, но можно дополнить скрипт). Если End Time превышает типовые 10 часов (например, разница — 10 лет), это ещё один сильный признак.

Команда для извлечения времени окончания билета:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768; StartTime=(Get-Date).AddHours(-1)} |
    Where-Object { $_.Properties[0].Value -eq 'Administrator' } |
    ForEach-Object {
        $endTime = $_.Properties[9].Value  # поле EndTime (индексы могут варьироваться)
        $lifetime = (Get-Date $endTime) - (Get-Date)
        [PSCustomObject] @{
            Time = $_.TimeCreated
            EndTime = $endTime
            LifetimeHours = [math]::Round($lifetime.TotalHours,1)
        }
    }
```

Пример аномального результата:

```text
Time                EndTime                 LifetimeHours
----                -------                 -------------
01.03.2025 15:10:05 01.03.2035 15:10:05     87600
```

(87600 часов = 10 лет). Такие данные однозначно указывают на ручное создание билета инструментом Golden Ticket.

**Шаг 4: Сравнение с нормальным билетом того же пользователя**  
Аналитик находит легитимный более ранний вход с рабочей станции администратора (например, в 8:30 утра) и видит нормальные флаги (`0x40e10000`) и время жизни 10 часов. Это подтверждает аномалию.

**Ожидаемый вывод**  
Совокупность признаков (нестандартные флаги, аномальное время жизни, отсутствие предварительной аутентификации) подтверждает предположение об использовании поддельного TGT, вероятно, сгенерированного злоумышленником с помощью Golden Ticket после компрометации хеша krbtgt. Аналитик эскалирует инцидент, передавая собранные артефакты команде реагирования, и предпринимает немедленные меры: изоляция затронутой учётной записи, изменение пароля krbtgt (дважды) и дальнейшее расследование вектора первоначального проникновения.

## Источники

- [Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket) Use in Active Directory – Active Directory & Azure AD/Entra ID Security](https://adsecurity.org?p=1515)
- [The Kerberos Authentication Process in Windows Environments - Cherry Security](https://cherry-security.com/the-kerberos-authentication-process-in-windows-environments)
- [Introduction to Microsoft Entra Kerberos](https://learn.microsoft.com/en-us/entra/identity/authentication/kerberos)
- [Kerberos Explained - Security - Spiceworks Community](https://community.spiceworks.com/t/kerberos-explained/940539)
- [How Kerberos Works | University IT](https://uit.stanford.edu/service/kerberos/user_guide/how)
- [Ticket and Authentication in Kerberos Active Directory](https://calcomsoftware.com/kerberos-tickets-and-authentication-in-active-directory)
- [What is Ticket Granting Tickets (TGT)/ - Security Wiki](https://doubleoctopus.com/security-wiki/authentication/ticket-granting-tickets)
- [[Research] Windows Authentication Series (Part2. Kerberos)(EN) - hackyboiz](https://hackyboiz.github.io/2025/04/21/mungsul/NTLM_Part2/en)
- [4768(S, F) A Kerberos authentication ticket (TGT) was requested.](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Ticket-Granting Tickets - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-tickets)
- [Общие сведения о Microsoft Entra Kerberos - Microsoft Entra ID | Microsoft Learn](https://learn.microsoft.com/ru-ru/entra/identity/authentication/kerberos)
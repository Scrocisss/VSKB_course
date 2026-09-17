# Ошибки конфигурации и неправильные права в облаке (IaaS/PaaS/SaaS)

## Контекст и базовые понятия: миссконфигурации и права доступа в облачных моделях

**Облачная миссконфигурация** — любое отклонение настроек облачного ресурса от рекомендованных производителем или внутренними политиками параметров безопасности, которое создаёт неконтролируемый вектор для атаки. Она не является уязвимостью программного кода — это ошибка человека или процесса, вызванная неполным пониманием модели общей ответственности, сложностью динамической облачной среды либо отсутствием автоматизированного контроля. По данным Cloud Security Alliance, свыше 90% инцидентов безопасности облака связаны с миссконфигурациями, а не с эксплуатацией уязвимостей платформы.

Неправильные права доступа — один из наиболее критичных и распространённых видов миссконфигурации. Они включают в себя избыточные полномочия учётных записей, ролей или сервисных принципалов; отсутствие многофакторной аутентификации (MFA) для привилегированных субъектов; использование ключей доступа, встроенных в код или общедоступные репозитории; а также неконтролируемое расширение привилегий за счёт цепочек допусков.

Ключевое разграничение: **мисконфигурация** охватывает любую некорректную настройку (сеть, хранилище, логирование, шифрование), тогда как **неправильные права** — частный, но самый высокорисковый случай, фокусирующийся на идентификации и авторизации. В облачных средах IaaS, PaaS и SaaS проявления этих ошибок различны, поскольку потребитель контролирует разные уровни стека. Сравнительная таблица ответственности позволяет точнее идентифицировать, где именно искать проблемы.

| Модель | За что отвечает облачный провайдер | За что отвечает потребитель |
|--------|------------------------------------|-----------------------------|
| IaaS   | Физическая безопасность ЦОД, гипервизор, сетевая инфраструктура, базовые сервисы хранения | ОС, приложения, конфигурация виртуальных сетей (Security Groups, VPC), IAM-политики, шифрование данных, управление ключами, логирование, антивирусная защита |
| PaaS   | Всё вышеперечисленное + среда исполнения, middleware, обновления платформы, ORM-сервисы | Конфигурация приложений и сервисов, управление доступом к платформе, настройка разрешений API, интеграционные ключи, безопасность загружаемого кода |
| SaaS   | Полностью инфраструктура, прикладной код, базовая конфигурация безопасности (шифрование на стороне провайдера) | Управление пользователями, ролями, правами доступа к данным, настройки общих ресурсов, мониторинг активности пользователей, контроль интеграций с внешними сервисами, соблюдение внутренних политик шаринга |

ASCII-схема иллюстрирует распределение границ ответственности в типовой IaaS-среде:

```text
[Физический ЦОД]         ───── провайдер
[Гипервизор / Хост]      ───── провайдер
[Виртуальная машина]     ───── потребитель: ОС, патчи, конфигурации
[Приложения и данные]    ───── потребитель: код, IAM, шифрование, сетевые ACL
```

Исследование [Sysdig](https://www.sysdig.com/blog/top-cloud-misconfigurations) подчёркивает, что облачные миссконфигурации являются следствием человеческого фактора и недостатка процессов. Они создают «возможностные» векторы атак — злоумышленнику не требуется сложный эксплоит, достаточно найти открытую точку входа. Поэтому первостепенная задача SOC L1 — распознавать типовые паттерны таких ошибок и инициировать их устранение.

## Внутреннее устройство: классификация ошибок конфигурации и избыточных прав в IaaS/PaaS/SaaS

Этот раздел даёт полный обзор ключевых классов облачных миссконфигураций, обязательный для специалиста по кибербезопасности. По характеру нарушаемого компонента выделяют категории, перечисленные в таблице ниже. Каждая категория включает как общие конфигурационные просчёты, так и те, что прямо связаны с управлением правами.

| Категория | Типичные ошибки | Индикаторы (логи, атрибуты) | Модель |
|-----------|-----------------|-----------------------------|--------|
| **Хранилище объектов** (S3, Blob Storage, GCS) | Публичный доступ на чтение/запись; отсутствие шифрования на стороне сервера; отключённое версионирование; отсутствие блокировки публичного доступа на уровне аккаунта | CloudTrail: `GetBucketAcl`, `PutBucketAcl` с `AllUsers`; AWS Config: `s3-bucket-public-read-prohibited` | IaaS |
| **Сетевые настройки** | Security Group с `0.0.0.0/0` для портов 22, 3389, всех портов; отсутствие Network ACL; слабая сегментация VPC; прямое подключение VM к публичному IP без межсетевого экрана | VPC Flow Logs: REJECT-пакеты от внешних IP к внутренним портам; Config: `vpc-sg-open-only-to-authorized-ports` | IaaS |
| **IAM и управление доступом** | Административные привилегии у непривилегированных ролей; отсутствие MFA для root и пользователей с консольным доступом; неиспользуемые ключи доступа старше 90 дней; парольные политики без требований сложности; роли с доверием внешним аккаунтам без условия ExternalId | CloudTrail: `CreateAccessKey`, `AttachRolePolicy`; IAM Access Analyzer: небезопасные внешние доверия | IaaS / PaaS |
| **Ключи и секреты API** | Вшитые в код приложений или CI/CD пайплайнов токены; отсутствие ротации ключей; использование долгоживущих статических ключей вместо временных ролевых (STS) | Лямбда-журналы с исключениями `AccessDenied`; GitHub-сканеры секретов; GuardDuty: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | PaaS / IaaS |
| **Логирование и мониторинг** | Отключённый CloudTrail в отдельных регионах; отсутствие логирования операций с данными (S3 Data Events); не настроен AWS Config; логи не реплицируются в центральный SIEM | Config: `cloud-trail-cloud-watch-logs-enabled`; отсутствие событий в ожидаемых временных окнах | Все модели |
| **Шифрование и защита данных** | Незашифрованные EBS/снепшоты; бакеты S3 без серверного шифрования; передача данных по HTTP вместо HTTPS внутри VPC; отсутствие HSM или KMS для управления ключами | Config: `encrypted-volumes`, `s3-bucket-server-side-encryption-enabled`; CloudTrail: вызовы без использования ключей KMS | IaaS / PaaS |
| **SaaS-приложения** | Общие ссылки с правами «Любой, у кого есть ссылка» на документы с конфиденциальными данными; избыточные разрешения OAuth-приложений; неотозванные гостевые учётные записи бывших сотрудников или подрядчиков | Логи провайдера: события шаринга; Azure AD: приложения с высокими разрешениями; SaaS Security Posture Management-алерты | SaaS |
| **Контейнерные и Kubernetes-среды** | Запуск контейнеров с привилегированным режимом; анонимный доступ к kube-apiserver; отсутствие NetworkPolicy; секреты в переменных окружения пода; Docker-сокет, смонтированный в контейнер | Falco: правила `Contact k8s API server from container`; kube-audit: `pods/exec` с аномальными субъектами | PaaS / CaaS |

Особого внимания заслуживает подкласс **неправильных прав**. Его корень — нарушение принципа наименьших привилегий. Типичные сценарии:
- «Дикие» (`wildcard`) разрешения: `Action: "*"`, `Resource: "*"` в политиках IAM, дающие субъекту полный контроль над всеми ресурсами.
- Отсутствие условий в доверительных отношениях ролей: роль, доверяющая внешнему AWS-аккаунту, без условия `sts:ExternalId` позволяет любому пользователю того аккаунта выполнять `AssumeRole`.
- Прикрепление управляемых политик `AdministratorAccess` к машинным ролям (EC2, Lambda), что при компрометации инстанса даёт злоумышленнику полный доступ.
- Делегирование прав без ограничения на передачу: пользователь с `iam:PassRole` и `ec2:RunInstances` может присвоить EC2-инстансу административную роль и затем получить её учётные данные через метаданные.

В PaaS-моделях, например Azure App Service, избыточные права на уровне Managed Identity позволяют приложению взаимодействовать с Key Vault или базами данных без необходимости, а в SaaS — глобальное разрешение OAuth-приложения на чтение почты всех пользователей (Microsoft Graph API) создаёт риск массовой утечки при компрометации токена.

## Применение и работа: детектирование, предотвращение и устранение облачных миссконфигураций

В SOC практическая работа с облачными миссконфигурациями начинается с приёма входящих алертов от средств posture-менеджмента (CSPM) и систем детекции угроз (CloudTrail, GuardDuty, Azure Defender). Аналитик L1 должен за короткое время определить реальный риск и эскалировать или закрыть инцидент.

**Инструментальные подходы.** Основными средствами автоматического выявления служат CSPM-решения (AWS Config, Azure Policy, GCP Security Command Center, а также сторонние — Sysdig, Wiz, Prisma Cloud). Они непрерывно оценивают конфигурации на соответствие индустриальным бенчмаркам (CIS, NIST) и генерируют находки. Для управления избыточными правами применяются CIEM-инструменты (Cloud Infrastructure Entitlement Management), которые анализируют фактически используемые разрешения и предлагают профили Least Privilege.

Однако аналитик не должен полагаться исключительно на пассивные дашборды. Прямой запрос к API провайдера позволяет верифицировать состояние ресурса. Ниже приведены практические команды для AWS, иллюстрирующие детектирование двух наиболее частых проблем.

**Поиск публичных S3-бакетов.**

```bash
# Получение списка бакетов
aws s3api list-buckets --query "Buckets[].Name" --output text
# Для каждого бакета проверить статус публичного доступа (на уровне аккаунта может быть ограничение)
aws s3api get-bucket-acl --bucket <bucket-name> \
    --query "Grants[?Grantee.URI=='http://acs.amazonaws.com/groups/global/AllUsers']" \
    --output table
```

Вывод в таблице сразу показывает наличие разрешений `READ`, `WRITE` для группы всех пользователей. Дополнительно через `get-public-access-block` проверяется блокировка публичного доступа на уровне бакета и аккаунта.

**Анализ избыточных IAM-политик.**

```bash
# Список присоединённых локальных и управляемых политик для роли <role-name>
aws iam list-attached-role-policies --role-name <role-name>
aws iam list-role-policies --role-name <role-name>

# Детализация конкретной политики
aws iam get-policy-version \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
    --version-id v1
```

Находка `AdministratorAccess` у роли, присвоенной веб-серверу, — немедленный повод для инцидента. Аналитик также должен проверить неиспользуемые разрешения через IAM Access Analyzer или сервис IAM Credential Report (`generate-credential-report` и `get-credential-report`). В отчёте видны даты последнего использования ключей; ключи старше 90 дней без активности требуют деактивации.

**Типичный фрагмент лога CloudTrail**, соответствующий публичному открытию бакета (иллюстративная схема):

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAXXXXXXXXXXXXXXXX",
    "arn": "arn:aws:iam::123456789012:user/admin",
    "accountId": "123456789012"
  },
  "eventTime": "2026-02-10T14:30:00Z",
  "eventName": "PutBucketAcl",
  "sourceIPAddress": "203.0.113.42",
  "requestParameters": {
    "AccessControlPolicy": {
      "AccessControlList": {
        "Grant": [
          {
            "Grantee": {
              "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
              "Type": "Group"
            },
            "Permission": "READ"
          }
        ]
      }
    }
  },
  "additionalEventData": {
    "SignatureVersion": "SigV4"
  }
}
```

На его основе можно построить правило детекции. Например, в Sigma-стиле:

```yaml
title: S3 Bucket Made Public via ACL
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: PutBucketAcl
    requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI:
      - 'http://acs.amazonaws.com/groups/global/AllUsers'
      - 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
  condition: selection
```

Аналитик, получивший такой алерт, идентифицирует пользователя, время и источник. Далее проверяется легитимность действия: совпадает ли запрос с заявкой на изменение (Change Request), присутствует ли в утверждённом окне обслуживания. Если нет — стартует процедура реагирования.

**SaaS-контекст.** Для приложений вроде Office 365 или Google Workspace типовой задачей становится выявление неконтролируемого раскрытия данных. Пример: в журнале аудита Microsoft 365 Unified Audit Log операция `Share` может содержать детали типа `SharingLinkType: 'AnonymousEdit'`. SOC L1 через PowerShell-командлет `Search-UnifiedAuditLog` формирует выборку таких событий за последние сутки и оценивает масштаб утечки.

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) `
    -Operations "SharingSet","AnonymousLinkCreated" `
    -ResultSize 1000 | Format-Table CreationDate,UserIds,Operations,AuditData
```

Практические ошибки аналитиков: игнорирование контекста ресурса — публичный бакет может преднамеренно использоваться для статического веб-хостинга, и его закрытие вызовет отказ в обслуживании; или избыточные разрешения у сервисной роли иногда необходимы из-за недостаточной гранулярности сервисных политик. Поэтому перед блокировкой обязательна консультация с владельцем ресурса.

## Сквозной практический пример: расследование непреднамеренного раскрытия данных и эскалации прав в AWS

**Исходные условия:** Организация использует AWS для приложения, обрабатывающего внутренние документы. Инфраструктура включает S3-бакет `docstore`, EC2-инстанс с ролью `AppRole` и разработчицкий IAM-юзер `dev_alice`. В SOC поступает алерт от GuardDuty: обнаружена подозрительная активность — вызов `AssumeRole` с необычного IP, использующий роль `AppRole`. Дополнительно внутренний сканер CSPM сигнализирует о находке `S3 bucket 'docstore' has public read ACL`.

**Шаг 1. Проверка публичного доступа к бакету.** Аналитик выполняет команду AWS CLI для подтверждения факта публичности.

```bash
aws s3api get-bucket-acl --bucket docstore \
    --query "Grants[?Grantee.URI=='http://acs.amazonaws.com/groups/global/AllUsers']"
```

Вывод (схематично):

```json
[
    {
        "Grantee": {
            "Type": "Group",
            "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
        },
        "Permission": "READ"
    }
]
```

Находка подтверждена: любой интернет-пользователь может читать объекты. Параллельно аналитик проверяет, включена ли блокировка публичного доступа на уровне аккаунта:

```bash
aws s3control get-public-access-block --account-id 123456789012
```

Если вывод содержит `"BlockPublicAcls": false` и `"BlockPublicPolicy": false`, риск многократно выше.

**Шаг 2. Анализ разрешений роли `AppRole`.** Аналитик запрашивает список политик, прикреплённых к роли:

```bash
aws iam list-attached-role-policies --role-name AppRole
```

Результат показывает `PolicyArn: arn:aws:iam::aws:policy/AmazonS3FullAccess` — избыточное разрешение, не ограниченное конкретным бакетом.

Детализация последних действий роли через CloudTrail:

```bash
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time 2026-03-01T00:00Z --end-time 2026-03-02T00:00Z \
    --query "Events[?Resources[?ResourceName=='AppRole']]"
```

В результатах находятся записи AssumeRole от пользователя `dev_alice`, но также аномальная запись с IP `198.51.100.77`, не принадлежащим корпоративной сети.

**Шаг 3. Корреляция действий.** Используя CloudTrail, аналитик фильтрует события, совершённые сессией с данным временным ключом (accessKeyId из записи AssumeRole). Обнаружены вызовы `s3:ListObjects` и `s3:GetObject` на бакет `docstore`. Зная, что роль имеет полный доступ к S3, а бакет публичен, злоумышленник мог использовать как прямое анонимное чтение, так и скомпрометированную роль для более скрытной эксфильтрации.

**Шаг 4. Немедленные меры.** Аналитик рекомендует и инициирует:
- Удаление публичного ACL: `aws s3api put-bucket-acl --bucket docstore --acl private`.
- Включение блокировки публичного доступа на бакете: `aws s3api put-public-access-block --bucket docstore --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.
- Замену политики роли `AppRole` на кастомную, разрешающую `s3:GetObject` только для `arn:aws:s3:::docstore/*` через `aws iam put-role-policy`.
- Принудительный отзыв активных сессий роли: `aws iam delete-role-policy` для временного удаления избыточной политики и создание новой.

После изменений аналитик повторяет проверки и документирует хронологию.

**Шаг 5. Анализ первопричины.** Выясняется, что публичный ACL был выставлен разработчиком `dev_alice` при тестировании, а роль `AppRole` получила `AmazonS3FullAccess` по шаблону быстрого старта без дальнейшего аудита. Отсутствие автоматического контроля (CSPM) позволило проблеме оставаться незамеченной неделями.

**Ожидаемый вывод.** Сквозной пример демонстрирует, как одна ошибка конфигурации (публичный бакет) в сочетании с избыточными правами роли приводит к инциденту с потенциальной утечкой данных. SOC L1, владея описанными техниками, способен не только подтвердить проблему, но и предоставить конкретные шаги по изоляции и устранению, минимизируя ущерб.

## Источники

- [Cloud Security in 2026: Threats, Technologies & Best Practices](https://www.cycognito.com/learn/cloud-security)
- [🔐 Shared Responsibility Model в облаке: кто за что отвечает в безопасности](https://cloud.servermall.ru/blog/shared-responsibility-model-v-oblake-kto-za-chto-otvechaet-v-bezopasnosti)
- [Top cloud misconfigurations: A CSPM perspective | Sysdig](https://www.sysdig.com/blog/top-cloud-misconfigurations)
- [Managing Cloud Misconfigurations Risks | CSA](https://cloudsecurityalliance.org/blog/2023/08/14/managing-cloud-misconfigurations-risks)
- [Cloud Misconfiguration: The #1 Cause of Data Breaches 2025 | Fidelis Security](https://fidelissecurity.com/threatgeek/threat-detection-response/cloud-misconfigurations-causing-data-breaches)
- [Understanding Cloud Security Architecture for IaaS, SaaS & PaaS](https://www.guidepointsecurity.com/blog/cloud-security-architecture)
- [What Is SaaS Security? | Definition & Explanation - Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-is-saas-security-definition-and-explanation)
- [The Shared Responsibility Model Explained w/Examples | Wiz](https://www.wiz.io/academy/cloud-security/shared-responsibility-model)
- [SaaS Misconfigurations: What They Are & How to Prevent | AppOmni](https://appomni.com/learn/saas-security-fundamentals/saas-misconfigurations-prevention-best-practices)
- [What are SaaS Misconfigurations? | CrowdStrike](https://www.crowdstrike.com/en-us/cybersecurity-101/identity-protection/saas-misconfigurations)
- [Learn About Cloud Misconfigurations - Darktrace](https://www.darktrace.com/cyber-ai-glossary/cloud-misconfigurations)
- [IaaS, PaaS, SaaS and CaaS: Cloud Models Explained - Mitiga](https://www.mitiga.io/blog/iaas-vs-paas-vs-saas-what-are-the-differences)
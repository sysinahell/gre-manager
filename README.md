<div align="center">

# 🛰️ GRE Manager

**Терминальный интерфейс для IPv4 GRE-туннелей, маршрутов, NAT, firewall и резервных копий на Debian / Ubuntu**

[![Version](https://img.shields.io/badge/version-1.5.0-blue.svg)](#-что-нового-в-v15)
[![Status](https://img.shields.io/badge/status-pre--production-orange.svg)](#-безопасность-и-ограничения)
[![Python](https://img.shields.io/badge/python-3.x-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-A81D33.svg?logo=debian&logoColor=white)](#-установка)
[![MikroTik](https://img.shields.io/badge/peer-MikroTik%20RouterOS-293239.svg)](#-новый-gre-до-mikrotik)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

**Русский** · [English](README.en.md)

</div>

---

GRE Manager — это TUI в одном файле на Python + `dialog`, удобный для работы по SSH. Он управляет L3 GRE-туннелями, маршрутами, source-routing, NAT для выхода в Интернет по каждому туннелю, изоляцией в firewall, резервными копиями и миграцией IP — и трогает **только свои** профили в `/etc/gre-manager/tunnels/`.

Нужны Python 3, `dialog`, `iproute2`, systemd и `iptables` (legacy или iptables-nft). GRETAP, IPv6 GRE, IPsec и шифрование GRE **не** поддерживаются.

> [!CAUTION]
> **Предрелизная версия.** Живых интеграционных тестов не было — сначала проверьте на одноразовой ВМ с Debian/Ubuntu и реальным MikroTik. Не перезапускайте сервисы туннелей через единственное SSH-подключение без доступа к консоли / rescue.

## 📑 Содержание

- [Возможности](#-возможности)
- [Что нового в v1.5](#-что-нового-в-v15)
- [Установка](#-установка)
- [Новый GRE до MikroTik](#-новый-gre-до-mikrotik)
- [Режимы firewall](#-режимы-firewall)
- [Аудит хоста](#-аудит-хоста-только-чтение)
- [Миграция существующих GRE](#-миграция-существующих-gre--передача-в-два-этапа)
- [Массовые NAT и режим безопасности](#-массовые-nat-и-режим-безопасности)
- [ACL для протокола 47](#-опциональный-acl-входящего-протокола-47)
- [Сохранение правил firewall](#-сохранение-и-восстановление-правил-firewall)
- [Бэкапы и миграция IP](#-бэкапы-и-миграция-ip)
- [Справка по CLI](#-справка-по-cli)
- [Проверка](#-проверка)
- [Безопасность и ограничения](#-безопасность-и-ограничения)
- [Лицензия](#-лицензия)

## ✨ Возможности

| | |
|---|---|
| 🧙 **Мастер туннелей** | Создаёт GRE с автоматическим выделением `/30` с учётом реальных адресов и маршрутов ядра |
| 🌐 **Раздача Интернета** | NAT + forwarding для каждого туннеля, по умолчанию включено для новых |
| 🛡️ **Изоляция в firewall** | Отдельная цепочка FORWARD `GMF_*` на каждый туннель с явным DROP |
| 🔒 **Входящий ACL** | Опциональный whitelist GRE-пиров по протоколу 47 на underlay IP |
| 🔎 **Аудит** | Отчёт (только чтение) о старых правилах, занятых адресах и неуправляемых GRE |
| 🔁 **Миграция** | Перенос существующих Linux GRE в управляемые профили без их остановки |
| 📦 **Массовые операции** | NAT и режим безопасности для всех или выбранных туннелей |
| 💾 **Бэкап / восстановление** | ZIP-архивы, автоматические снимки перед изменениями |
| ⚙️ **systemd** | Отдельный `gre-manager@<туннель>.service` на каждый туннель, опциональный автозапуск |
| 📟 **Скрипты для MikroTik** | Полный конфиг RouterOS 6 / 7: GRE, таблица маршрутизации, mangle, address list, NAT |

## 🆕 Что нового в v1.5

| Проблема в 1.4 | Решение в v1.5 | Примечание |
|---|---|---|
| `KeyError: internet` при редактировании предложенного `/30` | **Исправлено** | `/32` клиента берётся из реально выбранного `/30` |
| Существующие Linux GRE не распознавались | Предпросмотр и staging через `stage-live` + TUI | **Без принудительного перехвата** — сначала остановите старого владельца |
| Пул проверял только JSON менеджера | Читаются IPv4-адреса ядра, все таблицы маршрутов, профили и `/etc/gre-peers.conf` | Если ядро опросить не удалось — выделение запрещается |
| Широкие старые ACCEPT / MASQUERADE обходили переключатель NAT | Опциональная изолированная цепочка FORWARD на каждый GRE с финальным DROP | Старые профили остаются `legacy`, пока их явно не переключат |
| Существующие собственные политики FORWARD могли обходиться | `isolated-pass`: разрешённый трафик возвращается (RETURN) в родительскую цепочку FORWARD | По умолчанию для перенесённых GRE; новые используют `isolated` |
| Не было ограничения, кто может присылать GRE | Опциональный INPUT ACL по протоколу 47 с whitelist пиров + DROP | Только явное включение, один эксклюзивный underlay |
| `iptables-persistent` восстанавливал дубликаты | Идентичные правила менеджера принимаются идемпотентно | `firewall-reconcile` / `acl reconcile`, если перезагрузка их удалила |
| MTU 1476 / TTL 64 по умолчанию | Новые GRE: **MTU 1400**, **TTL 250** | Существующие профили сохраняют свои значения |
| Интерфейсы с `/24` и `/30` одновременно | Поддержка `extra_addresses`; миграция читает все IPv4-адреса | Проверьте поведение дублирующихся адресов на своём ядре |
| Не было массовой смены безопасности | `bulk-security` для всех или выбранных туннелей | `--apply` **перезапускает** активные GRE |

## 📥 Установка

### Зависимости

```bash
sudo apt-get update
sudo apt-get install -y python3 iproute2 dialog iptables iputils-ping procps
```

### Новая установка

```bash
git clone https://github.com/sysinahell/gre-manager.git
cd gre-manager
sudo install -m 0755 gre-manager.py /usr/local/sbin/gre-manager

# установить systemd-юниты
sudo gre-manager init

# проверка хоста (только чтение)
sudo gre-manager audit

# запуск TUI
sudo gre-manager
```

### Обновление с v1.4

```bash
# бэкап профилей и старой версии скрипта
sudo gre-manager backup /root/gre-before-v15.zip
sudo cp -a /usr/local/sbin/gre-manager /root/gre-manager.v1.4.bak

# установка новой версии
sudo install -m 0755 gre-manager.py /usr/local/sbin/gre-manager
sudo gre-manager init
sudo gre-manager audit
```

> [!NOTE]
> После обновления нужно выполнить `init`: он создаёт опциональный, **выключенный по умолчанию** `gre-manager-input-acl.service`. `init` не запускает и не перезапускает GRE и не перезаписывает `gre-manager@.service`, если тот отличается от известного шаблона.
>
> Для замены Python-файла **перезапуск GRE не нужен**. Существующие профили остаются `firewall_mode=legacy`, пока их явно не переключат. Бэкапы v1.2–v1.4 читаются.

## 🧭 Новый GRE до MikroTik

Типичная схема: LAN → **source NAT на MikroTik во внутренний IP GRE** → GRE → MASQUERADE на сервере для каждого пира → Интернет.

| Параметр | Значение |
|---|---|
| Внутренний GRE сервера | `10.255.10.1/30` |
| Внутренний GRE MikroTik | `10.255.10.2/30` |
| По умолчанию для новых туннелей | MTU 1400, TTL 250, NAT включён, `firewall_mode=isolated` |

- Если первый NAT делает MikroTik, **оставьте поле LAN MikroTik пустым** в мастере — `/32` пира разрешается автоматически, обратные маршруты не нужны.
- Если LAN маршрутизируются без NAT, укажите их в мастере: они попадут в allowlist NAT и в обратные маршруты через GRE-интерфейс.
- WAN сервера определяется автоматически — на хостах с несколькими аплинками проверьте его.
- GRE (протокол 47) должен быть разрешён в вашем INPUT, если вы не включаете [входящий ACL](#-опциональный-acl-входящего-протокола-47).

Конфиг для MikroTik генерируется целиком — см. [следующий раздел](#полный-скрипт-для-mikrotik-routeros-6--7). Краткая сводка по туннелю (адреса, NAT, недостающие маршруты):

```bash
sudo gre-manager peer gre1
```

### Полный скрипт для MikroTik (RouterOS 6 / 7)

TUI: меню туннеля → `Generate full MikroTik script`. Результат можно вывести простым текстом для копирования мышью (без рамок dialog), отправить сразу в локальный буфер обмена через OSC 52 (Windows Terminal, iTerm2, kitty, WezTerm; в tmux нужен `set -g set-clipboard on`), сохранить в `.rsc` или посмотреть в окне. Или через CLI:

```bash
# RouterOS 7: вывести скрипт на экран
sudo gre-manager mikrotik gre1 --ros 7 \
    --clients 192.168.88.10,192.168.88.0/24

# RouterOS 6: сохранить в файл для /import
sudo gre-manager mikrotik gre1 --ros 6 \
    --clients 192.168.88.10 -o /root/gre1.rsc
```

Готовый `.rsc` загрузите в **Files** на роутере и выполните:

```text
/import file-name=gre1.rsc
```

Скрипт создаёт GRE-интерфейс (keepalive выключен, MTU из профиля), его адрес `/30`, отдельную таблицу маршрутизации (`/routing table` в v7, `routing-mark` в v6) с маршрутом по умолчанию через внутренний IP сервера и `check-gateway=ping`, address-list клиентов и список исключений для частных сетей, mangle (метка соединения → метка маршрута, MSS clamp), маскарад в туннель и исключает помеченные соединения из FastTrack. Через GRE идут только клиенты из списка; сам роутер и публичный адрес GRE-сервера остаются в основной таблице.

| Параметр | Значение |
|---|---|
| `--ros 6\|7` | Версия RouterOS (по умолчанию 7) |
| `--clients` | IP / CIDR клиентов, которых заворачивать в туннель |
| `--server-ip` | Публичный IPv4 сервера, если сервер за NAT |
| `--fallback` | Без kill switch: пока GRE лежит, клиенты ходят через основной WAN |
| `-o FILE` | Сохранить как `.rsc` для `/import` |

Все объекты помечены `comment="gre-manager:<туннель>"`; команды удаления — в конце скрипта.

## 🚦 Режимы firewall

| Режим | Поведение | Для чего |
|---|---|---|
| `isolated` | Пропускает только разрешённые источники в/из выбранного WAN, остальной FORWARD-трафик этого GRE отбрасывает, добавляет MASQUERADE по источнику | Новые туннели (по умолчанию) |
| `isolated-pass` | Разрешённый трафик возвращается (RETURN) в родительскую `FORWARD`, и решение принимают существующие политики | Сосуществование с имеющимся firewall; по умолчанию для перенесённых GRE |
| `legacy` | Только правила NAT/FORWARD менеджера, без запрещающего барьера | Профили v1.4 и старше |

Новые туннели ставят изолирующий барьер **до** поднятия GRE-устройства и снимают **после** его удаления — так старый `gre+ ACCEPT` не успевает пропустить трафик.

> [!WARNING]
> На свежем VPS с политикой FORWARD DROP для `isolated-pass` могут понадобиться дополнительные ACCEPT-правила ниже по цепочке. Другие инструменты могут позже изменить порядок FORWARD — проверяйте через `audit`.

## 🔎 Аудит хоста (только чтение)

```bash
sudo gre-manager audit
```

Показывает режим безопасности и состояние управляемых туннелей, старые `gre+ ACCEPT`, сторонние MASQUERADE, недостающие цепочки/хуки менеджера, занятость пула `/30` (адреса ядра + все маршруты + `/etc/gre-peers.conf`) и неуправляемые GRE в ядре. Произвольные shell-скрипты и собственные реестры **не** разбираются — проверьте их вручную.

Проверка конфликтов адресов строгая: если существующий маршрут или интерфейс `/24` перекрывает предложенный `/30`, новый туннель не создаётся. Разберитесь, а не обходите проверку.

## 🔁 Миграция существующих GRE — передача в два этапа

**1. Сканирование и staging (только чтение)**

```bash
sudo gre-manager audit

# только предпросмотр
sudo gre-manager stage-live gre-shop3

# создать неактивный профиль (сам GRE не останавливается)
sudo gre-manager stage-live gre-shop3 --commit
```

Предпросмотр читает живые параметры `ip -d -j link`, все IPv4-адреса и неподключённые маршруты через этот GRE. Профиль создаётся с `internet.enabled=false`, `firewall_mode=isolated-pass` и без автоматически привязанных `ip rule`. Сложные конфигурации (wildcard remote, асимметричные ключи, неподдерживаемые параметры) отклоняются.

Перед переключением сохраните policy routing, `iptables-save`, исходный сервис / crontab и старый реестр пиров, проверьте профиль (адреса, ключи, MTU, TTL, маршруты, WAN, источники NAT).

**2. Плановое переключение** — только с доступом к консоли / rescue:

1. Остановите и отключите **старого** владельца и любое автопересоздание; убедитесь, что он не поднимется снова.
2. Удалите старый GRE-интерфейс в ядре.
3. Запустите туннель под управлением менеджера: `sudo systemctl enable --now gre-manager@gre-shop3.service`.
4. Проверьте маршруты, захват пакетов и исходящий NAT с обеих сторон.

> [!WARNING]
> Никогда не позволяйте старому скрипту и менеджеру одновременно управлять одним интерфейсом. Широкие старые правила INPUT/FORWARD/NAT автоматически не удаляются — запланируйте это отдельным изменением. Сначала переносите один тестовый туннель; используйте `isolated-pass`, пока не убедитесь, что существующие проверки FORWARD продолжают работать.

## 📦 Массовые NAT и режим безопасности

```bash
# NAT, предпросмотр (без --commit ничего не меняется)
sudo gre-manager bulk-internet --enable --all --wan ens3
sudo gre-manager bulk-internet --disable --tunnels gre1,gre3

# NAT, применить «на лету», без перезапуска GRE
sudo gre-manager bulk-internet --disable --tunnels gre1,gre3 \
    --commit --apply
```

```bash
# режим безопасности, предпросмотр
sudo gre-manager bulk-security --mode isolated-pass --tunnels gre1,gre2

# сохранить без перезапуска (применится при следующем старте)
sudo gre-manager bulk-security --mode isolated-pass --all --commit

# ОСТОРОЖНО: перезапускает активные GRE, SSH может оборваться
sudo gre-manager bulk-security --mode isolated-pass --all \
    --commit --apply
```

В `isolated` / `isolated-pass` выключение NAT сохраняет запрещающие барьеры FORWARD. В `legacy` удаляются только правила менеджера — старые широкие ACCEPT/MASQUERADE могут продолжать пропускать трафик. `ip_forward` глобальный и намеренно **никогда** не выключается автоматически.

## 🔒 Опциональный ACL входящего протокола 47

**Не включается при обновлении или миграции.** Включайте только на **эксклюзивном** underlay-адресе, убедившись, что **все** живые GRE на нём управляются менеджером. ACL ограничен `INPUT -i WAN -d LOCAL -p 47`: известные пиры пропускаются (RETURN), остальные отбрасываются (DROP).

```bash
# предпросмотр
sudo gre-manager acl preview --local 203.0.113.5 --wan ens3

# включить
sudo gre-manager acl enable --local 203.0.113.5 --wan ens3 \
    --exclusive-underlay --commit
sudo systemctl status gre-manager-input-acl.service

# после изменения списка пиров или перезагрузки iptables
sudo gre-manager acl reconcile --commit

# удалить только ACL менеджера
sudo gre-manager acl disable --commit
```

- Один управляемый underlay на хост. Активация отклоняется, если к этому IP привязан неуправляемый или перенесённый (staged) GRE.
- За NAT используйте **локальный IP, выданный серверу**, а не публичный адрес NAT.
- Whitelist по IP источника — это не аутентификация, не целостность и не шифрование; разрешённые пакеты всё равно проходят ваши правила INPUT.

## 🧱 Сохранение и восстановление правил firewall

Правила менеджера имеют точные комментарии и отдельные цепочки `GMF_*` на каждый туннель. Если `netfilter-persistent` восстанавливает **идентичные** правила до старта сервиса туннеля, они принимаются без дублей. Если позже перезагрузка их удалит, менеджер сам этого не заметит:

```bash
sudo gre-manager audit
sudo gre-manager firewall-reconcile gre1

# только если включён входящий ACL
sudo gre-manager acl reconcile --commit
```

`systemctl is-active` не доказывает корректность firewall. Восстановление отказывается работать с цепочками менеджера, изменёнными извне, а фоновый таймер не ставится, чтобы не конкурировать с другими инструментами. В продакшене выберите **один источник правды для firewall** и осознанно упорядочьте перезагрузки (netfilter-persistent / Docker / nftables / этот менеджер).

## 💾 Бэкапы и миграция IP

```bash
# на старом сервере
sudo gre-manager backup /root/gre-export.zip

# на новом сервере: предпросмотр, затем запись профилей
sudo gre-manager restore /root/gre-export.zip --local 203.0.113.20 --wan ens3
sudo gre-manager restore /root/gre-export.zip --local 203.0.113.20 --wan ens3 \
    --enable-saved --commit
```

```bash
# смена локального IPv4 у всех туннелей: предпросмотр, затем применение
sudo gre-manager bulk-local 203.0.113.20 --from 203.0.113.10
sudo gre-manager bulk-local 203.0.113.20 --from 203.0.113.10 --commit --apply
```

- `restore` **никогда** не запускает туннели; `bulk-local --apply` **перезапускает** активные GRE.
- Бэкап содержит только профили менеджера и флаги автозапуска — **не** неуправляемые туннели, глобальный firewall, Docker, собственные скрипты / юниты и входящий ACL. Переносите их отдельно.

## 💻 Справка по CLI

Все команды запускаются через `sudo`. Полная справка с ключами — `sudo gre-manager --help`.

| Команда | Что делает |
|---|---|
| `gre-manager` | Интерактивный TUI |
| `gre-manager init` | Установить systemd-юниты |
| `gre-manager audit` | Аудит firewall и адресов (только чтение) |
| `gre-manager pool [CIDR]` | Показать или изменить пул адресов `/30` |
| `gre-manager allocate [CIDR]` | Показать следующую свободную пару `/30` |
| `gre-manager peer TUNNEL` | Сводка по туннелю для стороны MikroTik |
| `gre-manager mikrotik TUNNEL` | Полный скрипт для RouterOS 6 / 7 |
| `gre-manager internet TUNNEL` | NAT одного туннеля |
| `gre-manager bulk-internet` | NAT для всех или выбранных туннелей |
| `gre-manager bulk-security` | Режим firewall для всех или выбранных туннелей |
| `gre-manager stage-live NAME` | Взять под управление существующий Linux GRE |
| `gre-manager firewall-reconcile NAME` | Восстановить пропавшие правила туннеля |
| `gre-manager acl ACTION` | Входящий ACL: `preview`, `enable`, `disable`, `reconcile` |
| `gre-manager backup FILE.zip` | Бэкап профилей |
| `gre-manager restore FILE.zip` | Восстановление из бэкапа |
| `gre-manager bulk-local NEW_IP` | Сменить локальный IPv4 у туннелей |

> [!TIP]
> Любая изменяющая команда работает **только в режиме предпросмотра**, пока не указан `--commit`.

## 🔍 Проверка

```bash
ip -br -4 addr
ip -d tunnel show
ip -4 route show table all
ip -4 rule show
sudo iptables -S FORWARD
sudo iptables -t nat -S POSTROUTING
sudo iptables -S INPUT
sudo systemctl status gre-manager@gre1.service
sudo journalctl -u gre-manager@gre1.service -n 60 --no-pager
```

На MikroTik первая проверка перед маршрутизацией LAN — `ping 10.255.10.1`.

## 🚧 Безопасность и ограничения

- GRE — это **IPv4-протокол 47**, а не TCP/UDP-порт 47, и он **не шифруется**. Firewall хостинга / облака должен пропускать протокол 47 между underlay-пирами.
- MASQUERADE сопоставляется по CIDR источника + выходному WAN — избегайте пересекающихся клиентских подсетей. Неограниченный источник `0.0.0.0/0` **никогда** не добавляется.
- Другие уровни (базовые цепочки nftables, UFW / firewalld, Docker, security groups облака, reverse-path filtering) влияют на трафик — проверяйте реальное прохождение пакетов.
- Изменения «на лету» затрагивают только правила, учтённые менеджером, и никогда не очищают цепочки. Откат — **best-effort**: держите доступ к консоли / out-of-band.
- GRE под управлением Netplan / NetworkManager / ifupdown не изменяются; существующие туннели можно взять под управление только через `stage-live`.
- Перед переключением продакшена проверьте на одноразовой ВМ дублирующиеся внутренние префиксы, цепочки iptables-nft, порядок правил Docker, rp_filter и фильтрацию протокола 47 у провайдера.

## 📂 Файлы

| Путь | Назначение |
|---|---|
| `/usr/local/sbin/gre-manager` | Установленный скрипт |
| `/etc/gre-manager/tunnels/` | Управляемые GRE-профили |
| `/etc/gre-manager/settings.json` | Глобальные настройки (пул адресов) |
| `/etc/gre-manager/gre-input-acl.json` | Настройки входящего ACL |
| `/etc/gre-peers.conf` | Старый реестр пиров (только чтение, учитывается при выделении) |
| `/etc/systemd/system/gre-manager@.service` | Шаблонный юнит туннеля |
| `/etc/systemd/system/gre-manager-input-acl.service` | Юнит входящего ACL (выключен по умолчанию) |
| `/etc/sysctl.d/90-gre-manager-forward.conf` | Постоянный IPv4 forwarding |
| `/run/gre-manager/` | Состояние во время работы, применённые правила firewall |
| `/var/backups/gre-manager/` | Автоматические бэкапы перед изменениями |

## 📄 Лицензия

[MIT](LICENSE) © sysinahell

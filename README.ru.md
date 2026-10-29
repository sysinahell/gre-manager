<div align="center">

# 🛰️ GRE Manager

**Терминальный интерфейс для IPv4 GRE-туннелей, маршрутов, NAT и резервных копий на Debian / Ubuntu**

[![Version](https://img.shields.io/badge/version-1.4.0-blue.svg)](#-что-нового-в-v14)
[![Python](https://img.shields.io/badge/python-3.x-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-A81D33.svg?logo=debian&logoColor=white)](#-установка)
[![Tests](https://img.shields.io/badge/unit%20tests-42-success.svg)](test_gre_manager.py)
[![MikroTik](https://img.shields.io/badge/peer-MikroTik%20RouterOS-293239.svg)](#-пример-новый-gre-до-mikrotik)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

[English](README.md) · **Русский**

</div>

---

GRE Manager — это TUI в одном файле на Python + `dialog`, удобный для работы по SSH. Он управляет GRE-туннелями, маршрутами, правилами source-routing, резервными копиями, миграцией IP, NAT для выхода в Интернет по каждому туннелю и массовыми изменениями firewall — и трогает **только свои** GRE-профили в `/etc/gre-manager/tunnels/`.

## 📑 Содержание

- [Возможности](#-возможности)
- [Что нового в v1.4](#-что-нового-в-v14)
- [Установка](#-установка)
- [Пример: новый GRE до MikroTik](#-пример-новый-gre-до-mikrotik)
- [TUI: массовое включение/выключение NAT](#-tui-массовое-включениевыключение-nat)
- [Справка по CLI](#-справка-по-cli)
- [Проверка](#-проверка-на-linux-сервере)
- [Восстановление и миграция IP](#-восстановление-на-другой-сервер-и-массовая-смена-локального-ipv4)
- [Безопасность и ограничения](#-безопасность-и-ограничения)
- [Тестирование](#-тестирование)
- [Лицензия](#-лицензия)

## ✨ Возможности

| | |
|---|---|
| 🧙 **Мастер туннелей** | Создаёт GRE с автоматическим выделением `/30` из пула (по умолчанию `10.255.10.0/24`) |
| 🌐 **Раздача Интернета** | NAT + forwarding для каждого туннеля, по умолчанию включено для новых |
| 🔀 **Маршрутизация** | Обратные маршруты к LAN за пиром, правила policy routing по источнику |
| 📦 **Массовые операции** | Включение/выключение NAT на всех или выбранных туннелях «на лету», без перезапуска GRE |
| 💾 **Бэкап / восстановление** | ZIP-архивы, автоматические снимки перед изменениями в `/var/backups/gre-manager/` |
| 🚚 **Миграция** | Восстановление на другой сервер и массовая смена локального underlay IPv4 |
| ⚙️ **systemd** | Отдельный `gre-manager@<туннель>.service` на каждый туннель, опциональный автозапуск |
| 📟 **Подсказки для MikroTik** | Готовые команды RouterOS для стороны пира |

## 🆕 Что нового в v1.4

1. **NAT настраивается автоматически для новых GRE.** После ввода конечных точек мастер открывает **Automatic Internet sharing** с `Enable Internet/NAT: yes` по умолчанию. WAN-интерфейс сервера предлагается по маршруту по умолчанию, а выделенный `/30` пир (`10.255.10.2/32` и т.д.) добавляется в разрешённые источники NAT. В мастере это можно отключить.
2. **LAN за MikroTik.** В том же мастере можно указать подсети через запятую, например `192.168.88.0/24,192.168.99.0/24`. Они добавляются в allowlist NAT **и** в профиль GRE на сервере как обратные маршруты через этот GRE-интерфейс (применяются при старте туннеля). Определить LAN со стороны сервера невозможно — вводите их вручную.
3. **Запуск сразу.** После сохранения профиля мастер спрашивает, включить ли автозапуск и запустить ли туннель сейчас. Если да — NAT / firewall / IP forwarding поднимаются вместе с туннелем; если нет — сохраняются до следующего запуска. Неудачный первый запуск отключает автозапуск, чтобы сломанный конфиг не пытался подниматься при каждой перезагрузке.
4. **Меню Bulk Internet/NAT** доступно из главного меню, даже если часть туннелей остановлена: `ENABLE` / `DISABLE` для `ALL` или для выбранных туннелей через чек-лист (выбор — пробелом), затем предпросмотр → автобэкап → подтверждение → опциональное применение «на лету».
5. **Переключение firewall «на лету».** Правила NAT и forwarding включаются/выключаются на работающих GRE **без перезапуска интерфейсов**. Правила учитываются по каждому туннелю в `/run/gre-manager/`; при ошибке выполняется best-effort откат конфигов и правил.
6. Изменение серверного адреса GRE `/30` теперь обновляет и `/32` пира в allowlist NAT, если он совпадал с прежним пиром. Другие клиентские LAN не переписываются.
7. **Обратная совместимость.** Существующие профили и бэкапы v1.2 / v1.3 продолжают работать. Обновление **не** включает NAT для существующих профилей — используйте *Bulk Internet/NAT*, чтобы включить его явно.

## 📥 Установка

### Зависимости

```bash
sudo apt update
sudo apt install -y python3 iproute2 iputils-ping dialog iptables procps
```

### Новая установка

```bash
git clone https://github.com/sysinahell/gre-manager.git
cd gre-manager
sudo install -m 0755 gre-manager.py /usr/local/sbin/gre-manager
sudo gre-manager init   # устанавливает systemd-юнит
sudo gre-manager        # запуск TUI
```

### Обновление с v1.3

```bash
# необязательно, но рекомендуется
sudo gre-manager backup /root/gre-before-v14.zip

sudo cp -a /usr/local/sbin/gre-manager /usr/local/sbin/gre-manager.v1.3.bak
sudo install -m 0755 gre-manager.py /usr/local/sbin/gre-manager
sudo gre-manager
```

> [!NOTE]
> При замене v1.3 не нужно перезапускать сеть или повторно выполнять `init` — конфигурация сохраняется.

## 🧭 Пример: новый GRE до MikroTik

| Параметр | Значение |
|---|---|
| Underlay IPv4 сервера | `203.0.113.10` |
| Underlay IPv4 MikroTik | `198.51.100.20` |
| WAN-интерфейс сервера | `ens3` |
| Внутренние адреса GRE (сервер / MikroTik) | `10.255.10.1/30` / `10.255.10.2/30` |

**TUI:** `Create GRE tunnel` → ввести `local`, `remote`, внутренний `/30` → `Automatic Internet sharing` → оставить NAT `yes`, WAN `ens3`, при необходимости указать LAN MikroTik `192.168.88.0/24`.

Менеджер настроит:

- адрес GRE на сервере `10.255.10.1/30`;
- allowlist NAT `10.255.10.2/32` и (если указана) `192.168.88.0/24`;
- обратный маршрут `192.168.88.0/24 dev gre1` (если указана LAN);
- IPv4 forwarding и iptables-правила для этого GRE при старте сервиса.

**На MikroTik:**

```routeros
/ip address add address=10.255.10.2/30 interface=GRE_NAME
```

> [!IMPORTANT]
> Маршрут до **публичного underlay IP** сервера должен идти мимо GRE-туннеля. Чтобы выходить в Интернет с MikroTik/LAN через GRE, направьте маршруты / routing policy на MikroTik на **внутренний IP GRE** сервера (например, `10.255.10.1`). RouterOS автоматически не настраивается — `sudo gre-manager peer gre1` выводит рекомендуемые команды.

## 📋 TUI: массовое включение/выключение NAT

В главном меню:

```text
Bulk Internet/NAT: enable/disable ALL or selected GRE
    ENABLE  Internet NAT/forwarding
    DISABLE Internet NAT/forwarding

    ALL managed GRE tunnels
    Select specific GRE tunnels using checkboxes
         [ ] gre1
         [ ] gre2
         [ ] gre3
```

- При **включении** можно задать общий WAN или оставить поле пустым, чтобы использовать сохранённый WAN каждого туннеля (или автоопределение, если его нет).
- Предпросмотр показывает все затронутые туннели и недостающие маршруты к клиентским LAN.
- При сохранении создаётся бэкап в `/var/backups/gre-manager/`; активные туннели можно обновить «на лету», остановленные получат настройки при следующем запуске.
- При **выключении** туннели и маршруты остаются поднятыми. Учтённые правила firewall удаляются, но глобальный IPv4 forwarding и его sysctl-файл **остаются**, так как на них могут полагаться другие сервисы.

## 💻 Справка по CLI

```text
sudo gre-manager                         # интерактивный TUI
sudo gre-manager --help                  # справка
sudo gre-manager init                    # установить systemd-юнит
sudo gre-manager backup /root/gre.zip    # сохранить все управляемые GRE
sudo gre-manager pool [NEW_POOL_CIDR]    # показать/изменить пул выделения /30
sudo gre-manager allocate [POOL_CIDR]    # предпросмотр следующей свободной пары /30
sudo gre-manager peer TUNNEL             # инструкции RouterOS по IP/маршрутам
sudo gre-manager internet TUNNEL         # статус NAT/forwarding
```

> [!TIP]
> `restore`, `bulk-local`, `internet` и `bulk-internet` работают **только в режиме предпросмотра**, пока не указан `--commit`.

### Массовый NAT

```bash
# Только предпросмотр — ничего не меняет
sudo gre-manager bulk-internet --enable --all --wan ens3
sudo gre-manager bulk-internet --disable --tunnels gre1,gre3

# Сохранить и сразу применить правила firewall, без перезапуска GRE
sudo gre-manager bulk-internet --enable --all --wan ens3 --commit --apply
sudo gre-manager bulk-internet --disable --tunnels gre1,gre3 --commit --apply

# Сохранить до следующего запуска/перезапуска сервиса (без --apply)
sudo gre-manager bulk-internet --enable --tunnels gre1,gre2 --commit
```

> [!WARNING]
> Для уже включённых профилей повторный `--enable --apply` без изменения настроек ничего не делает. Чтобы применить отложенные изменения, перезапустите сервис GRE или явно измените настройку. В TUI для активных туннелей выбирайте применение «на лету» при первом сохранении.

### Один туннель

```bash
sudo gre-manager internet gre1 --enable --wan ens3 \
  --sources 10.255.10.2/32,192.168.88.0/24 --commit --apply
```

Для старых профилей убедитесь, что существует обратный маршрут до `192.168.88.0/24` через GRE-интерфейс — массовое включение NAT не добавляет LAN-маршруты в старые профили (мастер новых туннелей добавляет).

## 🔍 Проверка на Linux-сервере

```bash
# Состояние GRE / интерфейсов / маршрутов
ip -br -4 addr show
ip -4 route show
ip -d tunnel show

# IPv4 forwarding
sysctl net.ipv4.ip_forward

# Правила NAT / FORWARD от GRE Manager
sudo iptables -t nat -S POSTROUTING | grep gre-manager
sudo iptables -S FORWARD | grep gre-manager

# Сервис туннеля gre1
sudo systemctl status gre-manager@gre1.service
sudo journalctl -u gre-manager@gre1.service -n 60 --no-pager
sudo gre-manager peer gre1
```

На MikroTik адреса и маршруты проверяйте отдельно. `ping 10.255.10.1` с роутера — первая проверка перед маршрутизацией интернет-трафика LAN.

## 🚚 Восстановление на другой сервер и массовая смена локального IPv4

```bash
sudo gre-manager backup /root/all-gre.zip
sudo gre-manager restore /root/all-gre.zip --local NEW_LOCAL_IP --wan ens3 --enable-saved --commit
sudo gre-manager bulk-local NEW_LOCAL_IP --from OLD_LOCAL_IP --commit --apply
```

- `restore` **никогда** не запускает туннели, даже если восстанавливает флаги автозапуска.
- `bulk-local --apply` **перезапускает** активные GRE и может оборвать SSH-сессию.

## 🚧 Безопасность и ограничения

- GRE — это **IPv4-протокол 47**, а не TCP/UDP-порт 47. Firewall сервера и хостинга должен пропускать протокол 47 между underlay-пирами. GRE **не шифруется**.
- Allowlist NAT привязан к заданным CIDR источников и WAN-устройству. Правила **FORWARD** проверяют входной GRE-интерфейс; правила **MASQUERADE** в `POSTROUTING` — CIDR источника + выходной WAN (iptables не позволяет `-i` там), поэтому избегайте пересекающихся клиентских подсетей и конфликтующих NAT-правил. Неограниченный источник `0.0.0.0/0` **никогда** не добавляется.
- Другие уровни firewall (базовые цепочки `nftables`, UFW / firewalld, Docker, security groups облака) могут влиять на трафик — проверяйте реальное прохождение пакетов, а не только наличие правил.
- `net.ipv4.ip_forward=1` сохраняется при включении NAT и **не** сбрасывается при выключении NAT на всех туннелях.
- Изменения «на лету» затрагивают только правила, учтённые этим менеджером, и никогда не очищают цепочки целиком. Откат — **best-effort**, а не сетевая транзакция: держите доступ к консоли / out-of-band.
- GRE-устройства под управлением Netplan / NetworkManager / ifupdown не импортируются и не изменяются.

## 🧪 Тестирование

```bash
python3 -m unittest -v test_gre_manager.py
```

Скрипт и 42 юнит-теста проверены синтаксически и с моками. Полный end-to-end тест на реальном Debian/Ubuntu с GRE и firewall **ещё не проводился** — сначала проверьте в безопасном окружении.

## 📂 Файлы

| Путь | Назначение |
|---|---|
| `/usr/local/sbin/gre-manager` | Установленный скрипт |
| `/etc/gre-manager/tunnels/` | Управляемые GRE-профили |
| `/etc/gre-manager/settings.json` | Глобальные настройки (пул адресов) |
| `/etc/systemd/system/gre-manager@.service` | Шаблонный systemd-юнит |
| `/etc/sysctl.d/90-gre-manager-forward.conf` | Постоянный IPv4 forwarding |
| `/run/gre-manager/` | Состояние во время работы, применённые правила firewall |
| `/var/backups/gre-manager/` | Автоматические бэкапы перед изменениями |

## 📄 Лицензия

[MIT](LICENSE) © sysinahell

# Полное удаление одной командой

Ничего скачивать и распаковывать не требуется. Полный uninstall предназначен для отдельного сервера, где AmneziaWG, Nginx и Certbot не обслуживают другие проекты.

```bash
curl -fsSL https://raw.githubusercontent.com/WeedVDK/sg-awg-panel/main/uninstall.sh | sudo bash
```

Команда запросит безопасное подтверждение:

```text
DELETE SG-AWG-PANEL COMPLETELY
```

Для автоматического удаления без вопроса подтверждения (только для отдельного тестового EC2):

```bash
curl -fsSL https://raw.githubusercontent.com/WeedVDK/sg-awg-panel/main/uninstall.sh | sudo bash -s -- --yes
```

После завершения:

```bash
sudo reboot
```

После перезагрузки можно установить свежий архив на тот же EC2. Полный uninstall 206 также удаляет локальную регистрацию SG-Node: Agent, токен, идентификатор, состояние, `sgcascade`, nftables и policy routing. Поэтому прежняя Node не подключится к Controller автоматически после новой установки.

Запись SG-Node хранится на Controller. Для совершенно нового теста удалите её в Cluster; для повторного подключения нажмите «Создать команду подключения» рядом с этой SG-Node.

Read-only аудит:

```bash
curl -fsSL https://raw.githubusercontent.com/WeedVDK/sg-awg-panel/main/verify-uninstall.sh | sudo bash
```

Аудит не удаляет файлы и не заменяет uninstall.


## Сбросить только подключение SG-Node

Если обычный AWG-сервер и его клиенты должны остаться, а нужно удалить только связь с Cluster:

```bash
sudo bash deploy/uninstall-node-agent.sh
```

Команда удаляет Agent, токен, имя Node, состояние и служебный Cascade, но сохраняет `awg0`, UDP 585 и обычных клиентов.

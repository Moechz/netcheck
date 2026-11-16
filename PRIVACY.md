# Privacy Policy — NetCheck for TerraMaster TOS

**Last updated:** 17 November 2026
**Data controller / contact:** Moechz — moechz@163.com

## 1. Summary

- The app runs **entirely on your NAS**. The developer does not receive, collect or have
  access to your data.
- No telemetry, no analytics and no account operated by the developer.

## 2. What data is processed

the application data directory used by NetCheck (configuration, repair history and pre-fix snapshots).

It inspects local network interfaces and TOS services and only performs changes you explicitly confirm.

## 3. Retention period

Data is kept until **you** delete it; uninstalling with "delete data" removes it. Logs are
rotated by the application or the container runtime.

## 4. Your rights and the deletion channel

Access/export by copying the data folder; correct in the app's own UI; delete by
uninstalling with "delete data" or removing the folder. Assistance:
**moechz@163.com** (reply within 30 days).

## 5. Security measures

The package uses pinned images, no `privileged`, no host networking and no Docker socket;
only the application port is published. Put the UI behind a TLS reverse proxy if exposed
outside the LAN.

## 6. Third-party sharing and API disclosure

The developer shares nothing. The app contacts only the services you configure — for
example the identity providers/applications you connect, an SMTP server you set, or an
update check. Endpoints are the ones you enter; data is what that feature needs;
destination is your LAN or the provider you chose.

## 7. Children

Not directed at children.

## 8. Changes

Material changes are published in this file and reflected in the "Last updated" date.

## 9. Contact

Moechz — **moechz@163.com** — <https://www.moechz.com/privacy.html>

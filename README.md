# NAART Wispbyte Gateway

Flask/WebSocket relay for NAART FTP Server remote access.
It relays remote Web UI, remote FTP bridge streams, and remote server update streams.

## Environment

- `PUBLIC_BASE_URL`: public portal URL, for example `https://your-app.wispbyte.com`.
- `DATABASE_PATH`: SQLite database path. Default: `wispbyte_gateway.sqlite3`.
- `MAX_BODY_MB`: max proxied web request body size. Default: `512`.
- `PORT`: Flask listen port. Default: `8080`.

## Remote Update

Remote updates use `/ws/client/update?slug=...` and only work for online devices that publish `remoteUpdateEnabled=true`.
The gateway relays update frames only; it does not store update packages.

## Run

```powershell
pip install -r requirements.txt
python main.py
```

Set production values in `.env` before starting the app.

## Device Registration

NAART FTP Server registers itself automatically when Remote Access is enabled.
Use the same `Portal URL` and a unique `Server slug` in the server settings.

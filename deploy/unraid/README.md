# Native LFPConnect deployment

Install release binaries and configuration under `/mnt/user/appdata/lfp-pipe`:

```text
/mnt/user/appdata/lfp-pipe/
  bin/lfp-pipe-client
  bin/lfp-pipe-server
  etc/librespeed-client.toml
  etc/server.toml
  log/
  run/
```

The scripts in this directory are intentionally self-contained because Unraid
User Scripts copies each script independently. Install the applicable script
with an array-start schedule. Override the root only when necessary with
`LFP_PIPE_HOME`.

```bash
/bin/bash /boot/config/plugins/user.scripts/scripts/lfp-pipe-server/script status
/bin/bash /boot/config/plugins/user.scripts/scripts/lfp-pipe-server/script restart
tail -f /mnt/user/appdata/lfp-pipe/log/server.log
```

The canonical general server configuration is
[`server.lfpconnect.toml`](../../server.lfpconnect.toml). Its advertised data
address must remain reachable by every tunnel client. The repository example
contains no tunnel authentication, so firewall the data listener to trusted
client networks. Supply the real NATS URL as `LFP_PIPE_NATS_URL` from the
protected User Script environment; do not write credentials into the tracked
TOML file.

## LibreSpeed client

LibreSpeed runs separately and exposes HTTP on `127.0.0.1:8000`. The
`lfp-pipe-librespeed-client` supervisor connects that backend to the native
public server configured under [`../swarm01`](../swarm01/README.md).

```bash
/bin/bash /boot/config/plugins/user.scripts/scripts/lfp-pipe-librespeed-client/script status
/bin/bash /boot/config/plugins/user.scripts/scripts/lfp-pipe-librespeed-client/script restart
tail -f /mnt/user/appdata/lfp-pipe/log/librespeed-client.log
```

Public address: `http://swarm01.example.com:7443/`.

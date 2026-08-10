# Public swarm01 deployment

The public endpoint runs directly as a Rust systemd service; the tunnel server
is not containerized. Install these files:

```text
/opt/lfp-pipe/bin/lfp-pipe-server
/etc/lfp-pipe/librespeed-server.toml
/etc/systemd/system/lfp-pipe-librespeed.service
```

Copy this directory's service and configuration, then enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lfp-pipe-librespeed.service
sudo systemctl status lfp-pipe-librespeed.service
sudo journalctl -u lfp-pipe-librespeed.service -f
```

Put `LFP_PIPE_NATS_URL=...` in `/etc/lfp-pipe/lfp-pipe.env`, set that file to
mode `0600`, and reload the service. The unit reads this optional environment
file. Do not add the real URL to the tracked TOML example.

The service accepts public traffic on `7443` and reverse client connections on
the configured data listener. Permit only the required public ingress and
restrict the unauthenticated data listener to trusted client source addresses.
The advertised data address must be the public swarm address clients can reach,
not a ZeroTier/ZeroBus alias when validating the real public path.

Public address: `http://swarm01.lfpconnect.io:7443/`.

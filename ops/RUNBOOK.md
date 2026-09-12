# ghostpay go-live runbook

The relayer (serve.mjs) runs under systemd on a Debian 13 VPS at 80.78.19.4 as the
`ghostpay` service. The original build lives at /root/ghostpay and is the running one.
The new build sits at /opt/ghostpay with its own /opt/ghostpay/ghostpay.env. This runbook
puts the new build in front of the domain and keeps the old one as the rollback target.

## 1. DNS

Done: ghostpay.ethprivacy.tools resolves to 80.78.19.4. Caddy issues the Let's Encrypt
certificate automatically on first request, no cert step needed.

## 2. Firewall

Ports 80 and 443 must be open (Caddy needs both: 80 for the ACME challenge, 443 to serve).

```
ufw allow 80/tcp
ufw allow 443/tcp
ufw status
```

If the provider has its own network firewall, open 80/443 there too.

## 3. Install Caddy

```
apt update
apt install -y caddy curl
systemctl enable caddy
```

## 4. Drop in the Caddyfile

```
cp /opt/ghostpay/ops/Caddyfile /etc/caddy/Caddyfile
caddy fmt --overwrite /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
```

The Caddyfile proxies ghostpay.ethprivacy.tools to 127.0.0.1:8791 and sets a CSP
(default-src 'self', with 'unsafe-inline' on script/style because the app uses inline
blocks, and connect-src naming the RPC hosts the browser calls), nosniff, and a
no-referrer policy. A commented block for docs.ethprivacy.tools serving
/opt/ghostpay/docs is included for later: uncomment it once that DNS name points at
80.78.19.4.

## 5. Verify HTTPS

```
curl -fsS https://ghostpay.ethprivacy.tools/health
curl -fsSI https://ghostpay.ethprivacy.tools/
```

/health returns the relayer status JSON (runners, contracts, fee settings; never keys).
The headers on / should include the CSP, X-Content-Type-Options: nosniff, and
Referrer-Policy: no-referrer. The certificate appears on the first request; give it a
few seconds.

## 6. Deploy the new build

deploy.sh pulls a branch into /opt/ghostpay, runs npm ci, syntax-checks serve.mjs,
points the ghostpay unit at /opt/ghostpay via a systemd drop-in, restarts, and
health-checks /health + /. A failed health check rolls the unit back to /root/ghostpay
automatically and exits 1.

From a Mac:

```
./deploy.sh prod/phase-3-ops-docs                  # runs over ssh root@80.78.19.4
VPS_HOST=root@other-host ./deploy.sh <branch>      # different target
```

On the VPS as root:

```
/opt/ghostpay/deploy.sh prod/phase-3-ops-docs --on-vps
```

Local prep only (pull + npm ci + syntax check, nothing deployed):

```
./deploy.sh prod/phase-3-ops-docs --local
```

Watch the journal during a deploy:

```
journalctl -u ghostpay -f
```

## 7. Rollback

deploy.sh rolls back on its own when the health check fails. To roll back by hand,
point the drop-in at /root/ghostpay and restart:

```
cat > /etc/systemd/system/ghostpay.service.d/10-ghostpay-paths.conf <<'EOF'
[Service]
WorkingDirectory=/root/ghostpay
EnvironmentFile=/root/ghostpay/ghostpay.env
ExecStart=
ExecStart=/usr/bin/node /root/ghostpay/serve.mjs
EOF
systemctl daemon-reload
systemctl restart ghostpay
curl -fsS http://127.0.0.1:8791/health
```

Adjust the node path if `command -v node` says otherwise. The empty `ExecStart=` line is
required: it clears the base unit's command before the new one is set.

## 8. Rotate the runner key

Runners pay gas for announces and sweeps, and receive the relayer fees onchain. The
runner key lives in ghostpay.env (RUNNER_PK) or runners.local.json, both gitignored.

1. Generate a fresh key off the server, note its address.
2. Fund the new address with enough ETH for gas plus the fee reserve (FEE_RESERVE_ETH,
   default 0.005 on the relayer).
3. Edit ghostpay.env on the VPS: replace RUNNER_PK with the new key. Never paste the key
   into chat, tickets, or the shell history of a shared account; use an editor.
4. `systemctl restart ghostpay` and check `curl -fsS http://127.0.0.1:8791/health`:
   the runners list must show only the new address.
5. Drain the old runner: send its remaining ETH to the new runner or FEE_OWNER. This is
   a mainnet transaction: double-check the destination before signing.
6. Delete the old key from ghostpay.env backups once the old address is empty.

## 9. Rotate the drpc RPC key

RPC_URLS in ghostpay.env is a comma-separated list; each read call picks a random
endpoint from it.

1. Issue a new key in the drpc dashboard and build the new endpoint URL.
2. Edit ghostpay.env: swap the old drpc URL for the new one inside RPC_URLS.
3. `systemctl restart ghostpay`.
4. Verify: `journalctl -u ghostpay -n 50 --no-pager` should show clean broadcasts, and
   `curl -fsS http://127.0.0.1:8791/health` should list the endpoint hostnames.
5. Revoke the old key in the drpc dashboard.

## 10. Journals and state

All in the deploy directory (/opt/ghostpay or /root/ghostpay), all gitignored:

- fees.jsonl: one JSON line per fee-bearing broadcast ({ts, kind, feeBps, estFeeWei,
  txHash, runner}). kind "fee-forward" lines are outflows to FEE_OWNER, not revenue.
  `node fees.mjs` prints the revenue report.
- broadcasts.jsonl: the reaper journal, one JSON line per journaled broadcast. The
  reaper marks entries done with a finalStatus: confirmed, replaced, reverted,
  given-up, or untracked. Entries are pruned a week after completion.
- monitor-state.json: monitor.mjs's cursor (last run time) plus the given-up hashes it
  already alerted on. Delete it to re-baseline the monitor.
- Service logs: `journalctl -u ghostpay`. Keys are never logged by the relayer.

Backup (ops/backup.sh): tars fees.jsonl, broadcasts.jsonl, and ghostpay.env into
/root/backups/ghostpay-<datestamp>.tar.gz (mode 600), keeping the last 12. Cron line:

```
41 3 * * * /opt/ghostpay/ops/backup.sh >> /var/log/ghostpay-backup.log 2>&1
```

ghostpay.env holds secrets: keep the archives on the VPS, mode 600, root only.

## 11. Monitoring and alerts

monitor.mjs runs from cron (no VPS changes needed beyond the cron entry):

```
23 */6 * * * cd /opt/ghostpay && /usr/bin/node monitor.mjs >> monitor.log 2>&1
```

Each run reads the journals, computes fees earned and forwarded since the last run,
counts reaper outcomes, reads runner balances over RPC, and sends a Telegram digest.
Telegram config: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID in the environment, or
monitor.local.json (gitignored): {"telegram": {"botToken": "…", "chatId": "…"}}.
With no telegram config the digest prints to stdout instead.

A digest looks like:

```
ghostpay monitor · 2026-09-12 18:23Z
fees since 2026-09-12T12:23:01.004Z: earned 0.000006 ETH (2) · forwarded 0 ETH (0)
fees all time: earned 0.000571 ETH (11) · forwarded 0 ETH (0)
reaper since 2026-09-12T12:23:01.004Z: confirmed 4 · replaced 2 · reverted 0 · given-up 0 · untracked 0 · in-flight 0
runner 0x7cE5…2FDA: 0.042 ETH
alerts: none
```

ALERTs go out as a separate message titled GHOSTPAY ALERT, before the digest:

- Runner balance below 2x FEE_RESERVE_ETH (0.01 ETH by default in monitor.mjs): the
  runner can no longer both pay gas and keep its reserve. Fund the runner.
- Reaper gave up on a broadcast after 4 attempts: the payload stays in
  broadcasts.jsonl. Investigate by hand: check the tx hashes on an explorer, check
  journalctl for the rebroadcast errors, then rebroadcast the payload manually or
  refund the user offchain. A given-up entry alerts once; a low balance alerts on
  every run until it is fixed.

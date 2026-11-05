# Server setup: install SereS

`install.sh` installs SereS on Ubuntu / Debian and keeps it running with pm2. Run it as the user
SereS should run as (not root); it asks for `sudo` for the system packages.

```bash
curl -fsSLO https://raw.githubusercontent.com/SereSChat/SereS/main/deploy/install.sh
bash install.sh --public-url https://beta.seres-chat.com --rp-id seres-chat.com
```

What it does (everything that is already there is kept):

1. installs Python 3 + venv, git and curl with `apt`
2. installs Node.js 22 with npm (NodeSource) if there is no Node.js 18 or newer, then `pm2`
3. clones SereS to `~/SereS` – or, if SereS is already there, updates it with `git pull`
   (changes made by hand, e.g. mail settings in `.env`, are kept)
4. creates `.venv` and installs `requirements.txt` and `gunicorn`
5. installs **coturn**, the TURN server for voice calls, and writes `/etc/turnserver.conf`
6. writes `ecosystem.config.js` (gunicorn with `--preload`, on `127.0.0.1` and `::1`, plus the
   TURN settings) and starts SereS with pm2
7. sets up `pm2 startup`, so SereS starts again after a reboot, and checks that it answers

| Option | Meaning |
| --- | --- |
| `--port` | Port SereS listens on, default `2222` |
| `--workers` | Number of gunicorn workers, default `4` |
| `--public-url` | Address of SereS, for the links in mails and for passkeys |
| `--rp-id` | Domain for passkeys, e.g. `seres-chat.com` (works for all subdomains) |
| `--turn-host` | Public address of the TURN server, default: the server's public IPv4 |
| `--no-turn` | Don't set up a TURN server |
| `--dir` | Where SereS is installed, default `~/SereS` |
| `--branch` | Git branch for a new download, default `main` |
| `--name` | Name in pm2, default `SereS` |
| `--no-pull` | Don't run `git pull` |
| `--no-ipv6` | Only listen on `127.0.0.1` |
| `--no-startup` | Don't start SereS automatically after a reboot |

**Update:** run `~/SereS/deploy/install.sh` again. It installs only what is missing (e.g. coturn
on a server set up before voice calls existed) and keeps the port, `--public-url`, `--rp-id` and
the TURN server from the last run.

### Voice calls: open the TURN ports

Calls go directly between the browsers. In some networks (mobile data, company Wi-Fi) that isn't
possible; then the audio goes through the TURN server, still encrypted end-to-end. It does **not**
go through the Cloudflare tunnel, so open these ports in your hoster's firewall (netcup: SCP →
server → Firewall) and in `ufw`, if you use it:

| Protocol | Port |
| --- | --- |
| TCP + UDP | `3478` |
| UDP | `49160-49200` |

The config only relays to the internet, never to this server or private networks.

---

# Server setup: e-mail for password resets

`setup-mailserver.sh` turns an Ubuntu 22.04 / 24.04 server into a **send-only** mail server for
SereS (Postfix + DKIM). It must run on the **same server as SereS**, because the mail server only
listens on `localhost` – nothing is opened to the internet.

You need: root access (`sudo`), a domain where you can edit DNS records, and the server's public
IPv4 address.

## 1. Update SereS on the server

```bash
cd /path/to/SereS            # where SereS is installed
git pull
source .venv/bin/activate
pip install -r requirements.txt   # new: webauthn (passkeys)
```

## 2. Run the script

```bash
sudo ./deploy/setup-mailserver.sh \
     --domain seres-chat.com \
     --public-url https://seres-chat.com \
     --seres-env /path/to/SereS/src/backend/.env \
     --test-to your.address@gmail.com
```

| Option | Meaning |
| --- | --- |
| `--domain` | Domain the mails come from (required) |
| `--hostname` | Name of the mail server, default `mail.<domain>` |
| `--from` | Sender, default `no-reply@<domain>` |
| `--public-url` | Address of SereS; used for the links in mails and for passkeys |
| `--seres-env` | Writes `SMTP_*`, `MAIL_FROM` and `PUBLIC_URL` into this `.env` |
| `--ip` | Public IPv4, if it is not detected correctly |
| `--test-to` | Sends a test mail to this address |

The script can be run again at any time (it keeps the DKIM key).

## 3. Create the DNS records

At the end the script prints a table like this – create exactly these records at your domain
provider (e.g. Cloudflare, IONOS, Strato, Namecheap):

| Type | Name | Value |
| --- | --- | --- |
| A | `mail.seres-chat.com` | server IP |
| TXT | `seres-chat.com` | `v=spf1 ip4:<server IP> -all` |
| TXT | `seres._domainkey.seres-chat.com` | `v=DKIM1; h=sha256; k=rsa; p=…` (long key) |
| TXT | `_dmarc.seres-chat.com` | `v=DMARC1; p=quarantine; adkim=s; aspf=s` |

If there already is an SPF record (`v=spf1 …`), don't add a second one – add `ip4:<server IP>`
to the existing one. With Cloudflare: set the A record for `mail.` to "DNS only" (grey cloud).

## 4. Settings at the server hoster

- **Reverse DNS (PTR):** set the server IP's reverse DNS to `mail.seres-chat.com`
  (Hetzner: Cloud Console → server → Networking; other hosters have a similar setting).
- **Port 25:** many hosters block outgoing port 25 for new servers (Hetzner, OVH, DigitalOcean, …).
  Request the unblock in the hoster's support form – without it no mail leaves the server.

## 5. Restart SereS and check

```bash
sudo systemctl restart seres      # or however SereS is started on your server
```

After the DNS changes are live (minutes up to a few hours):

```bash
dig +short TXT seres._domainkey.seres-chat.com    # shows the DKIM key
sudo opendkim-testkey -d seres-chat.com -s seres -vvv   # should end with "key OK"
echo "Test" | mail -s "SereS test" -r no-reply@seres-chat.com you@example.org
```

Then try it in SereS: login page → "Forgot password?" → "By e-mail". Check the spam folder the
first time. https://www.mail-tester.com rates the setup (aim for 9/10 or better).

## Troubleshooting

```bash
sudo journalctl -u postfix -n 50     # what happened to the last mails
mailq                                # mails still waiting
sudo postqueue -f                    # try sending waiting mails again
```

- `Connection timed out` to port 25 → the hoster still blocks port 25 (step 4).
- Mails land in spam → check SPF/DKIM/DMARC with mail-tester.com and the PTR record.
- The e-mail tab says "not set up" → `.env` misses `SMTP_HOST`, or SereS was not restarted.

## Without your own mail server

Any SMTP provider works too (Brevo, Mailjet, Postmark, your mail hoster). Then skip the script
and only put the provider's data into `src/backend/.env`:

```bash
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USER=your-login
SMTP_PASSWORD=your-smtp-key
MAIL_FROM="SereS <no-reply@seres-chat.com>"
PUBLIC_URL=https://seres-chat.com
```

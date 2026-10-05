# Running mjolnir as a service

## Windows

`mjolnir service` runs one long-running command as a Windows service: a
receiver, a tunnel server, or a tunnel client. The command goes after
`--` with its usual flags. It must be `recv --keep-listening`,
`tunnel-server`, or `tunnel --reconnect`; without those flags a receiver
would stop after one transfer and a client after one session.

The service runs as SYSTEM, so mjolnir must live where only
administrators can change it, and so must its key, its authorized-keys
file, and the folder a receiver writes into. In an elevated terminal
(Run as administrator), install mjolnir under Program Files:

```powershell
$env:MJOLNIR_INSTALL_DIR = "$env:ProgramFiles\mjolnir"
irm https://raw.githubusercontent.com/mrquantumoff/mjolnir/master/scripts/install.ps1 | iex
```

Then, in a new elevated terminal, write the key, allow the sender, and
install and start the service:

```powershell
mjolnir keygen --system --out $env:ProgramData\mjolnir\recv.key
Set-Content $env:ProgramData\mjolnir\senders.txt "<SENDER_PUBLIC_KEY>"
cd $env:ProgramData\mjolnir
mjolnir service install inbox -- recv --keep-listening --key recv.key `
    --authorized senders.txt --out incoming
mjolnir service start inbox
```

A tunnel server and a tunnel client install the same way:

```powershell
mjolnir service install relay -- tunnel-server --key server.key `
    --authorized clients.txt --permit-open db.internal:5432
mjolnir service install db -- tunnel relay.example:7778 --key client.key `
    --peer "<SERVER_PUBLIC_KEY>" -L 15432:db.internal:5432 --reconnect
```

A NAME is letters, digits, `-`, and `_`, and the service is
`mjolnir-NAME`, shown as `mjolnir NAME`. `install` parses the command the
same way the CLI does, so a typo fails at install rather than at start.
The service runs this binary from where it was installed, in the
directory `install` ran in, so relative paths such as `--key recv.key`
keep working. It starts at boot, or with `--manual` only on `mjolnir
service start NAME`. `install` does not start it.

`mjolnir service start NAME` and `stop NAME` start and stop it. `start`
waits until the service runs and watches it for 2 more seconds; one that
stops in that time is reported as failed, with its exit code and log
file. `status NAME` prints its state, its PID while it runs, the
command, and the log file. `uninstall NAME` stops it if it runs, then
removes it. Install, uninstall, start, and stop need an elevated
terminal and fail with "access denied" without one. `status` works from
any terminal. An `install` that fails partway leaves no service behind.

The service runs as LocalSystem, so it reads keys and writes files as
SYSTEM. Received files take the access list of their `--out` directory.
`install` refuses, and the service refuses again each time it starts,
when an account other than SYSTEM, Administrators, and TrustedInstaller
can change the mjolnir binary or its folder, the key, the
authorized-keys file, or a receiver's `--out` folder (or, if it does not
exist yet, the nearest folder above it), or can replace one of them
through a folder above it. When a folder above one of them is a junction
or another link, the folders it leads to are checked too. A receiver
writing as SYSTEM into a folder others can change would follow links
they plant there. The check covers `--out` itself, not the folders under
it, so do not grant other accounts write access anywhere under a
service's `--out`. A subfolder they can change could be swapped for a
junction that sends the receiver's writes elsewhere. The error names
those accounts. A folder made under `%ProgramData%\mjolnir` passes; one
made elsewhere usually inherits write access for Users and needs the
`icacls` command the error prints. `keygen --system` writes a key that
passes, and creates its folder the same way if it is missing; read the
key with `mjolnir pubkey` from an elevated terminal. A key `keygen`
wrote without `--system` also grants your account, so `install` refuses
it and names the `icacls` command that would fix it.

Stderr goes to `%ProgramData%\mjolnir\NAME.log`, or to the file `--log
PATH` names. `install` creates a missing log folder owned by
Administrators, with full control for SYSTEM and Administrators, read
access for Users, and nothing inherited. It refuses a log folder that
another account can change or add files to, an existing log file another
account can change, and a log path that is a link. The service checks
again each time it starts. Each line starts with a UTC timestamp, and the file is appended to
across restarts. It holds the start lines, a summary per transfer,
failed handshakes and sessions, and why the service stopped, but no
per-second progress lines.

`stop` ends the command the way Ctrl-C ends a tunnel: streams reset the
connections they carried. A receiver cancels its transfer, which resumes
from staging when the sender retries. When the command fails on its own,
for example because its port is taken or a client's first session fails,
the service stops with an error and the service manager starts it again
10 seconds later. It does this up to 3 times. After a fourth failure the
service stays stopped until you start it, and the count starts over after
a day without a failure. A stop you ask for is not a failure.

## Linux

Linux needs no subcommand: systemd runs the same commands. Save a unit
such as `/etc/systemd/system/mjolnir-inbox.service` and run `systemctl
enable --now mjolnir-inbox`:

```ini
[Unit]
Description=mjolnir inbox
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mjolnir recv --keep-listening --key /etc/mjolnir/recv.key --authorized /etc/mjolnir/senders.txt --out /srv/incoming
Restart=on-failure
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
```

`KillSignal=SIGINT` makes `systemctl stop` act as Ctrl-C does, so a
tunnel resets its streams' connections instead of closing them as if
they had ended.

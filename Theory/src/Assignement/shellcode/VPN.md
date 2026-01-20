# BASC VPN

## Set up

To set up the VPN connection, you will need:

1. [Install WireGuard](https://www.wireguard.com/install/); in the suggested
   configuration, this simply means to execute: `sudo apt install wireguard`
2. Download your personal configuration file; for this step, we use GitHub,
   via OAUTH, for authentication, so you'll need to login there (and be in
   our GitHub classroom, of course):
   [Get your configuration file](https://bart.disi.unige.it/basc2025)

The configuration file is an ASCII file; open it and take a look.
In the first lines, beginning with `#`, you'll find some important information:

- Your IP address inside the VPN; this address is strictly personal and cannot be changed (if you do, you won't be able to make any connection inside the VPN).
- Your base port number, say *n*. Your services (examples/exercises) will listen to TCP ports: *n*, *n+1*, *n+2*, up to *n+19*.
  Don't worry: we'll not use all of them.
- Instructions on how to bring up/down the VPN connection.

## Connection verification

To activate the VPN connection execute: `sudo wg-quick up ./<your-conf-file>`

If you get an error like
`wg-quick: The config file must be a valid interface name, followed by .conf`,
then try renaming your config file to a short name with no special characters
(e.g. `basc_vpn.conf`).

Beware that connecting to our VPN, **inside Unige Wifi, works on Eduroam only**; that is, the VPN does not work on Genuawifi (because almost all ports are blocked on that network).

Once the VPN is up, you should be able to:

- ping the server: `ping -c 3 192.168.20.1`
- connect to your base port and get a greeting message: `nc -v 192.168.20.1 <your-base-port>`

  Note: I'll bring this "hello service" down in a couple of weeks

Inside our VPN you can only connect to your port-range on the server; no other connections are allowed.

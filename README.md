# vyatta-ipsec-trapd

This repo contains the scripts (including sysvinit), and the MIB, for
providing IPsec traps on SA transitioned based on
Netlink XFRM messages.

## Requirements

This package requires `Net::SNMP`, `IO::Interface::Simple`, and `File::Slurp`
as well as Perl 5.12 or later.

## Configuration

No configuration is explicitly required: if SNMP is configured with one or
more trap-targets and an SNMP description, that's sufficient to enable this
service.

## Using

This service is started at boot-time, but it may be explicitly launched as:

```
sudo service ipsec-trapd start
```

from the CLI, following any SNMP configuration changes.

# palo-check-cert-expiry

Check Palo Alto Certificate Expiry by API

## Bash script

Written to align with Linux/Bash-based certificate management scripts.

This script has the following defaults:

- Retrieve certificates expiring within 30 days (adjustable via config file).
- Palo Alto AKI_KEY read from `/etc/ipn/.panrc`, use `-k` flag or set in config file.

Command line usage: 

```text
This script checks whether any certificates will expire within x days on a Palo Alto firewall
or Panorama.

Either of the following must be provided:
    FQDN              Fully qualified name of the Palo Alto firewall or Panorama
                      interface. It must be reachable from this host on port TCP/443.
                      If omitted, one or more firewalls can be parsed in a config file.
    PATH              Path to config file.

OPTIONS:
    -k key(path|ext)  API key file location or extension. Default: /etc/ipa/.panrc
                      If a string is parsed, the following paths are searched:
                      {key(path)}/.panrc         - Example: /etc/panos/fw1.local/.panrc
                      /etc/ipa/.panrc.{key(ext)} - Example: /etc/ipa/,panrc.fw1.local
    -t days           Threshold in number of days. (default: 30)

    -h                Display this help and exit.
    -v                Verbose mode.
```

And can also read the following from a configuration file: 

- `host=`               Firewall or Panorama hostname or IP address. 
- `api_key=`            API key for Palo Alto firewall or Panorama access.
- `crt_name_filter=`    Certificate name filter string.
- `alert_after_days=`   Alert on certificates expiring within x days.
- `email_enable=`       Enable email notification (boolean yes/true, everything else=false).
- `email_to=`           Send email to one or more addresses (comma- or space-separated)
- `email_body_header=`  Email body header. Default: "Dear recipient,\n\nPlease check if the following certificates are still required. Renew if required, or delete if no longer in use:\n"
- `email_body_footer=`  Email body footer. Default: "\n-- \nRegards,\n$(hostname)"
- `email_from=`         Sender address. Default: "${0##*/} <$(id -un)@$(hostname)>"

⚠️ Note that config file options allow parsing of commands and system variables to this script, use with caution! ⚠️

## Required Palo Alto API_KEY privileges

- Web UI: None
- XML API: Only Configuration
- Command Line: None
- REST API: None

## Original Python code

Update the firewall endpoints with your production firewall IPs or hostnames within the prod dictionary and test firewalls in the test dictionary. << change to config file

When testing, you can easily switch between them by changing the reference firewall endpoints. << correct sentence

The machine running the operation can either use a local postfix relay or send directly to another relay by modifying the 'smtp_server' variable.

The script will send an email if any certificates are expiring within the next 30 days, but this can be adjusted in the check_expiring_certs function to a time range of your choice. << change setting to config file and read from parameter input

I've used this method to load env. variables: 
https://ip-life.net/loading-environment-variables-in-a-cron-job/

Utilises a bash helper script to start the Python code.

A cron job should be defined to dictate how frequently the check runs: 

```
20 6 * * 1-5 BASH_ENV=/path/to/.python_profile /path/to/scripts/palo-alto/check-certs.sh
```

Of course, the firewalls must allow API access to the user running the scripts and the machine IP to access the API.

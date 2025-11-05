#!/bin/bash

# Check Certs on Palo Alto Firewalls and alert if nearing expiry date

## Fixed variables
# Reuse pan_instcert API key
API_KEY="/etc/ipa/.panrc"
# Filter for selecting certificates to report on
CRT_FLT="_vpn"
# Alert threshold in days
THRESHOLD_DAYS=30
# Script vars
VERBOSE=0
OPTIND=1

## Logging
LOG="/var/log/pan_ckh_certs.log"
wlog() {
    printf "$*"
    printf "[$(date --rfc-3339=seconds)]: $*" >> "$LOG"
}
trap 'wlog "ERROR - Certificate check failed.\n"' TERM HUP

## Usage info
show_help() {
cat << EOF
Usage: ${0##*/} [-hv] [OPTIONS] FQDN/PATH
This script checks whether any certificates are about to expire on a Palo Alto firewall
or Panorama. Optionally, the expiry date of an individual certificate can be checked.

Either of the following must be provided:
    FQDN              Fully qualified name of the Palo Alto firewall or Panorama
                      interface. It must be reachable from this host on port TCP/443.
                      If omitted, one or more firewalls can be parsed in a config file.
    PATH              Path to config file.

OPTIONS:
    -c CERT_CN        Common Name (Subject) of the certificate to be checked.
    -n CERT_NAME      Name of the certificate in PanOS configuration. Defaults to the
                      certificate Common Name.
    -k key(path|ext)  API key file location or extension.

    -h                Display this help and exit.
    -v                Verbose mode.
EOF
}

## Read/interpret optional arguments
while getopts c:n:Yp:s:k:C:K:vh opt; do
    case $opt in
        c)  CERT_CN=$OPTARG
            ;;
        n)  CERT_NAME=$OPTARG
            ;;
        k)  API_KEY=$OPTARG
            ;;
        v)  VERBOSE=$((VERBOSE+1))
            ;;
        h)  show_help
            exit 0
            ;;
        *)  show_help >&2
            exit 1
            ;;
    esac
done
shift "$((OPTIND-1))"   # Discard the options and sentinel --

## Check if run as root
if [ "$EUID" -ne 0 ]; then
    echo "We have root"
    root=true
fi

## Start logging
wlog "START of pan_chk_certs.\n"

# Check whether a file path or a single valid FQDN was parsed for the Palo Alto API interface
CFG_FILE=""
declare -a PAN_MGMT
if [[ -f "$@" ]]; then
    #(( $VERBOSE > 0 )) && wlog "File exists: $@\n"
    if [[ -r "$@" ]]; then
        CFG_FILE="$@"
        (( $VERBOSE > 0 )) && wlog "CFG_FILE: $CFG_FILE\n"
    else
        wlog "ERROR: File cannot be read: $@\n"
        exit 4
    fi        
elif grep -q -P '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$)' <<< "$@"; then
    HOST="${@,,}"
    (( $VERBOSE > 0 )) && wlog "PAN_FQDN: $HOST\n"
    if ! nc -z $HOST 443 2>/dev/null; then
        wlog "ERROR: Palo Alto device unreachable at: https://$HOST/\n"
        exit 4
    fi
    PAN_MGMT+=("$HOST")
else
    wlog "ERROR: A valid PATH or FQDN is required to check certificates.\n"
    wlog "Parsed string: $@\n\n"
    show_help >&2
    exit 4
fi

# Use parsed API key if given
if [[ "$API_KEY" != "/etc/ipa/.panrc" ]]; then
    if [ -d "API_KEY" ]; then
        # Parsed string is a directory
        API_KEY="${API_KEY}/.panrc"
    elif [[ "$API_KEY" != *\/* ]]; then
        # Parsed string is a file extension
        API_KEY="/etc/ipa/.panrc.$API_KEY"
    fi
    if [ -f "$API_KEY" ]; then
        wlog "Parsed API key file exists: $API_KEY\n"
    else
        wlog "ERROR: Parsed API key file doesn't exist: $API_KEY\n"
        show_help >&2
        exit 1
    fi
fi 

# Try to read API_KEY
if grep -q -P '^api_key=' "$API_KEY"; then
    (( $VERBOSE > 0 )) && wlog "API key found in: $API_KEY\n"
    # Commit the cardinal sin of changing the type of the variable from file-path to string.
    API_KEY=$(grep -P '^api_key=' "$API_KEY")
    API_KEY="${API_KEY#api_key=}"
fi

# Read config file
if [ -n $CFG_FILE ]; then
    # Verify one or more hostnames are included in the config file
    if ! grep -q -P '^hosts=' "$CFG_FILE"; then
        wlog "ERROR: Missing 'hosts=' entry in in: $CFG_FILE\n"
        exit 5
    else
        (( $VERBOSE > 0 )) && wlog "One or more hosts found in: $CFG_FILE\n"
        HOSTS=$(grep -P '^hosts=' "$CFG_FILE")
        HOSTS="${HOSTS#hosts=}"
        # Accept comma and space-separated input, and convert to an array for looping
        PAN_MGMT=(${HOSTS//,/ })
    fi
    # Try to read API key from config file if one isn't parsed
    if grep -q -P '^api_key=' "$CFG_FILE"; then
        (( $VERBOSE > 0 )) && wlog "API key found in: $CFG_FILE\n"
        API_KEY=$(grep -P '^api_key=' "$CFG_FILE")
        API_KEY="${API_KEY#api_key=}"
    fi
    # Try to read certificate name filter string from config file
    if grep -q -P '^crt_name_filter=' "$CFG_FILE"; then
        CRT_FLT=$(grep -P '^crt_name_filter=' "$CFG_FILE")
        CRT_FLT="${CRT_FLT#crt_name_filter=}"
        (( $VERBOSE > 0 )) && wlog "Certificate name filter \"$CRT_FLT\" found in: $CFG_FILE\n"
    fi
    # GTry to read alerting threshold from config file
    if grep -q -P '^alert_after_days=' "$CFG_FILE"; then
        THRESHOLD_DAYS=$(grep -P '^alert_after_days=' "$CFG_FILE")
        THRESHOLD_DAYS="${THRESHOLD_DAYS#crt_name_filter=}"
        (( $VERBOSE > 0 )) && wlog "Certificate expiry threshold set to $THRESHOLD_DAYS days\n"
    fi
fi

# Sanity check, at least one host must be known
if [ ${PAN_MGMT[@]} -eq 0 ]; then
    wlog "ERROR: No hosts found, terminating.\n"
    exit 1
fi
if [[ "$API_KEY" == "/etc/ipa/.panrc" ]]; then
    wlog "ERROR: No API key found. Parse option '-k', check the config file or $API_KEY\n"
    exit 5
fi

## Requirements
# Installed packages: openssl, pan-python, xmllint (libxml2-utils)

## CURL
OUTPUT=$(curl -k --form file=@$TEMP_PFX "https://$PAN_MGMT/api/?type=import&category=certificate&certificate-name=$CERT_NAME&format=pkcs12&passphrase=$TEMP_PWD&key=$API_KEY" && echo " ")
CRT_STATUS=$?
wlog "XML API output for crt: $OUTPUT\n"
if [ $CRT_STATUS -eq 0 ]; then
    OUTPUT=$(curl -k --form file=@$TEMP_PFX "https://$PAN_MGMT/api/?type=import&category=private-key&certificate-name=$CERT_NAME&format=pkcs12&passphrase=$TEMP_PWD&key=$API_KEY" && echo " ")
    KEY_STATUS=$?
    wlog "XML API output for key: $OUTPUT\n"
    if [ $KEY_STATUS -eq 0 ]; then
        wlog "Finished uploading certificate: $CERT_NAME\n"
    elif [ $KEY_STATUS -ne 0 ]; then
        wlog "ERROR: Upload of key failed.\n"
        exit 12
    fi
else
    wlog "ERROR: Upload of certificate failed.\n"
    exit 12
fi

## Fetch certificate expiry dates using panxapi.py
# Filter by certificate name
XML_DATA=$(/usr/local/bin/panxapi.py -h $PAN_MGMT -K $API_KEY -gx "/config/shared/certificate/entry[contains(@name, '$CRT_FLT' )]" 2>&1)

# Or filter by issuer:
#   Example issuer XML: <issuer>/O=ORG/CN=ORG GP CA</issuer>
#   Then use this filter: CRT_FLT="ORG GP CA"
#XML_DATA=$(/usr/local/bin/panxapi.py -h $PAN_MGMT -K $API_KEY -gx "/config/shared/certificate/entry[contains(issuer, '$CRT_FLT' )]" 2>&1)

# Sanity check returned data
if [ $? -ne 0 ] || [ -z "$XML_DATA" ]; then
    wlog "ERROR: Failed to fetch data or no certificates found.\n"
    exit 1
elif [[ $(echo "$XML_DATA" | head -n1) != 'get: success [code="19"]' ]] || [ $(echo "$XML_DATA" | wc -l) -eq 1 ]; then
    wlog "Failed to fetch data or no certificates found. panxapi.py returned: $(echo "$XML_DATA" | head -n1)\n"
    exit 1
elif [[ $(echo "$XML_DATA" | head -n1) == 'get: success [code="19"]' ]]; then
    (( $VERBOSE > 0 )) && wlog "API query ok.\n"
    XML_DATA=$(echo "$XML_DATA" | tail -n +2)
fi

## Build arrays using xmllint
# Extract names into an array, use sed to clean the output of xmllint for mapfile.
mapfile -t CERT_NAMES < <(echo "$XML_DATA" | xmllint --xpath "//entry/@name" - 2>/dev/null | sed 's/ name=/\n/g; s/"//g' | grep -v '^$')
# Extract expiry-epoch values into another array
mapfile -t EXPIRY_EPOCHS < <(echo "$XML_DATA" | xmllint --xpath "//expiry-epoch/text()" - 2>/dev/null)

## Calculate nn-day notification threshold
# Calculate the epoch timestamp for n days from now
THRESHOLD_SEC=$((THRESHOLD_DAYS * 86400))
NOW=$(date +%s)
THRESHOLD_EPOCH=$((NOW + THRESHOLD_SEC))

wlog "Found the following certificates expiring within $THRESHOLD_DAYS days (before $(date -d "@$THRESHOLD_EPOCH")).\n"

# --- 4. Filter and Output Results ---

FILTERED_NAMES=()
FILTERED_DATES=()

# Iterate through the array indices
for i in "${!CERT_NAMES[@]}"; do
    NAME="${CERT_NAMES[$i]}"
    EXPIRY_EPOCH="${EXPIRY_EPOCHS[$i]}"

    # Check if the certificate epoch time is less than our 30-day threshold
    if [[ "$EXPIRY_EPOCH" -lt "$EXPIRY_THRESHOLD" ]]; then
        # Convert epoch back to a human-readable date for display
        HUMAN_DATE=$(date -d "@$EXPIRY_EPOCH")
        
        # Add to filtered arrays
        FILTERED_NAMES+=("$NAME")
        FILTERED_DATES+=("$HUMAN_DATE")
    fi
done

# --- 5. Display the filtered results ---
if [ ${#FILTERED_NAMES[@]} -eq 0 ]; then
    echo "No certificates found expiring within the next 30 days."
else
    for i in "${!FILTERED_NAMES[@]}"; do
        echo "ALERT: ${FILTERED_NAMES[$i]} expires on ${FILTERED_DATES[$i]}"
    done
fi






# Extract certificate names to array
mapfile -t CERT_NAMES < <(echo "$JSON_DATA" | jq -r '.[].name')

# Extract certificate expiry to array
mapfile -t EXPIRY_EPOCH < <(echo "$JSON_DATA" | jq -r '.[].expiry-epoch')

if [[ ! -z $SSL_TLS_PROFILE_1 ]]; then
    RESULT=$(/usr/local/bin/panxapi.py -h $PAN_MGMT -K $API_KEY -S "<certificate>$CERT_NAME</certificate>" "/config/shared/ssl-tls-service-profile/entry[@name='$SSL_TLS_PROFILE_1']" 2>&1)
    (( $VERBOSE > 0 )) && wlog "$RESULT\n"
    if [[ "$RESULT" =~ (command succeeded) ]]; then
        PROFILES=$SSL_TLS_PROFILE_1
        wlog "Successfully updated SSL/TLS Profile $SSL_TLS_PROFILE_1\n"
    else
        wlog "ERROR: Update of SSL/TLS Profile $SSL_TLS_PROFILE_1 failed.\n"
    fi
    if [[ ! -z $SSL_TLS_PROFILE_2 ]]; then
        RESULT=$(/usr/local/bin/panxapi.py -h $PAN_MGMT -K $API_KEY -S "<certificate>$CERT_NAME</certificate>" "/config/shared/ssl-tls-service-profile/entry[@name='$SSL_TLS_PROFILE_2']" 2>&1)
        (( $VERBOSE > 0 )) && wlog "$RESULT\n"
        if [[ "$RESULT" =~ (command succeeded) ]]; then
            PROFILES="$PROFILES $SSL_TLS_PROFILE_2"
            wlog "Successfully updated SSL/TLS Profile $SSL_TLS_PROFILE_2\n"
        else
            wlog "ERROR: Update of SSL/TLS Profile $SSL_TLS_PROFILE_2 failed.\n"
        fi
    fi
fi




from datetime import datetime
from panos.firewall import Firewall
import paloalto
import smtplib

# Firewall hosts
firewall_endpoints = {
    'prod': [
        'prod.firewall.1',
        'prod.firewall.2',
        'prod.firewall.3',
        'prod.firewall.4',
        'prod.firewall.5'
        ],
    'test': [
        'test.firewall.1'
        ]
    }
firewall_hosts = firewall_endpoints['prod']  # Select firewall endpoints

# List containers
db_name = []
db_exp_date = []

# Counter
counter = 0

# Fetch todays date
today = datetime.now()

# Send mail using local postfix
port = 25
smtp_server = "localhost"
sender_email = "Python@somedomain.com"
receiver_email = "some.recipient@somedomain.com"
message = """\
From: {sender}
Subject: Palo Alto Certificate Warning
Date: {date}
To: {recipient}

There are {count} certificates nearing expiry!
Please check all production Palo Alto firewalls
for certificates nearing expiration.
Palo Alto Primary Firewalls:
{firewall}

Certs nearing expiry:
{certs}

This message has been sent from Python."""


# Create datetime object from string
def get_datetime_object(dt_string):
    """
    Return datetime object from string

    """
    dt_object = datetime.strptime(dt_string, '%b %d %H:%M:%S %Y %Z')
    return dt_object


def check_expiring_certs(indict):
    """
    Check if certs on the firewall are nearing expiry within 30 days

    """
    global counter
    cert_names = []
    for k, v in indict.items():
        diff = get_datetime_object(k[k.find("(")+1:k.find(")")]) - today
        if diff.days <= 30:  # Expiry within days (30 standard)
            counter = counter + 1
            cert_names.append(v)
    return cert_names


for i in firewall_hosts:
    while True:
        try:
            fw = Firewall(i, api_key=paloalto.return_token())
            raw_data = fw.op('show sslmgr-store config-certificate-info')
            data = raw_data.find('.//result')
            cert_list = data.text.splitlines()
            break
        except Exception as e:
            print(i, e)

# Create Cert lists
for cert in cert_list:
    if 'db-exp-date' in cert:
        db_exp_date.append(cert.strip())
    elif 'db-name' in cert:
        db_name.append(cert.strip())

# Create Cert Dictionary
cert_dict = dict(zip(db_exp_date, db_name))

# Run function
expiring_cert_list = check_expiring_certs(cert_dict)

# Transform to set
expiring_cert_set = set(expiring_cert_list)

# Send an email if expiry is nearing 30 days
if counter >= 1:
    print('There are {0} certificates nearing expiry!'.format(counter))
    try:
        server = smtplib.SMTP(smtp_server, port)
        server.ehlo()  # Can be omitted
        server.sendmail(
            sender_email,
            receiver_email,
            message.format(
                sender=sender_email,
                date=today,
                recipient=receiver_email,
                count=counter,
                firewall='\n'.join(firewall_hosts),
                certs='\n'.join(expiring_cert_set)
                )
            )
    except Exception as e:
        # Print any error messages to stdout
        print(e)
    finally:
        server.quit()

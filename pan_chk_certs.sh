#!/bin/bash
# Check Certs on Palo Alto Firewalls and alert if nearing expiry date

## Requirements
# Installed packages: openssl, pan-python, xmllint (libxml2-utils)

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
    -k key(path|ext)  API key file location or extension.

    -h                Display this help and exit.
    -v                Verbose mode.
EOF
}

## Read/interpret optional arguments
while getopts c:n:Yp:s:k:C:K:vh opt; do
    case $opt in
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
    wlog "ERROR: A valid configuration file (PATH) or FQDN is required to check certificates.\n"
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
    # Try to read alerting threshold from config file
    if grep -q -P '^alert_after_days=' "$CFG_FILE"; then
        THRESHOLD_DAYS=$(grep -P '^alert_after_days=' "$CFG_FILE")
        THRESHOLD_DAYS="${THRESHOLD_DAYS#crt_name_filter=}"
        (( $VERBOSE > 0 )) && wlog "Certificate expiry threshold set to $THRESHOLD_DAYS days\n"
    fi
    # Try to read send_email boolean flag from config file (yes/no)
    if grep -q -P '^email_enable=' "$CFG_FILE"; then
        EMAIL=$(grep -P '^email_enable=' "$CFG_FILE")
        [[ "$EMAIL" == "true" ]] && EMAIL="yes"
        (( $VERBOSE > 0 )) && wlog "email_enable=$EMAIL read from: $CFG_FILE\n"
    fi
    # Try to read email body header from config file
    if grep -q -P '^email_body_header=' "$CFG_FILE"; then
        BODY_HEADER=$(grep -P '^email_body_header=' "$CFG_FILE")
        (( $VERBOSE > 0 )) && wlog "email_body_header read from: $CFG_FILE\n"
    fi
    # Try to read email body footer from config file
    if grep -q -P '^email_body_footer=' "$CFG_FILE"; then
        BODY_FOOTER=$(grep -P '^email_body_footer=' "$CFG_FILE")
        (( $VERBOSE > 0 )) && wlog "email_body_footer read from: $CFG_FILE\n"
    fi
    # Try to read email body footer from config file
    if grep -q -P '^email_from=' "$CFG_FILE"; then
        EMAIL_SENDER=$(grep -P '^email_from=' "$CFG_FILE")
        (( $VERBOSE > 0 )) && wlog "email_from=$EMAIL_SENDER setting read from: $CFG_FILE\n"
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

## Fetch certificate expiry dates using panxapi.py

# Filter by certificate name:
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

## Filter results
(( $VERBOSE > 0 )) && wlog "Found these certificates expiring within $THRESHOLD_DAYS days (before $(date -d "@$THRESHOLD_EPOCH")).\n"

FILTERED_NAMES=()
FILTERED_DATES=()
# Iterate through the array indices
for i in "${!CERT_NAMES[@]}"; do
    NAME="${CERT_NAMES[$i]}"
    EXPIRY_EPOCH="${EXPIRY_EPOCHS[$i]}"
    # Check if the certificate epoch time is less than the set threshold
    if [[ "$EXPIRY_EPOCH" -lt "$EXPIRY_THRESHOLD" ]]; then
        # Convert epoch back to a human-readable date for display
        HUMAN_DATE=$(date -d "@$EXPIRY_EPOCH")
        # Add to filtered arrays
        FILTERED_NAMES+=("$NAME")
        FILTERED_DATES+=("$HUMAN_DATE")
        (( $VERBOSE > 0 )) && wlog " - $NAME expires on $HUMAN_DATE.\n"
    fi
done

# Log the filtered results
if [ ${#FILTERED_NAMES[@]} -eq 0 ]; then
    wlog "No certificates found expiring within the next $THRESHOLD_DAYS days.\n"
fi

#    for i in "${!FILTERED_NAMES[@]}"; do
#        echo "ALERT: ${FILTERED_NAMES[$i]} expires on ${FILTERED_DATES[$i]}"
#    done

# Set defaults in case not parsed or missing from config
: ${EMAIL:="yes"}
: ${BODY_HEADER:="Dear recipient,\n\nPlease check if the following certificates are still required. Renew if required, or delete if no longer in use:\n"}
: ${BODY_FOOTER:="\n-- \nRegards,\n$(hostname)"}
: ${SENDER:="pan_chk_certs.sh <$(id -un)@$(hostname)>"}

# Test if at least one email address is configured if the send flag is set
if [[ "$EMAIL" == "yes" ]]; then
    if [ ${#TO[@]} -eq 0 ]; then
        wlog "ERROR: No email address(es) found in config file: $CNF\n"
        exit 1
    fi
    SEND_TO=()
    for i in "${!TO[@]}"; do
        # Grab the base address if 'pretty' formatting is given.
        addr=$(echo "${TO[$i]}" | cut -d "<" -f2 | cut -d ">" -f1)
        if [[ "$addr" =~ ^.+@.+\.[[:alpha:]]{2,}$ ]]; then
            # Test if the domain has an MX record
            if host -t MX ${addr##*@} &> /dev/null; then
                # Found an MX record, use it.
                SEND_TO+=($addr)
            else
                # Ignore invalid addresses
                wlog "WARNING: No MX record found for $addr, skipping this email address.\n"
            fi
        else
            wlog "WARNING: $addr is not a valid email address.\n"
        fi
    done
    if [ ${#SEND_TO[@]} -eq 0 ]; then
        wlog "ERROR: No valid email addresses found in configuration file: $CNF\n"
        wlog "WARNING: No email will be sent.\n"
        #SEND="no"
    else
        # Set the email subject line
        SUBJECT="ALERT: Expired firewall certificates found."

        ## Compile the email body
        BODY=""
        # Find the length of the longest element in the array
        max=1
        for i in "${FILTERED_NAMES[@]}"; do
            len=${#i}
            ((len > max)) && max=$len
        done
        # add a 2 character wide spacing
        max=$((max+2))
        # Get the number of elements in the array
        items=${#FILTERED_NAMES[@]}
        # Iterate through the indices (0 to num_items-1)
        for ((i=0; i<$num_items; i++)); do
            # Format the current line using printf and append it to the variable
            # %-10s formats a left-aligned string in a 10-char width column
            line=$(printf "%-${max}s - expires on: %s\n" "${column1_data[i]}" "${column2_data[i]}")
            BODY+="$line"
        done

        # Send the email
        printf "$BODY_HEADER\n\n$BODY\n\n$BODY_FOOTER\n" | s-nail -s "$SUBJECT" -r "$SENDER" "${SEND_TO[@]}"
        wlog "Email sent to: ${SEND_TO[@]}\n"
    fi
fi

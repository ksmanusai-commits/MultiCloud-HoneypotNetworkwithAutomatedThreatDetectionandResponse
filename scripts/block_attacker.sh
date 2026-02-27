manohar@gcp-logserver:/opt/splunk/bin/scripts$ cat block_attacker.sh
#!/bin/bash
# block_attacker.sh - read TSV of IP<TAB>Cloud and block on clouds
# Uses single Azure scalable rule AutoBlockedIPs-Honeypot (no per-IP rules)

set -euo pipefail

LOG_FILE="/var/log/block_attacker.alert.log"
EXPORT_FILE="/var/tmp/opencanary/opencanary_export.tsv"
: "${DRY_RUN:=0}"

mkdir -p "$(dirname "$EXPORT_FILE")"

log() {
  printf "[%s] [blocker] %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG_FILE"
}

# Load configs if present
if [[ -r /etc/auto-block.conf ]]; then
  set -a; . /etc/auto-block.conf; set +a
  log "Loaded /etc/auto-block.conf"
else
  log "No /etc/auto-block.conf - continuing with env vars"
fi

# helper: retry with simple backoff
retry() {
  local n=0 max=3 delay=2
  until "$@"; do
    n=$((n+1))
    if [[ $n -ge $max ]]; then return 1; fi
    sleep $delay
    delay=$((delay * 2))
  done
  return 0
}

AWS_BIN="$(command -v aws || true)"
AZ_BIN="$(command -v az || true)"
GCLOUD_BIN="$(command -v gcloud || true)"

log "CLI checks: aws=${AWS_BIN:-no}, az=${AZ_BIN:-no}, gcloud=${GCLOUD_BIN:-no}"

# ---------- Azure helper: ensure AutoBlockedIPs-Honeypot exists and contains a prefix ----------
azure_ensure_and_append() {
  local IP="$1"
  local RULE_NAME="AutoBlockedIPs-Honeypot"
  local NEW_IP_PREFIX="${IP}/32"

  # try to login if needed (service principal supported)
  if ! az account show >/dev/null 2>&1; then
    if [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_CLIENT_SECRET:-}" && -n "${AZURE_TENANT_ID:-}" ]]; then
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 || true
      [[ -n "${AZURE_SUBSCRIPTION_ID:-}" ]] && az account set --subscription "$AZURE_SUBSCRIPTION_ID" >/dev/null 2>&1 || true
    fi
  fi

  # gather existing prefixes (handles single or plural fields)
  existing_ips="$(az network nsg rule show -g "$AZURE_RG" --nsg-name "$AZURE_NSG" --name "$RULE_NAME" -o json 2>/dev/null \
    | jq -r '(.sourceAddressPrefixes[]? // .sourceAddressPrefix?)' 2>/dev/null || true)"

  # if rule missing or no prefixes, attempt creation (try configured priority then fallbacks)
  if [[ -z "$existing_ips" ]]; then
    try_prios=()
    if [[ -n "${AZURE_RULE_PRIORITY:-}" ]]; then try_prios+=("$AZURE_RULE_PRIORITY"); fi
    try_prios+=(3500 4000 4500 5000)

    for p in "${try_prios[@]}"; do
      if az network nsg rule create -g "$AZURE_RG" --nsg-name "$AZURE_NSG" \
         --name "$RULE_NAME" --priority "$p" --direction Inbound --access Deny --protocol "*" \
         --source-address-prefixes "$NEW_IP_PREFIX" --description "Auto-blocked IPs from OpenCanary" --only-show-errors >/dev/null 2>&1; then
        log "[Azure] Created ${RULE_NAME} priority=${p} with ${NEW_IP_PREFIX}"
        existing_ips="$NEW_IP_PREFIX"
        break
      else
        err=$(az network nsg rule create -g "$AZURE_RG" --nsg-name "$AZURE_NSG" \
          --name "$RULE_NAME" --priority "$p" --direction Inbound --access Deny --protocol "*" \
          --source-address-prefixes "$NEW_IP_PREFIX" --description "Auto-blocked IPs from OpenCanary" 2>&1 || true)
        if echo "$err" | grep -qi "SecurityRuleConflict"; then
          log "[Azure] priority $p in use (SecurityRuleConflict), trying next"
          continue
        else
          log "[Azure] Error creating ${RULE_NAME} at priority $p: $(echo "$err" | tail -n 1)"
        fi
      fi
    done
  fi

  # refresh existing_ips after possible create
  existing_ips="$(az network nsg rule show -g "$AZURE_RG" --nsg-name "$AZURE_NSG" --name "$RULE_NAME" -o json 2>/dev/null \
    | jq -r '(.sourceAddressPrefixes[]? // .sourceAddressPrefix?)' 2>/dev/null || true)"

  # if prefix already present, skip
  if echo "$existing_ips" | grep -xq "${NEW_IP_PREFIX}"; then
    log "[Azure] ${IP} already present in '${RULE_NAME}', skipping"
    return 0
  fi

  # append and dedupe
  merged=$(printf "%s\n%s\n" "$existing_ips" "$NEW_IP_PREFIX" | sed '/^$/d' | sort -u | tr '\n' ' ')
  if [[ -n "$merged" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      log "[Azure] (dry-run) Would update ${RULE_NAME} to: $merged"
    else
      if az network nsg rule update -g "$AZURE_RG" --nsg-name "$AZURE_NSG" --name "$RULE_NAME" --source-address-prefixes $merged --only-show-errors >/dev/null 2>&1; then
        log "[Azure] OK: ${IP}/32 appended to ${RULE_NAME}"
      else
        log "[Azure] ERROR: Failed to update '${RULE_NAME}' with ${IP}"
      fi
    fi
  fi
}

# Validate EXPORT_FILE exists
if [[ ! -r "$EXPORT_FILE" ]]; then
  log "ERROR: export file not found or unreadable: $EXPORT_FILE"
  exit 1
fi

while IFS=$'\t' read -r IP CLOUD; do
  [[ -z "$IP" ]] && continue
  log "Processing $IP (seen_in=$CLOUD)"

  ##########################
  # AWS - prefix list method (requires AWS access)
  ##########################
  if [[ -n "${AWS_PL_ID:-}" && -n "${AWS_REGION:-}" && -n "$AWS_BIN" ]]; then
    if ! "$AWS_BIN" sts get-caller-identity --output text >/dev/null 2>&1; then
      log "[AWS] ERROR: AWS credentials not available for the runtime user. Please configure AWS credentials or attach an instance role."
    else
      if "$AWS_BIN" ec2 get-managed-prefix-list-entries \
        --region "$AWS_REGION" --prefix-list-id "$AWS_PL_ID" \
        --query "Entries[?Cidr=='$IP/32']" --output text | grep -q "$IP"; then
        log "[AWS] $IP already blocked, skipping"
      else
        if [[ "$DRY_RUN" -eq 1 ]]; then
          log "[AWS] (dry-run) Would block $IP"
        else
          VER=$("$AWS_BIN" ec2 describe-managed-prefix-lists \
            --region "$AWS_REGION" --prefix-list-ids "$AWS_PL_ID" \
            --query "PrefixLists[0].Version" --output text 2>/dev/null)
          log "[AWS] Adding $IP/32 (ver=${VER:-unknown})"
          if retry "$AWS_BIN" ec2 modify-managed-prefix-list \
            --region "$AWS_REGION" --prefix-list-id "$AWS_PL_ID" \
            --current-version "$VER" \
            --add-entries Cidr="$IP/32",Description="Auto-blocked by OpenCanary"; then
            log "[AWS] OK: $IP/32 blocked (prefix-list)"
          else
            log "[AWS] ERROR blocking $IP (modify-managed-prefix-list failed)"
          fi
        fi
      fi
    fi
  fi

  ##########################
  # Azure - use helper
  ##########################
  if [[ -n "${AZURE_RG:-}" && -n "${AZURE_NSG:-}" && -n "$AZ_BIN" ]]; then
    azure_ensure_and_append "$IP"
  fi

  ##########################
  # GCP - one rule per IP style (auto-deny-<ip>)
  ##########################
  if [[ -n "${GCP_PROJECT_ID:-}" && -n "$GCLOUD_BIN" ]]; then
    RULE="auto-deny-${IP//./-}"
    if gcloud compute firewall-rules describe "$RULE" --project="$GCP_PROJECT_ID" &>/dev/null; then
      log "[GCP] $IP already blocked, skipping"
    else
      if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[GCP] (dry-run) Would block $IP"
      else
        log "[GCP] Adding $RULE priority=${GCP_DENY_PRIORITY:-90}"
        if retry gcloud compute firewall-rules create "$RULE" \
          --project="$GCP_PROJECT_ID" \
          --network=default \
          --priority="${GCP_DENY_PRIORITY:-90}" \
          --direction=INGRESS --action=DENY --rules=all \
          --source-ranges="$IP/32"; then
          log "[GCP] OK: $IP/32 blocked (rule=$RULE)"
        else
          log "[GCP] ERROR blocking $IP"
        fi
      fi
    fi
  fi

done < "$EXPORT_FILE"

log "DONE"


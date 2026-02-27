
manohar@gcp-logserver:/opt/splunk/bin/scripts$ cat reset_all_blocks.sh
#!/usr/bin/env bash
set -euo pipefail

# Reset all IP blocks across AWS, Azure, and GCP
# NOTE: Azure scalable rule 'AutoBlockedIPs-Honeypot' will be reset to
# a safe placeholder '192.0.2.0/32' (TEST-NET address) to avoid leaving rule empty
# or accidentally allowing/denying everything.

# --- AWS ---
AWS_PL_ID="pl-067a3fa961dd2a39d"
AWS_REGION="us-east-1"

echo "[AWS] Checking prefix list entries..."
ENTRIES_JSON=$(aws ec2 get-managed-prefix-list-entries \
  --prefix-list-id "$AWS_PL_ID" --region "$AWS_REGION" \
  --query "Entries[].{Cidr:Cidr}" --output json || echo "[]")

if [[ "$ENTRIES_JSON" != "[]" && -n "$ENTRIES_JSON" ]]; then
  CUR_VER=$(aws ec2 describe-managed-prefix-lists \
    --prefix-list-ids "$AWS_PL_ID" --region "$AWS_REGION" \
    --query "PrefixLists[0].Version" --output text)
  echo "[AWS] Removing all entries from $AWS_PL_ID (version=$CUR_VER)..."
  # remove-entries expects a JSON list like [{"Cidr":"1.2.3.4/32"},...]
  # Build remove list from returned entries
  REMOVE_JSON=$(echo "$ENTRIES_JSON" | jq -c '[.[] | {Cidr:.Cidr}]')
  if [[ "$REMOVE_JSON" != "[]" ]]; then
    aws ec2 modify-managed-prefix-list \
      --prefix-list-id "$AWS_PL_ID" \
      --current-version "$CUR_VER" \
      --remove-entries "$REMOVE_JSON" --region "$AWS_REGION"
    echo "[AWS] Prefix list cleared."
  else
    echo "[AWS] No entries to remove."
  fi
else
  echo "[AWS] No entries to remove."
fi

# --- Azure ---
AZ_RG="Capstone"
AZ_NSG="AzureVMnsg706"
AUTO_RULE_NAME="AutoBlockedIPs-Honeypot"
PLACEHOLDER_PREFIX="192.0.2.0/32"   # TEST-NET (safe placeholder)

echo "[Azure] Deleting dynamic AUTO_DENY_* rules (if any)..."
set +e
AUTO_RULES=$(az network nsg rule list --resource-group "$AZ_RG" --nsg-name "$AZ_NSG" \
  --query "[?starts_with(name, 'AUTO_DENY_')].name" -o tsv 2>/dev/null) || AUTO_RULES=""
set -e

if [[ -n "$AUTO_RULES" ]]; then
  while read -r r; do
    [[ -z "$r" ]] && continue
    echo "[Azure] Deleting rule: $r"
    az network nsg rule delete --resource-group "$AZ_RG" --nsg-name "$AZ_NSG" --name "$r" || \
      echo "[Azure] Failed deleting $r (continuing)"
  done <<< "$AUTO_RULES"
else
  echo "[Azure] No AUTO_DENY_ rules found."
fi

echo "[Azure] Resetting scalable rule '${AUTO_RULE_NAME}' (if exists)..."
set +e
az network nsg rule show -g "$AZ_RG" --nsg-name "$AZ_NSG" --name "$AUTO_RULE_NAME" -o json >/tmp/az_rule.json 2>/dev/null
SHOW_RC=$?
set -e

if [[ $SHOW_RC -ne 0 ]]; then
  echo "[Azure] Rule '${AUTO_RULE_NAME}' not found or cannot access. Skipping scalable-rule reset."
else
  # read existing prefixes (for log/debug)
  EXISTING_PREFIXES=$(jq -r '(.sourceAddressPrefixes[]? // .sourceAddressPrefix?)' /tmp/az_rule.json 2>/dev/null || true)
  echo "[Azure] Current prefixes in ${AUTO_RULE_NAME}:"
  if [[ -n "$EXISTING_PREFIXES" ]]; then
    echo "$EXISTING_PREFIXES"
  else
    echo "(none)"
  fi

  # Replace with safe placeholder. This removes attacker CIDRs from the rule.
  echo "[Azure] Updating ${AUTO_RULE_NAME} -> $PLACEHOLDER_PREFIX"
  if az network nsg rule update -g "$AZ_RG" --nsg-name "$AZ_NSG" --name "$AUTO_RULE_NAME" \
       --source-address-prefixes "$PLACEHOLDER_PREFIX" --only-show-errors >/dev/null 2>&1; then
    echo "[Azure] ${AUTO_RULE_NAME} updated to placeholder prefix."
  else
    echo "[Azure] ERROR: Failed to update ${AUTO_RULE_NAME}. You may need additional permissions or to update manually."
  fi
fi

# --- GCP ---
GCP_PROJECT="flowing-blade-464915-d3"

echo "[GCP] Deleting auto-deny-* firewall rules..."
set +e
RULES=$(gcloud compute firewall-rules list --project="$GCP_PROJECT" --filter="name~'auto-deny-'" --format="value(name)" 2>/dev/null) || RULES=""
set -e

if [[ -n "$RULES" ]]; then
  while read -r r; do
    [[ -z "$r" ]] && continue
    echo "[GCP] Deleting firewall rule: $r"
    gcloud compute firewall-rules delete "$r" --project="$GCP_PROJECT" -q || \
      echo "[GCP] Failed deleting $r (continuing)"
  done <<< "$RULES"
else
  echo "[GCP] No auto-deny-* rules found."
fi

echo "[ALL CLOUDS] Reset complete."

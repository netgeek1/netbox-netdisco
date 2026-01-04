#!/usr/bin/env bash
# ============================================================
# NetBox Docker All-in-One Installer & Manager (+ Discovery + Plugins)
# Version: 1.9.17
# Baseline: v1.2.8 (LOCKED)
# ============================================================
# v1.3.x features (kept intact):
# - NetBox + Postgres + Redis + Redis-cache
# - Netdisco backend + web using shared Postgres
# - Idempotent Netdisco DB creation + schema init
# - Visible wait counters (Postgres + HTTP services)
# - SNMP helpers (Netdisco):
#   * SNMP v2c RO community management (netdisco.env)
#   * SNMPv3 READ-ONLY profiles (netdisco/environments/deployment.yml device_auth)
# - NetBox plugins (Topology Views + BGP):
#   * Plugins installed INSIDE container via derived image build
#   * Enable/disable via /etc/netbox/config/plugins.py bind-mounted from /opt/netbox
#
# v1.3.4 FIX:
# - NetBox image venv may not include pip; bootstrap pip robustly in Dockerfile:
#   * try python -m pip
#   * if missing: python -m ensurepip --upgrade
#   * if still missing: fetch+run get-pip.py via python urllib (no curl needed)
#
# Notes:
# - No docker-compose `version:` key (Compose v2+)
# - Script runs from ANY directory; install state stored in /etc/netbox-docker-manager.conf
# - Docker containers are managed as the real user (docker group), not root
# ============================================================

set -euo pipefail

SCRIPT_VERSION="1.9.17"

# Script identity (helps detect running the wrong file/version)
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_BASENAME="$(basename "$SCRIPT_PATH")"

# ------------------------------------------------------------
# Auto sudo
# ------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

REAL_USER="${SUDO_USER:-root}"

# ------------------------------------------------------------
# Begin 1.9.17 additions
# ------------------------------------------------------------
### =================================================
### BEGIN - NETBOX AUTH / TOKEN / PRIVILEGE FRAMEWORK
### =================================================
# ------------------------------------------------------------
# ENV VALIDATION + AUTO‑REPAIR + SAFE SECRET GENERATOR
# ------------------------------------------------------------

# Validate .env file for malformed or multiline entries
validate_env_file() {
  local env_file="/opt/netbox/.env"
  log "Validating ${env_file}"

  if [[ ! -f "$env_file" ]]; then
    log "WARN: .env file does not exist"
    return 1
  fi

  local bad_lines
  bad_lines=$(awk '
    /^[A-Za-z0-9_]+=.+$/ { next }     # valid KEY=value
    /^[[:space:]]*$/ { next }         # skip empty
    /^#/ { next }                     # skip comments
    { print NR ":" $0 }               # everything else is invalid
  ' "$env_file")

  if [[ -n "$bad_lines" ]]; then
    log "ERROR: Invalid or multiline entries detected:"
    echo "$bad_lines"
    return 2
  fi

  log "ENV validation passed"
  return 0
}

# Attempt to repair wrapped or multiline base64 values in .env
repair_env_file() {
  local env_file="/opt/netbox/.env"
  log "Attempting automatic repair of ${env_file}"

  if [[ ! -f "$env_file" ]]; then
    log "ERROR: Cannot repair missing .env file"
    return 1
  fi

  # Backup before modifying
  cp "$env_file" "${env_file}.bak.$(date +%Y%m%d-%H%M%S)"

  # Join any wrapped base64 fragments into a single line
  awk '
    /^[A-Za-z0-9_]+=/{ 
        if (key) print key "=" value
        split($0, kv, "=")
        key=kv[1]
        value=kv[2]
        next
    }
    /^[A-Za-z0-9+\/]+=*$/ {
        value = value $0
        next
    }
    {
        if (key) print key "=" value
        key=""
        value=""
        print $0
    }
    END {
        if (key) print key "=" value
    }
  ' "$env_file" > "${env_file}.fixed"

  mv "${env_file}.fixed" "$env_file"
  log "ENV repair complete"
}

# Generate a safe, single‑line base64 secret (never wraps)
generate_safe_secret() {
  openssl rand -base64 50 | tr -d '\n'
}

# ------------------------------------------------------------
# ENV VALIDATION WORKFLOW (call this before sourcing .env)
# ------------------------------------------------------------
validate_and_repair_env() {
  validate_env_file || {
    log "ENV file invalid — attempting repair"
    repair_env_file
    validate_env_file || {
      log "ERROR: ENV file still invalid after repair"
      exit 1
    }
  }
}

########################################
# ENV AUTOLOAD (authoritative)
########################################
NETBOX_ENV="/opt/netbox/.env"
if [[ -f "$NETBOX_ENV" ]]; then
  validate_and_repair_env
  set -a
  source "$NETBOX_ENV"
  set +a
fi

########################################
# REQUIRED BASE SETTINGS
########################################
: "${NETBOX_API:=http://localhost:8000/api}"

########################################
# TOKEN ENFORCEMENT MODES
########################################
# Modes:
#   RO  = read-only discovery / diff
#   RW  = write / apply / reconcile
########################################

########################################
# TOKEN GENERATION
########################################

generate_netbox_tokens() {
    local secrets_file="/opt/netbox/secrets/secrets.env"
    local log_dir="/opt/netbox/logs"
    local timestamp
    timestamp=$(date +"%Y%m%d-%H%M%S")
    local log_file="${log_dir}/token-gen-${timestamp}.log"
    local container
    container="$(docker ps --format '{{.Names}}' | grep -E '^netbox|netbox-netdisco-web' | head -n 1)"
    local superuser="admin"

    mkdir -p "$log_dir"
    echo "[INFO] Token generation started at ${timestamp}" | tee -a "$log_file"

    # Check for existing tokens (idempotency)
    if [[ -f "$secrets_file" ]]; then
        source "$secrets_file"

        if [[ -n "$NETBOX_API_TOKEN_RW" && -n "$NETBOX_API_TOKEN_RO" ]]; then
            echo "[INFO] Existing tokens detected. Skipping regeneration." | tee -a "$log_file"
            echo "[INFO] RW token length: ${#NETBOX_API_TOKEN_RW}" | tee -a "$log_file"
            echo "[INFO] RO token length: ${#NETBOX_API_TOKEN_RO}" | tee -a "$log_file"
            return 0
        else
            echo "[WARN] Secrets file exists but tokens are missing or empty." | tee -a "$log_file"
        fi
    else
        echo "[WARN] Secrets file not found. Creating new one." | tee -a "$log_file"
    fi

    echo "[INFO] Generating new NetBox API tokens..." | tee -a "$log_file"

    # Ensure container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo "[ERROR] NetBox container '${container}' is not running." | tee -a "$log_file"
        return 1
    fi

    # Generate RW token
    local token_rw
    token_rw=$(docker exec -u root "${container}" \
        python3 /opt/netbox/netbox/manage.py tokens create "${superuser}" --write-enabled \
        | awk '/Key:/ {print $2}')

    if [[ -z "$token_rw" ]]; then
        echo "[ERROR] Failed to generate RW token." | tee -a "$log_file"
        return 1
    fi
    echo "[INFO] RW token generated." | tee -a "$log_file"

    # Generate RO token
    local token_ro
    token_ro=$(docker exec -u root "${container}" \
        python3 /opt/netbox/netbox/manage.py tokens create "${superuser}" \
        | awk '/Key:/ {print $2}')

    if [[ -z "$token_ro" ]]; then
        echo "[ERROR] Failed to generate RO token." | tee -a "$log_file"
        return 1
    fi
    echo "[INFO] RO token generated." | tee -a "$log_file"

    # Write tokens to secrets file
    mkdir -p "$(dirname "$secrets_file")"
    {
        echo "NETBOX_API_TOKEN_RW=${token_rw}"
        echo "NETBOX_API_TOKEN_RO=${token_ro}"
    } > "$secrets_file"

    chmod 600 "$secrets_file"
    echo "[INFO] Tokens written to ${secrets_file}" | tee -a "$log_file"

    # Verification
    source "$secrets_file"
    if [[ -n "$NETBOX_API_TOKEN_RW" && -n "$NETBOX_API_TOKEN_RO" ]]; then
        echo "[INFO] Token verification successful." | tee -a "$log_file"
    else
        echo "[ERROR] Token verification failed." | tee -a "$log_file"
        return 1
    fi

    echo "[INFO] Token generation completed successfully." | tee -a "$log_file"
    return 0
}

########################################
# TOKEN VALIDATION
########################################
netbox_validate_token() {
  local mode="$1"
  local token_var

  case "$mode" in
    RO) token_var="NETBOX_API_TOKEN_RO" ;;
    RW) token_var="NETBOX_API_TOKEN_RW" ;;
    *)
      echo "[FATAL] Invalid token mode: $mode"
      exit 1
      ;;
  esac

  if [[ -z "${!token_var:-}" ]]; then
    echo "[ERROR] Required NetBox token missing: $token_var"
    exit 1
  fi

  export NETBOX_TOKEN="${!token_var}"
}

########################################
# NETBOX API WRAPPER (PRIVILEGE AWARE)
########################################
netbox_api() {
  local method="$1" endpoint="$2" data="$3"

  curl -fsS -X "$method" \
    -H "Authorization: Token $NETBOX_TOKEN" \
    -H "Content-Type: application/json" \
    ${data:+-d "$data"} \
    "$NETBOX_API/$endpoint"
}

########################################
# TOKEN AUTO-GENERATION (ADMIN ONLY)
########################################
netbox_generate_token() {
  local name="$1"
  local write="$2"   # true | false

  netbox_validate_token RW

  local payload
  if [[ "$write" == "true" ]]; then
    payload='{"name":"'"$name"'","write_enabled":true}'
  else
    payload='{"name":"'"$name"'","write_enabled":false}'
  fi

  netbox_api POST "users/tokens/" "$payload" | jq -r '.key'
}

########################################
# AUTO-ENSURE TOKENS (IDEMPOTENT)
########################################
netbox_ensure_tokens() {
  netbox_validate_token RW

  if [[ -z "${NETBOX_API_TOKEN_RO:-}" ]]; then
    echo "[INFO] Creating read-only NetBox token"
    NETBOX_API_TOKEN_RO="$(netbox_generate_token discovery-ro false)"
    echo "NETBOX_API_TOKEN_RO=$NETBOX_API_TOKEN_RO" >> "$NETBOX_ENV"
  fi

  if [[ -z "${NETBOX_API_TOKEN_RW:-}" ]]; then
    echo "[INFO] Creating read-write NetBox token"
    NETBOX_API_TOKEN_RW="$(netbox_generate_token discovery-rw true)"
    echo "NETBOX_API_TOKEN_RW=$NETBOX_API_TOKEN_RW" >> "$NETBOX_ENV"
  fi
}

########################################
# PRIVILEGE SEPARATED EXECUTION HELPERS
########################################
with_netbox_ro() {
  netbox_validate_token RO
  "$@"
}

with_netbox_rw() {
  netbox_validate_token RW
  "$@"
}

### =================================================
### END - NETBOX AUTH / TOKEN / PRIVILEGE FRAMEWORK
### =================================================

### --- Constants ---
NETBOX_API="${NETBOX_API:-http://localhost:8000/api}"

DISCOVERY_DIR="/opt/netbox/discovery"
SCAN_JSON="$DISCOVERY_DIR/scan.json"
NORM_JSON="$DISCOVERY_DIR/normalized.json"
SNMP_JSON="$DISCOVERY_DIR/snmp.json"
AUDIT_LOG="$DISCOVERY_DIR/audit.log"

mkdir -p "$DISCOVERY_DIR"

### --- NetBox API wrapper ---
netbox_api() {
  local method="$1" endpoint="$2" data="$3"
  curl -sS -X "$method" \
    -H "Authorization: Token $NETBOX_TOKEN" \
    -H "Content-Type: application/json" \
    ${data:+-d "$data"} \
    "$NETBOX_API/$endpoint"
}

### --- CIDR Discovery (Nmap) ---
discovery_scan_cidr() {
  : > "$AUDIT_LOG"
  nmap -sn "$1" -oX - | python3 - <<'PY' > "$SCAN_JSON"
import xml.etree.ElementTree as ET, json, sys
root = ET.fromstring(sys.stdin.read())
hosts=[]
for h in root.findall("host"):
    a=h.find("address[@addrtype='ipv4']")
    if a is None: continue
    hn=h.find("hostnames/hostname")
    hosts.append({
        "ip":a.get("addr"),
        "name":hn.get("name") if hn is not None else None
    })
print(json.dumps(hosts,indent=2))
PY
}

### --- Normalize ---
discovery_normalize() {
  jq '
  map({
    name:(.name // ("host-" + (.ip|gsub("\\."; "-")))),
    ip:.ip,
    site:"default",
    role:"unknown",
    type:"generic"
  })' "$SCAN_JSON" > "$NORM_JSON"
}

### --- Ensure primitives ---
netbox_ensure() {
  local ep="$1" name="$2" payload="$3"
  netbox_api GET "$ep/?name=$name" | jq -e '.count>0' >/dev/null || \
    netbox_api POST "$ep/" "$payload" >/dev/null
}

### --- Device import ---
discovery_import_devices() {
  jq -c '.[]' "$NORM_JSON" | while read -r d; do
    name=$(jq -r .name <<<"$d")
    ip=$(jq -r .ip <<<"$d")

    netbox_ensure "dcim/sites" default '{"name":"default","slug":"default"}'
    netbox_ensure "dcim/device-roles" unknown '{"name":"unknown","slug":"unknown"}'
    netbox_ensure "dcim/device-types" generic '{"model":"generic","slug":"generic","manufacturer":1}'

    dev_id=$(netbox_api GET "dcim/devices/?name=$name" | jq -r '.results[0].id//empty')

    if [[ -z "$dev_id" ]]; then
      dev_id=$(netbox_api POST "dcim/devices/" "{
        \"name\":\"$name\",
        \"site\":1,
        \"device_role\":1,
        \"device_type\":1,
        \"status\":\"active\"
      }" | jq -r .id)
      echo "[ADD] $name" >> "$AUDIT_LOG"
    fi

    netbox_api POST "ipam/ip-addresses/" "{
      \"address\":\"$ip/32\",
      \"assigned_object_type\":\"dcim.device\",
      \"assigned_object_id\":$dev_id
    }" >/dev/null 2>&1 || true
  done
}

### --- SNMP Interface Discovery ---
discovery_snmp_interfaces() {
  jq -r '.[].ip' "$NORM_JSON" | while read -r ip; do
    snmpwalk -On -v2c -c public "$ip" IF-MIB::ifDescr 2>/dev/null | \
    awk -F': ' '{print $2}' | while read -r iface; do
      echo "$ip|$iface"
    done
  done | jq -R 'split("|")|{ip:.[0],iface:.[1]}' | jq -s '.' > "$SNMP_JSON"
}

### --- Interface import ---
discovery_import_interfaces() {
  jq -c '.[]' "$SNMP_JSON" | while read -r i; do
    ip=$(jq -r .ip <<<"$i")
    iface=$(jq -r .iface <<<"$i")

    dev_id=$(netbox_api GET "dcim/devices/?q=$ip" | jq -r '.results[0].id//empty')
    [[ -z "$dev_id" ]] && continue

    netbox_api POST "dcim/interfaces/" "{
      \"device\":$dev_id,
      \"name\":\"$iface\",
      \"type\":\"other\"
    }" >/dev/null 2>&1 || true
  done
}

### --- Apply (authoritative) ---
discovery_apply() {
  discovery_normalize
  discovery_import_devices
  discovery_snmp_interfaces
  discovery_import_interfaces
  echo "[DONE] Discovery applied" >> "$AUDIT_LOG"
}

### ==================================
### BEGIN - ADVANCED DISCOVERY LAYERS
### ==================================

### --- Files ---
DIFF_JSON="$DISCOVERY_DIR/diff.json"
NEIGHBOR_JSON="$DISCOVERY_DIR/neighbors.json"
RECON_LOG="$DISCOVERY_DIR/reconcile.log"

### --- Netdisco API helper ---
netdisco_api() {
  curl -sS "http://localhost:5000/api/v1/$1"
}

### ==================================================
### LLDP / CDP NEIGHBOR DISCOVERY (via Netdisco)
### ==================================================
discovery_neighbors() {
  netdisco_api "search/device?field=ip&op=~&value=." | \
  jq -r '.devices[].ip' | while read -r ip; do
    netdisco_api "object/device/$ip/neighbor" | \
    jq -c '.neighbors[]?' | while read -r n; do
      jq -n --arg src "$ip" --argjson n "$n" '
        {
          src_ip:$src,
          local_port:$n.port,
          remote_name:$n.remote_name,
          remote_port:$n.remote_port
        }'
    done
  done | jq -s '.' > "$NEIGHBOR_JSON"
}

### --- Import neighbors ---
discovery_import_neighbors() {
  jq -c '.[]' "$NEIGHBOR_JSON" | while read -r n; do
    src=$(jq -r .src_ip <<<"$n")
    lport=$(jq -r .local_port <<<"$n")
    rname=$(jq -r .remote_name <<<"$n")
    rport=$(jq -r .remote_port <<<"$n")

    src_id=$(netbox_api GET "dcim/devices/?q=$src" | jq -r '.results[0].id//empty')
    dst_id=$(netbox_api GET "dcim/devices/?name=$rname" | jq -r '.results[0].id//empty')
    [[ -z "$src_id" || -z "$dst_id" ]] && continue

    li=$(netbox_api GET "dcim/interfaces/?device_id=$src_id&name=$lport" | jq -r '.results[0].id//empty')
    ri=$(netbox_api GET "dcim/interfaces/?device_id=$dst_id&name=$rport" | jq -r '.results[0].id//empty')
    [[ -z "$li" || -z "$ri" ]] && continue

    netbox_api POST "dcim/cables/" "{
      \"a_terminations\":[{\"object_type\":\"dcim.interface\",\"object_id\":$li}],
      \"b_terminations\":[{\"object_type\":\"dcim.interface\",\"object_id\":$ri}]
    }" >/dev/null 2>&1 || true
  done
}

### ==================================================
### DIFF-BEFORE-APPLY
### ==================================================
discovery_diff() {
  netbox_api GET "dcim/devices/?limit=10000" | \
  jq '[.results[].name]' > "$DISCOVERY_DIR/netbox_devices.json"

  jq '[.[].name]' "$NORM_JSON" > "$DISCOVERY_DIR/discovered_devices.json"

  jq -n '
    {
      add: (input[1] - input[0]),
      remove: (input[0] - input[1])
    }' \
    "$DISCOVERY_DIR/netbox_devices.json" \
    "$DISCOVERY_DIR/discovered_devices.json" \
    > "$DIFF_JSON"
}

### ==================================================
### DELETE RECONCILIATION (SAFE)
### ==================================================
discovery_reconcile_delete() {
  jq -r '.remove[]' "$DIFF_JSON" | while read -r name; do
    id=$(netbox_api GET "dcim/devices/?name=$name" | jq -r '.results[0].id//empty')
    [[ -z "$id" ]] && continue
    netbox_api PATCH "dcim/devices/$id/" '{"status":"offline"}' >/dev/null
    echo "[OFFLINE] $name" >> "$RECON_LOG"
  done
}

### ==================================================
### NETDISCO → NETBOX ENRICHMENT
### ==================================================
discovery_enrich_from_netdisco() {
  netdisco_api "search/device?field=ip&op=~&value=." | \
  jq -c '.devices[]' | while read -r d; do
    ip=$(jq -r .ip <<<"$d")
    model=$(jq -r .model <<<"$d")
    os=$(jq -r .os <<<"$d")
    vendor=$(jq -r .vendor <<<"$d")

    id=$(netbox_api GET "dcim/devices/?q=$ip" | jq -r '.results[0].id//empty')
    [[ -z "$id" ]] && continue

    netbox_api PATCH "dcim/devices/$id/" "{
      \"custom_fields\":{
        \"model\":\"$model\",
        \"os\":\"$os\",
        \"vendor\":\"$vendor\"
      }
    }" >/dev/null
  done
}

### ==================================================
### FULL APPLY (EXTENDED)
### ==================================================
discovery_apply_full() {
  discovery_diff
  discovery_apply
  discovery_neighbors
  discovery_import_neighbors
  discovery_reconcile_delete
  discovery_enrich_from_netdisco
  echo "[DONE] Full discovery + reconciliation applied" >> "$AUDIT_LOG"
}

### ==================================
### END - ADVANCED DISCOVERY LAYERS
### ==================================


# ------------------------------------------------------------
# End 1.9.17 additions
# ------------------------------------------------------------

# ------------------------------------------------------------
# SNMP Debug Logging (host-side)
# ------------------------------------------------------------
SNMP_DEBUG_LOG_REL="logs/snmp-debug.log"

log_script_identity() {
  # Best-effort: write last-run marker into install dir if available
  local msg
  msg="version=${SCRIPT_VERSION} script=${SCRIPT_BASENAME} path=${SCRIPT_PATH} user=$(whoami) time=$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[INFO] ${msg}"
  if [[ -n "${INSTALL_DIR:-}" ]]; then
    mkdir -p "${INSTALL_DIR}/logs" 2>/dev/null || true
    echo "${msg}" | sudo tee "${INSTALL_DIR}/logs/script-last-run.txt" >/dev/null 2>&1 || true
  fi
}
snmp_debug_log_path() { echo "${INSTALL_DIR}/${SNMP_DEBUG_LOG_REL}"; }

snmp_dbg_init() {
  cd_install_dir
  mkdir -p "${INSTALL_DIR}/logs"
  local f
  f="$(snmp_debug_log_path)"
  sudo touch "$f" 2>/dev/null || true
  sudo chmod 0644 "$f" 2>/dev/null || true
}

snmp_dbg() {
  snmp_dbg_init
  local f ts
  f="$(snmp_debug_log_path)"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts] $*" | sudo tee -a "$f" >/dev/null 2>&1 || true
}

snmp_dbg_cmd() {
  # snmp_dbg_cmd "label" <command...>
  local label="$1"; shift
  snmp_dbg "CMD ${label}: $*"
  local out rc
  out="$(mktemp)"
  "$@" >"$out" 2>&1
  rc=$?
  snmp_dbg "RC ${label}: ${rc}"
  tail -n 200 "$out" | while IFS= read -r l; do snmp_dbg "OUT ${label}: ${l}"; done
  rm -f "$out"
  return $rc
}

snmp_dbg_file_meta() {
  local f="$1"
  snmp_dbg "FILE ${f}"
  snmp_dbg_cmd "ls-${f}" sudo ls -l "$f"
  snmp_dbg_cmd "head-${f}" sudo bash -lc "sed -n '1,120p' '$f'"
}

view_snmp_debug_log() {
  cd_install_dir
  snmp_dbg_init
  echo
  echo "=== SNMP Debug Log ($(snmp_debug_log_path)) ==="
  if [[ -f "$(snmp_debug_log_path)" ]]; then
    sudo tail -n 400 "$(snmp_debug_log_path)" 2>/dev/null || true
  else
    echo "(no log yet)"
  fi
  echo
}
SCRIPT_NAME="NetBox Docker Manager"
DEFAULT_INSTALL_DIR="/opt/netbox"
STATE_FILE="/etc/netbox-docker-manager.conf"

NETBOX_PORT=8000
NETDISCO_PORT=5000

# Netdisco shell scripts expect these under `set -u`
NETDISCO_PG_MAJOR=15
DEPLOY_ADMIN_USER_DEFAULT=1

# NetBox plugins
NB_PLUGIN_TOPOLOGY_PIP="netbox-topology-views"
NB_PLUGIN_TOPOLOGY_MOD="netbox_topology_views"
NB_PLUGIN_BGP_PIP="netbox-bgp"
NB_PLUGIN_BGP_MOD="netbox_bgp"

# ------------------------------------------------------------
# Discovery (Model 2 multi-source) - CONFIG ONLY (no importers yet)
# ------------------------------------------------------------
DISCOVERY_DIR_REL="discovery"
DISCOVERY_CFG="discovery/discovery.env"
DISCOVERY_REPORTS_DIR="discovery/reports"
DISCOVERY_LAST_DRYRUN_FILE="discovery/last_dryrun.json"
DISCOVERY_LAST_APPLY_FILE="discovery/last_apply.json"

# Source toggles (1=enabled, 0=disabled)
DISC_NETDISCO_NETWORK=1
DISC_VMWARE_VCENTER=0
DISC_PROXMOX=0
DISC_BAREMETAL_AD=0
DISC_BAREMETAL_SSH=0
DISC_CLOUD_AWS=0
DISC_CLOUD_AZURE=0
DISC_CLOUD_GCP=0
DISC_ACTIVE_SCANNING=0

# ------------------------------------------------------------
# Auto sudo
# ------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

REAL_USER="${SUDO_USER:-root}"

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
err()  { echo "[ERROR] $*" >&2; }
pause(){ read -rp "Press ENTER to continue..."; }

write_state_install_dir() { echo "INSTALL_DIR=\"$1\"" > "$STATE_FILE"; }
load_state_install_dir() { [[ -f "$STATE_FILE" ]] && source "$STATE_FILE" || true; }

ensure_install_dir() {
  load_state_install_dir
  if [[ -n "${INSTALL_DIR:-}" && -d "${INSTALL_DIR:-}" ]]; then
    return
  fi

  read -rp "Install directory [$DEFAULT_INSTALL_DIR]: " INSTALL_DIR
  INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
  mkdir -p "$INSTALL_DIR"
  write_state_install_dir "$INSTALL_DIR"
}

cd_install_dir() { ensure_install_dir; cd "$INSTALL_DIR"; }
as_user() { sudo -u "$REAL_USER" "$@"; }

# Ensure KEY=VALUE exists in a file; append if missing
ensure_kv() { grep -q "^$2=" "$1" || echo "$2=$3" >> "$1"; }

# Replace-or-append KEY=VALUE in env file
set_env_kv() {
  local file="$1" key="$2" val="$3"
  if [[ ! -f "$file" ]]; then
    echo "${key}=${val}" > "$file"
    return
  fi
  if grep -qE "^${key}=" "$file"; then
    sed -i "s#^${key}=.*#${key}=${val}#g" "$file"
  else
    echo "${key}=${val}" >> "$file"
  fi
}

# ------------------------------------------------------------
# Docker install & prerequisites (Ubuntu/Debian)
# ------------------------------------------------------------
install_docker() {
  command -v docker >/dev/null 2>&1 && return
  log "Docker not found; installing prerequisites + Docker Engine..."

  apt-get update
  apt-get install -y ca-certificates curl gnupg lsb-release openssl

  mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

  systemctl enable docker
  systemctl start docker

  log "Docker installed."
}

ensure_docker_group() {
  getent group docker >/dev/null || groupadd docker
  if ! id "$REAL_USER" | grep -q docker; then
    log "Adding user '$REAL_USER' to docker group"
    usermod -aG docker "$REAL_USER"
    warn "You may need to log out/in for group changes to apply in existing sessions."
  fi
}

# ------------------------------------------------------------
# Wait helpers
# ------------------------------------------------------------
wait_for_http() {
  local name="$1" url="$2" timeout="$3" waited=0
  echo "[INFO] Waiting for $name at $url"
  until curl -fsS "$url" >/dev/null 2>&1; do
    sleep 5
    waited=$((waited+5))
    echo "  ⏳ $name waiting: ${waited}s / ${timeout}s"
    if (( waited >= timeout )); then
      err "$name not reachable after ${timeout}s"
      return 1
    fi
  done
  log "$name reachable after ${waited}s"
}

wait_for_postgres() {
  local timeout=180 waited=0
  echo "[INFO] Waiting for Postgres"
  until as_user docker compose exec -T postgres pg_isready -U netbox >/dev/null 2>&1; do
    sleep 5
    waited=$((waited+5))
    echo "  ⏳ Postgres waiting: ${waited}s / ${timeout}s"
    if (( waited >= timeout )); then
      err "Postgres not ready after ${timeout}s"
      return 1
    fi
  done
  log "Postgres ready after ${waited}s"
}

# ------------------------------------------------------------
# Files/dirs
# ------------------------------------------------------------
ensure_dirs() {
  cd_install_dir
  mkdir -p netdisco/{logs,config,nd-site-local,environments}
  mkdir -p netbox-custom/{config,build}
  # Netdisco runs as UID/GID 901 in images; best-effort
  chown -R 901:901 netdisco 2>/dev/null || true
}

# ------------------------------------------------------------
# Env generation
# ------------------------------------------------------------
generate_netbox_env() {
  cd_install_dir
  local key
  key=$(grep -E '^SECRET_KEY=' .env 2>/dev/null | cut -d= -f2- || true)
  [[ -z "$key" ]] && key=$(openssl rand -base64 50)

  cat > .env <<EOF
ALLOWED_HOSTS=*
SECRET_KEY=$key
DB_NAME=netbox
DB_USER=netbox
DB_PASSWORD=netbox
DB_HOST=postgres
DB_PORT=5432
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_CACHE_HOST=redis-cache
REDIS_CACHE_PORT=6379
SUPERUSER_NAME=admin
SUPERUSER_EMAIL=admin@example.com
SUPERUSER_PASSWORD=admin
EOF
}

generate_netdisco_env() {
  cd_install_dir
  if [[ ! -f netdisco.env ]]; then
    cat > netdisco.env <<EOF
NETDISCO_DB_HOST=postgres
NETDISCO_DB_PORT=5432
NETDISCO_DB_NAME=netdisco
NETDISCO_DB_USER=netbox
NETDISCO_DB_PASS=netbox
NETDISCO_CURRENT_PG_VERSION=$NETDISCO_PG_MAJOR
DEPLOY_ADMIN_USER=$DEPLOY_ADMIN_USER_DEFAULT
NETDISCO_RO_COMMUNITY=public
EOF
  fi

  ensure_kv netdisco.env NETDISCO_CURRENT_PG_VERSION "$NETDISCO_PG_MAJOR"
  ensure_kv netdisco.env DEPLOY_ADMIN_USER "$DEPLOY_ADMIN_USER_DEFAULT"
  ensure_kv netdisco.env NETDISCO_RO_COMMUNITY "public"
}

# ------------------------------------------------------------
# Netdisco deployment.yml (SNMPv3 profiles)
# ------------------------------------------------------------
ensure_netdisco_deployment_yml() {
  cd_install_dir
  local f="netdisco/environments/deployment.yml"
  if [[ -f "$f" ]]; then
    return 0
  fi

  cat > "$f" <<'EOF'
# Netdisco deployment config
# Managed by NetBox Docker Manager
#
# SECURITY: this file can contain secrets. Restrict permissions.
no_auth: true
discover_snmpver: 2
device_auth: []
EOF

  chmod 0640 "$f" || true
  chown 901:901 "$f" 2>/dev/null || true
}

# ------------------------------------------------------------
# Netdisco: SNMP profile visibility + testing (inside container)
# ------------------------------------------------------------
netdisco_profiles_show() {
  netdisco_require_env_mount || return 1

  cd_install_dir
  local f="netdisco/environments/deployment.yml"
  if [[ ! -f "$f" ]]; then
    err "Netdisco deployment.yml not found at: ${INSTALL_DIR}/$f"
    echo "Run install/update first, or create it via Netdisco options."
    return 1
  fi
  echo
  echo "=== Netdisco SNMP Config (from ${INSTALL_DIR}/$f) ==="
  echo
  # Redact common secret keys (pass/password/community). Keep structure.
  sed -E \
    -e 's/^(\s*(pass|password|community)\s*:\s*).*/\1*******/I' \
    "$f" | sed -n '1,240p'
  echo
  echo "Profiles count (device_auth entries):"
  grep -cE '^[[:space:]]*-[[:space:]]*tag:' "$f" 2>/dev/null || echo 0
  echo
}

netdisco_snmp_test_from_container() {
  netdisco_require_env_mount || return 1

  cd_install_dir
  read -rp "Target device IP/hostname: " target
  target="${target:-}"
  if [[ -z "$target" ]]; then
    warn "No target provided."
    return 1
  fi
  echo
  echo "=== Netdisco SNMP Test (discover) ==="
  echo "Target: $target"
  echo
  as_user docker compose exec -T netdisco-backend bash -lc \
    "export NETDISCO_LOG_LEVEL=debug; ~/bin/netdisco-do discover -d \"$target\"" || true
  echo
}






netdisco_add_snmpv3_ro_profile() {
  cd_install_dir
  mkdir -p "${INSTALL_DIR}/logs"
  echo "option9 $(date '+%Y-%m-%d %H:%M:%S') script=${SCRIPT_BASENAME} path=${SCRIPT_PATH}" | sudo tee "${INSTALL_DIR}/logs/option9.flag" >/dev/null 2>&1 || true
  snmp_dbg "Option 9 selected (marker=${INSTALL_DIR}/logs/option9.flag)"
  snmp_credentials_add
}







show_netdisco_credential_ui_hint() {
  echo
  echo "Netdisco credential management UI:"
  echo "  URL: http://<host>:${NETDISCO_PORT}"
  echo "  Look for Admin/Credentials (varies by Netdisco version)."
  echo
  echo "This script can also add SNMPv3 RO profiles into:"
  echo "  ${INSTALL_DIR:-/opt/netbox}/netdisco/environments/deployment.yml"
  echo
}

set_netdisco_snmp_ro_community() {
  cd_install_dir
  generate_netdisco_env
  local cur
  cur="$(grep -E '^NETDISCO_RO_COMMUNITY=' netdisco.env | cut -d= -f2- || true)"
  read -rp "Netdisco SNMP v2c RO community [${cur:-public}]: " community
  community="${community:-${cur:-public}}"
  set_env_kv netdisco.env NETDISCO_RO_COMMUNITY "$community"
  log "Updated netdisco.env. Restarting Netdisco containers..."
  as_user docker compose restart netdisco-backend netdisco-web || true
}

add_netdisco_snmpv3_profile() {
  cd_install_dir
  ensure_netdisco_deployment_yml

  echo
  echo "SNMPv3 READ-ONLY profile builder"
  echo "This will write an authoritative SNMPv3 config to netdisco/environments/deployment.yml"
  echo "Press ENTER at any prompt to cancel."
  echo

  # Tag
  read -rp "Profile tag (example: v3_ro_default) [v3_ro_default]: " ND_V3_TAG
  ND_V3_TAG="${ND_V3_TAG:-v3_ro_default}"
  [[ -z "${ND_V3_TAG}" ]] && warn "Cancelled." && return 0

  # Username
  read -rp "SNMPv3 username: " ND_V3_USER
  [[ -z "${ND_V3_USER:-}" ]] && warn "Cancelled." && return 0

  # Auth proto (strict)
  while true; do
    read -rp "Auth protocol (SHA|MD5) [SHA]: " ND_V3_AUTH_PROTO
    ND_V3_AUTH_PROTO="${ND_V3_AUTH_PROTO:-SHA}"
    ND_V3_AUTH_PROTO="$(echo "$ND_V3_AUTH_PROTO" | tr '[:lower:]' '[:upper:]')"
    if [[ -z "${ND_V3_AUTH_PROTO}" ]]; then
      warn "Cancelled."
      return 0
    fi
    if [[ "${ND_V3_AUTH_PROTO}" == "SHA" || "${ND_V3_AUTH_PROTO}" == "MD5" ]]; then
      break
    fi
    warn "Invalid auth protocol. Valid: SHA or MD5."
  done

  # Auth passphrase (loop; do not error out)
  while true; do
    read -rsp "Auth passphrase (min 8 chars): " ND_V3_AUTH_PASS
    echo
    if [[ -z "${ND_V3_AUTH_PASS}" ]]; then
      warn "Cancelled."
      return 0
    fi
    if [[ ${#ND_V3_AUTH_PASS} -ge 8 ]]; then
      break
    fi
    warn "Too short. Auth passphrase must be at least 8 characters. Try again (or press ENTER to cancel)."
  done

  # Mode
  while true; do
    echo "Privacy mode: 1) authPriv (recommended)  2) authNoPriv"
    read -rp "Select [1]: " pm
    pm="${pm:-1}"
    if [[ -z "${pm}" ]]; then
      warn "Cancelled."
      return 0
    fi
    if [[ "${pm}" == "1" ]]; then
      ND_V3_MODE="authPriv"
      break
    fi
    if [[ "${pm}" == "2" ]]; then
      ND_V3_MODE="authNoPriv"
      break
    fi
    warn "Invalid selection. Enter 1 or 2."
  done

  ND_V3_PRIV_PROTO=""
  ND_V3_PRIV_PASS=""

  if [[ "${ND_V3_MODE}" == "authPriv" ]]; then
    # Priv proto (strict)
    while true; do
      read -rp "Priv protocol (AES|DES) [AES]: " ND_V3_PRIV_PROTO
      ND_V3_PRIV_PROTO="${ND_V3_PRIV_PROTO:-AES}"
      ND_V3_PRIV_PROTO="$(echo "$ND_V3_PRIV_PROTO" | tr '[:lower:]' '[:upper:]')"
      if [[ -z "${ND_V3_PRIV_PROTO}" ]]; then
        warn "Cancelled."
        return 0
      fi
      if [[ "${ND_V3_PRIV_PROTO}" == "AES" || "${ND_V3_PRIV_PROTO}" == "DES" ]]; then
        break
      fi
      warn "Invalid priv protocol. Valid: AES or DES."
    done

    # Priv passphrase (loop; do not error out)
    while true; do
      read -rsp "Priv passphrase (min 8 chars): " ND_V3_PRIV_PASS
      echo
      if [[ -z "${ND_V3_PRIV_PASS}" ]]; then
        warn "Cancelled."
        return 0
      fi
      if [[ ${#ND_V3_PRIV_PASS} -ge 8 ]]; then
        break
      fi
      warn "Too short. Priv passphrase must be at least 8 characters. Try again (or press ENTER to cancel)."
    done
  fi

  # Write authoritative YAML (discover_snmpver=3, no_auth=false, device_auth populated)
  netdisco_write_snmpv3_yaml || return 1

  # Verify persistence on host
  local f="${INSTALL_DIR}/netdisco/environments/deployment.yml"
  if ! grep -q '^discover_snmpver:[[:space:]]*3' "$f" || ! grep -q '^[[:space:]]*-[[:space:]]*tag:' "$f"; then
    err "SNMPv3 profile write verification failed (deployment.yml did not contain expected values)."
    echo "File: $f"
    return 1
  fi

  # If container is running, enforce bind-mount and restart to reload
  netdisco_require_env_mount || return 1

  log "SNMPv3 READ-ONLY profile written successfully."
  log "Restarting Netdisco backend/web to reload config..."
  as_user docker compose restart netdisco-backend netdisco-web >/dev/null 2>&1 || true
}

# ------------------------------------------------------------
# NetBox plugins support (derived image build)
# ------------------------------------------------------------
plugins_enabled() {
  cd_install_dir
  [[ -f netbox-custom/config/plugins.py ]] && grep -q "netbox_topology_views\|netbox_bgp" netbox-custom/config/plugins.py
}

write_plugins_py_enabled() {
  cd_install_dir
  cat > netbox-custom/config/plugins.py <<EOF
# Managed by ${SCRIPT_NAME} v${SCRIPT_VERSION}
PLUGINS = [
  '${NB_PLUGIN_TOPOLOGY_MOD}',
  '${NB_PLUGIN_BGP_MOD}',
]

PLUGINS_CONFIG = {
  '${NB_PLUGIN_TOPOLOGY_MOD}': {
    'static_image_directory': '${NB_PLUGIN_TOPOLOGY_MOD}/img',
    'allow_coordinates_saving': True,
    'always_save_coordinates': True,
  }
}
EOF
  chmod 0644 netbox-custom/config/plugins.py || true
}

write_plugins_py_disabled() {
  cd_install_dir
  cat > netbox-custom/config/plugins.py <<EOF
# Managed by ${SCRIPT_NAME} v${SCRIPT_VERSION}
PLUGINS = []
PLUGINS_CONFIG = {}
EOF
  chmod 0644 netbox-custom/config/plugins.py || true
}

write_netbox_plugin_dockerfile() {
  cd_install_dir
  cat > netbox-custom/build/Dockerfile <<'EOF'
ARG NETBOX_IMAGE=netboxcommunity/netbox:latest
FROM ${NETBOX_IMAGE}

# ---- pip bootstrap (Dockerfile-safe) ----
RUN set -e; \
    V=/opt/netbox/venv/bin/python; \
    if [ ! -x "$V" ] && [ -x /opt/netbox/venv/bin/python3 ]; then V=/opt/netbox/venv/bin/python3; fi; \
    "$V" -m pip --version >/dev/null 2>&1 || "$V" -m ensurepip --upgrade || true

RUN /opt/netbox/venv/bin/python - <<'PY'
import os, tempfile, urllib.request
url = "https://bootstrap.pypa.io/get-pip.py"
fd, path = tempfile.mkstemp(prefix="get-pip-", suffix=".py")
os.close(fd)
urllib.request.urlretrieve(url, path)
with open(path, "rb") as f:
    code = compile(f.read(), path, "exec")
exec(code, {"__name__": "__main__"})
PY

RUN /opt/netbox/venv/bin/python -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/netbox/venv/bin/python -m pip install --no-cache-dir \
      netbox-topology-views \
      netbox-bgp

RUN mkdir -p /opt/netbox/netbox/static/netbox_topology_views/img
EOF
}

# ------------------------------------------------------------
# Compose generation (with optional plugin build)
# ------------------------------------------------------------
generate_compose_yml() {
  cd_install_dir

  local netbox_service
  if plugins_enabled; then
    netbox_service=$(cat <<'EOS'
  netbox:
    build:
      context: ./netbox-custom/build
      dockerfile: Dockerfile
      args:
        NETBOX_IMAGE: netboxcommunity/netbox:latest
    env_file: [.env]
    ports: ["8000:8080"]
    volumes:
      - netbox_media:/opt/netbox/netbox/media
      - netbox_reports:/opt/netbox/netbox/reports
      - netbox_scripts:/opt/netbox/netbox/scripts
      - ./netbox-custom/config/plugins.py:/etc/netbox/config/plugins.py:ro
    restart: unless-stopped
EOS
)
  else
    netbox_service=$(cat <<'EOS'
  netbox:
    image: netboxcommunity/netbox:latest
    env_file: [.env]
    ports: ["8000:8080"]
    volumes:
      - netbox_media:/opt/netbox/netbox/media
      - netbox_reports:/opt/netbox/netbox/reports
      - netbox_scripts:/opt/netbox/netbox/scripts
      - ./netbox-custom/config/plugins.py:/etc/netbox/config/plugins.py:ro
    restart: unless-stopped
EOS
)
  fi

  cat > docker-compose.yml <<EOF
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: netbox
      POSTGRES_USER: netbox
      POSTGRES_PASSWORD: netbox
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

  redis-cache:
    image: redis:7-alpine
    restart: unless-stopped

${netbox_service}

  netdisco-backend:
    image: netdisco/netdisco:latest-backend
    env_file: [netdisco.env]
    volumes:
      - ./netdisco/environments:/home/netdisco/environments
      - ./netdisco/nd-site-local:/home/netdisco/nd-site-local
      - ./netdisco/logs:/home/netdisco/logs
    restart: unless-stopped

  netdisco-web:
    image: netdisco/netdisco:latest-web
    env_file: [netdisco.env]
    ports: ["5000:5000"]
    volumes:
      - ./netdisco/environments:/home/netdisco/environments
      - ./netdisco/nd-site-local:/home/netdisco/nd-site-local
      - ./netdisco/logs:/home/netdisco/logs
    restart: unless-stopped

volumes:
  postgres_data:
  netbox_media:
  netbox_reports:
  netbox_scripts:
EOF
}

# ------------------------------------------------------------
# Netdisco DB init (IDEMPOTENT + POSTGRES-SAFE)
# ------------------------------------------------------------
init_netdisco_db() {
  cd_install_dir
  log "Ensuring Netdisco database exists"

  # Check if DB exists
  local exists
  exists="$(as_user docker compose exec -T postgres \
      psql -U netbox -tAc "SELECT 1 FROM pg_database WHERE datname='netdisco';" || true)"

  if [[ "$exists" == "1" ]]; then
    log "Netdisco database already exists"
  else
    log "Creating Netdisco database..."
    as_user docker compose exec -T postgres \
      psql -U netbox -v ON_ERROR_STOP=1 \
      -c "CREATE DATABASE netdisco;"
    log "Netdisco database created"
  fi

  log "Initializing / verifying Netdisco schema"
  as_user docker compose exec netdisco-backend \
    /home/netdisco/bin/netdisco-env /home/netdisco/bin/netdisco-updatedb.sh
}

# ------------------------------------------------------------
# NetBox plugins actions
# ------------------------------------------------------------
enable_netbox_plugins() {
  cd_install_dir
  write_plugins_py_enabled
  write_netbox_plugin_dockerfile
  generate_compose_yml

  log "Building NetBox image with plugins..."
  as_user docker compose build netbox

  log "Restarting NetBox to load plugins..."
  as_user docker compose up -d netbox
}

disable_netbox_plugins() {
  cd_install_dir
  write_plugins_py_disabled
  generate_compose_yml

  log "Restarting NetBox without plugins (stock image)..."
  as_user docker compose up -d netbox
}

plugin_status() {
  cd_install_dir
  echo
  echo "NetBox plugin status:"
  if plugins_enabled; then
    echo "  Enabled: YES"
    echo "  Build image: YES (derived NetBox image)"
  else
    echo "  Enabled: NO"
    echo "  Build image: NO (stock NetBox image)"
  fi
  echo
  echo "plugins.py:"
  if [[ -f netbox-custom/config/plugins.py ]]; then
    sed -n '1,200p' netbox-custom/config/plugins.py
  else
    echo "  (missing)"
  fi
  echo
}

# ------------------------------------------------------------
# Core stack actions
# ------------------------------------------------------------
install_or_update_stack() {
  ensure_install_dir
  cd_install_dir

  ensure_dirs
  generate_netbox_env
  generate_netdisco_env
  ensure_netdisco_deployment_yml
  
  if [[ ! -f netbox-custom/config/plugins.py ]]; then
    write_plugins_py_disabled
  fi

  write_netbox_plugin_dockerfile
  generate_compose_yml

  log "Starting core services"
  as_user docker compose up -d postgres redis redis-cache netbox
  wait_for_postgres

  log "Starting Netdisco backend"
  as_user docker compose up -d netdisco-backend
  init_netdisco_db

  log "Starting Netdisco web"
  as_user docker compose up -d netdisco-web

  wait_for_http "NetBox" "http://localhost:${NETBOX_PORT}" 300
  wait_for_http "Netdisco" "http://localhost:${NETDISCO_PORT}" 300
  generate_netbox_tokens
  with_netbox_rw netbox_ensure_tokens
  log "All services operational"
}

start_stack()   { cd_install_dir; as_user docker compose up -d; }
stop_stack()    { cd_install_dir; as_user docker compose down; }
restart_stack() { cd_install_dir; as_user docker compose restart; }
status_stack()  { cd_install_dir; as_user docker compose ps; }
logs_stack()    { cd_install_dir; as_user docker compose logs -f; }

# ------------------------------------------------------------
# Discovery config & menu_main wiring (Model 2) - NO IMPORTERS YET
# ------------------------------------------------------------
discovery_ensure_paths() {
  cd_install_dir
  mkdir -p "${DISCOVERY_REPORTS_DIR}"
}

discovery_load_config() {
  cd_install_dir
  discovery_ensure_paths
  if [[ -f "${DISCOVERY_CFG}" ]]; then
    # shellcheck disable=SC1090
    source "${DISCOVERY_CFG}"
  else
    discovery_save_config
  fi
}

discovery_save_config() {
  cd_install_dir
  discovery_ensure_paths
  cat > "${DISCOVERY_CFG}" <<EOF
# Managed by ${SCRIPT_NAME} v${SCRIPT_VERSION}
DISC_NETDISCO_NETWORK=${DISC_NETDISCO_NETWORK}
DISC_VMWARE_VCENTER=${DISC_VMWARE_VCENTER}
DISC_PROXMOX=${DISC_PROXMOX}
DISC_BAREMETAL_AD=${DISC_BAREMETAL_AD}
DISC_BAREMETAL_SSH=${DISC_BAREMETAL_SSH}
DISC_CLOUD_AWS=${DISC_CLOUD_AWS}
DISC_CLOUD_AZURE=${DISC_CLOUD_AZURE}
DISC_CLOUD_GCP=${DISC_CLOUD_GCP}
DISC_ACTIVE_SCANNING=${DISC_ACTIVE_SCANNING}
EOF
  chmod 0640 "${DISCOVERY_CFG}" || true
}

discovery_enabled_sources_list() {
  discovery_load_config
  local out=()
  [[ "${DISC_NETDISCO_NETWORK}" == "1" ]] && out+=("netdisco_network")
  [[ "${DISC_VMWARE_VCENTER}" == "1" ]] && out+=("vmware_vcenter")
  [[ "${DISC_PROXMOX}" == "1" ]] && out+=("proxmox")
  [[ "${DISC_BAREMETAL_AD}" == "1" ]] && out+=("baremetal_ad")
  [[ "${DISC_BAREMETAL_SSH}" == "1" ]] && out+=("baremetal_ssh_winrm")
  [[ "${DISC_CLOUD_AWS}" == "1" ]] && out+=("cloud_aws")
  [[ "${DISC_CLOUD_AZURE}" == "1" ]] && out+=("cloud_azure")
  [[ "${DISC_CLOUD_GCP}" == "1" ]] && out+=("cloud_gcp")
  [[ "${DISC_ACTIVE_SCANNING}" == "1" ]] && out+=("active_scanning")
  printf "%s\n" "${out[@]}"
}

discovery_status() {
  cd_install_dir
  discovery_load_config
  echo
  echo "Discovery Sources (Model 2):"
  printf "  %-28s %s\n" "Netdisco (network):"      "$([[ ${DISC_NETDISCO_NETWORK} == 1 ]] && echo ENABLED || echo DISABLED)"
  printf "  %-28s %s\n" "VMware vCenter:"          "$([[ ${DISC_VMWARE_VCENTER} == 1 ]] && echo ENABLED || echo DISABLED)"
  printf "  %-28s %s\n" "Proxmox:"                 "$([[ ${DISC_PROXMOX} == 1 ]] && echo ENABLED || echo DISABLED)"
  printf "  %-28s %s\n" "Bare metal (AD):"         "$([[ ${DISC_BAREMETAL_AD} == 1 ]] && echo ENABLED || echo DISABLED)"
  printf "  %-28s %s\n" "Bare metal (SSH/WinRM):"   "$([[ ${DISC_BAREMETAL_SSH} == 1 ]] && echo ENABLED || echo DISABLED)"
  printf "  %-28s %s\n" "Cloud (AWS):"             "$([[ ${DISC_CLOUD_AWS} == 1 ]] && echo ENABLED || echo DISABLED)"
  printf "  %-28s %s\n" "Cloud (Azure):"           "$([[ ${DISC_CLOUD_AZURE} == 1 ]] && echo ENABLED || echo DISABLED)"
  printf "  %-28s %s\n" "Cloud (GCP):"             "$([[ ${DISC_CLOUD_GCP} == 1 ]] && echo ENABLED || echo DISABLED)"
  printf "  %-28s %s\n" "Active scanning (Nmap):"   "$([[ ${DISC_ACTIVE_SCANNING} == 1 ]] && echo ENABLED || echo DISABLED)"
  echo
  echo "Config file:"
  echo "  ${INSTALL_DIR}/${DISCOVERY_CFG}"
  echo
  if [[ -f "${DISCOVERY_LAST_DRYRUN_FILE}" ]]; then
    echo "Last dry-run report:"
    echo "  ${INSTALL_DIR}/${DISCOVERY_LAST_DRYRUN_FILE}"
  else
    echo "Last dry-run report: (none yet)"
  fi
  if [[ -f "${DISCOVERY_LAST_APPLY_FILE}" ]]; then
    echo "Last apply report:"
    echo "  ${INSTALL_DIR}/${DISCOVERY_LAST_APPLY_FILE}"
  else
    echo "Last apply report: (none yet)"
  fi
  echo
}

discovery_toggle_menu() {
  cd_install_dir
  discovery_load_config
  while true; do
    clear
    echo "======================================"
    echo " Discovery: Toggle sources (Model 2)"
    echo "======================================"
    echo "[1] Netdisco (network)        [$([[ ${DISC_NETDISCO_NETWORK} == 1 ]] && echo ON || echo OFF)]"
    echo "[2] VMware vCenter            [$([[ ${DISC_VMWARE_VCENTER} == 1 ]] && echo ON || echo OFF)]"
    echo "[3] Proxmox                   [$([[ ${DISC_PROXMOX} == 1 ]] && echo ON || echo OFF)]"
    echo "[4] Bare metal (Active Dir)   [$([[ ${DISC_BAREMETAL_AD} == 1 ]] && echo ON || echo OFF)]"
    echo "[5] Bare metal (SSH/WinRM)    [$([[ ${DISC_BAREMETAL_SSH} == 1 ]] && echo ON || echo OFF)]"
    echo "[6] Cloud (AWS)               [$([[ ${DISC_CLOUD_AWS} == 1 ]] && echo ON || echo OFF)]"
    echo "[7] Cloud (Azure)             [$([[ ${DISC_CLOUD_AZURE} == 1 ]] && echo ON || echo OFF)]"
    echo "[8] Cloud (GCP)               [$([[ ${DISC_CLOUD_GCP} == 1 ]] && echo ON || echo OFF)]"
    echo "[9] Active scanning (Nmap)    [$([[ ${DISC_ACTIVE_SCANNING} == 1 ]] && echo ON || echo OFF)]"
    echo
    echo "ENTER = Save + return"
    read -rp "Toggle which source [1-9]: " sel
    if [[ -z "${sel}" ]]; then
      discovery_save_config
      log "Discovery source toggles saved."
      return 0
    fi
    case "$sel" in
      1) DISC_NETDISCO_NETWORK=$((1-DISC_NETDISCO_NETWORK)) ;;
      2) DISC_VMWARE_VCENTER=$((1-DISC_VMWARE_VCENTER)) ;;
      3) DISC_PROXMOX=$((1-DISC_PROXMOX)) ;;
      4) DISC_BAREMETAL_AD=$((1-DISC_BAREMETAL_AD)) ;;
      5) DISC_BAREMETAL_SSH=$((1-DISC_BAREMETAL_SSH)) ;;
      6) DISC_CLOUD_AWS=$((1-DISC_CLOUD_AWS)) ;;
      7) DISC_CLOUD_AZURE=$((1-DISC_CLOUD_AZURE)) ;;
      8) DISC_CLOUD_GCP=$((1-DISC_CLOUD_GCP)) ;;
      9) DISC_ACTIVE_SCANNING=$((1-DISC_ACTIVE_SCANNING)) ;;
      *) ;;
    esac
  done

}

discovery_dry_run_all() {
  echo "[INFO] Discovery dry-run invoked (no changes will be applied)."
  cd_install_dir
  discovery_load_config
  discovery_ensure_paths
  local sources
  sources="$(discovery_enabled_sources_list || true)"
  if [[ -z "${sources}" ]]; then
    warn "No discovery sources enabled. Enable sources first."
    return 0
  fi

  local ts report
  ts="$(date '+%Y-%m-%d %H:%M:%S %z')"
  report="${DISCOVERY_REPORTS_DIR}/dry-run-$(date '+%Y%m%d-%H%M%S').json"

  cat > "${report}" <<EOF
{
  "mode": "dry-run",
  "timestamp": "${ts}",
  "enabled_sources": [
$(discovery_enabled_sources_list | awk '{printf "    \"%s\",\n",$0}' | sed '$ s/,$//')
  ],
  "note": "Menu wiring + config persistence only. Importers are not implemented yet.",
  "proposed_changes": {
    "devices_create": 0,
    "interfaces_add": 0,
    "links_create": 0,
    "skipped": 0
  }
}
EOF
  cp -f "${report}" "${DISCOVERY_LAST_DRYRUN_FILE}"
  log "Dry-run report written:"
  echo "  ${INSTALL_DIR}/${report}"
  echo "  (latest) ${INSTALL_DIR}/${DISCOVERY_LAST_DRYRUN_FILE}"
}

discovery_apply_all() {
  cd_install_dir
  discovery_load_config
  discovery_ensure_paths

  if [[ ! -f "${DISCOVERY_LAST_DRYRUN_FILE}" ]]; then
    err "No dry-run report found. Run 'Discovery: Dry-run' first."
    return 1
  fi

  echo
  echo "WARNING: This will write to NetBox once importers exist."
  echo "Right now, importers are NOT implemented; apply will only write an audit report."
  echo
  echo "Type APPLY to continue:"
  read -r confirm
  if [[ "${confirm}" != "APPLY" ]]; then
    warn "Apply cancelled."
    return 0
  fi

  local ts report
  ts="$(date '+%Y-%m-%d %H:%M:%S %z')"
  report="${DISCOVERY_REPORTS_DIR}/apply-$(date '+%Y%m%d-%H%M%S').json"
  cat > "${report}" <<EOF
{
  "mode": "apply",
  "timestamp": "${ts}",
  "enabled_sources": [
$(discovery_enabled_sources_list | awk '{printf "    \"%s\",\n",$0}' | sed '$ s/,$//')
  ],
  "note": "Importers are not implemented yet. No NetBox writes were performed.",
  "applied_changes": {
    "devices_created": 0,
    "interfaces_added": 0,
    "links_created": 0
  }
}
EOF
  cp -f "${report}" "${DISCOVERY_LAST_APPLY_FILE}"
  log "Apply audit report written:"
  echo "  ${INSTALL_DIR}/${report}"
  echo "  (latest) ${INSTALL_DIR}/${DISCOVERY_LAST_APPLY_FILE}"
}

discovery_view_last_report() {
  cd_install_dir
  discovery_load_config
  echo
  if [[ -f "${DISCOVERY_LAST_DRYRUN_FILE}" ]]; then
    echo "=== Last Dry-Run Report ==="
    sed -n '1,240p' "${DISCOVERY_LAST_DRYRUN_FILE}"
    echo
  else
    echo "No dry-run report yet."
    echo
  fi
  if [[ -f "${DISCOVERY_LAST_APPLY_FILE}" ]]; then
    echo "=== Last Apply Report ==="
    sed -n '1,240p' "${DISCOVERY_LAST_APPLY_FILE}"
    echo
  else
    echo "No apply report yet."
    echo
  fi
}

# ------------------------------------------------------------
# Netdisco safety checks + config writers
# ------------------------------------------------------------
netdisco_require_env_mount() {
  cd_install_dir
  local host_dir="${INSTALL_DIR}/netdisco/environments"
  local cont_dir="/home/netdisco/environments"

  if [[ ! -d "$host_dir" ]]; then
    err "Netdisco environments directory missing on host:"
    echo "  $host_dir"
    return 1
  fi

  if ! as_user docker compose ps netdisco-backend >/dev/null 2>&1; then
    warn "Netdisco backend not running; skipping mount validation."
    return 0
  fi

  local stamp=".bind_test_$(date +%s)"
  touch "$host_dir/$stamp"

  if ! as_user docker compose exec -T netdisco-backend test -f "$cont_dir/$stamp"; then
    rm -f "$host_dir/$stamp"
    err "Netdisco environments directory is NOT bind-mounted into the container."
    echo "FIX: add volume ./netdisco/environments:/home/netdisco/environments"
    return 1
  fi

  rm -f "$host_dir/$stamp"
  return 0
}

netdisco_write_snmpv3_yaml() {
  cd_install_dir
  local f="netdisco/environments/deployment.yml"
  mkdir -p netdisco/environments

  cat > "$f" <<EOF
no_auth: false
discover_snmpver: 3
device_auth:
  - tag: ${ND_V3_TAG}
    user: ${ND_V3_USER}
    ro: true
    auth:
      proto: ${ND_V3_AUTH_PROTO}
      pass: ${ND_V3_AUTH_PASS}
$( [[ "${ND_V3_MODE}" == "authPriv" ]] && cat <<EOP
    priv:
      proto: ${ND_V3_PRIV_PROTO}
      pass: ${ND_V3_PRIV_PASS}
EOP
)
EOF
}

# ------------------------------------------------------------
# Netdisco SNMP Credentials MACD (Move/Add/Change/Delete) manager
# - Stores canonical creds in netdisco/environments/credentials.db (line-based)
# - Regenerates netdisco/environments/deployment.yml from the DB
# - Keeps v2c community in netdisco.env (NETDISCO_RO_COMMUNITY) in sync
# Format (one per line, | separated):
#   v3|<tag>|<user>|<auth_proto>|<auth_pass>|<mode authPriv|authNoPriv>|<priv_proto>|<priv_pass>
#   v2c|<tag>|<community>
# SECURITY: file contains secrets. Permissions are restricted.
SNMP_DB_REL="netdisco/environments/credentials.db"
SNMP_DB_PERM="0640"
SNMP_OWNER_GID="901"

snmp_db_path() { echo "${INSTALL_DIR}/${SNMP_DB_REL}"; }

snmp_db_ensure() {
  cd_install_dir
  mkdir -p netdisco/environments
  local db
  db="$(snmp_db_path)"
  if [[ ! -f "$db" ]]; then
    sudo touch "$db"
    sudo chgrp "${SNMP_OWNER_GID}" "$db" 2>/dev/null || true
    sudo chmod "${SNMP_DB_PERM}" "$db" 2>/dev/null || true
  fi
}

snmp_db_list_raw() {
  snmp_db_ensure
  local db
  db="$(snmp_db_path)"
  # DB is root-owned (security). Always read via sudo.
  sudo cat "$db" 2>/dev/null | grep -vE '^\s*($|#)' || true
}

snmp_db_list_tags() {
  snmp_db_list_raw | awk -F'|' '{print $2}' | sed '/^\s*$/d' || true
}

snmp_db_tag_exists() {
  local tag="$1"
  snmp_db_list_raw | awk -F'|' -v t="$tag" '$2==t {found=1} END{exit(found?0:1)}'
}

snmp_db_get_line_by_tag() {
  local tag="$1"
  snmp_db_list_raw | awk -F'|' -v t="$tag" '$2==t {print $0; exit 0}'
}

snmp_db_delete_tag() {
  cd_install_dir
  snmp_db_ensure
  local tag="$1"
  local db tmp
  db="$(snmp_db_path)"
  tmp="$(mktemp)"
  sudo awk -F'|' -v t="$tag" 'BEGIN{OFS="|"} {if($2!=t) print $0}' "$db" > "$tmp" 2>/dev/null || true
  sudo cp "$tmp" "$db"
  rm -f "$tmp"
  sudo chgrp "${SNMP_OWNER_GID}" "$db" 2>/dev/null || true
  sudo chmod "${SNMP_DB_PERM}" "$db" 2>/dev/null || true
}

snmp_db_upsert_line() {
  cd_install_dir
  snmp_db_ensure
  local newline="$1"
  local tag
  tag="$(echo "$newline" | awk -F'|' '{print $2}')"
  local db tmp
  db="$(snmp_db_path)"
  tmp="$(mktemp)"
  # Read/write DB with sudo (DB is root-owned for security). Replace any existing line with same tag, then append newline.
  sudo awk -F'|' -v t="$tag" -v nl="$newline" 'BEGIN{OFS="|"} {if($2!=t) print $0} END{print nl}' "$db" > "$tmp" 2>/dev/null || {
    echo "$newline" > "$tmp"
  }
  sudo cp "$tmp" "$db"
  rm -f "$tmp"
  sudo chgrp "${SNMP_OWNER_GID}" "$db" 2>/dev/null || true
  sudo chmod "${SNMP_DB_PERM}" "$db" 2>/dev/null || true
}

snmp_db_reorder_tag() {
  # Move: reorder by placing the selected tag at a new index (1-based)
  cd_install_dir
  snmp_db_ensure
  local tag="$1"
  local newpos="$2"
  local db tmp line
  db="$(snmp_db_path)"
  tmp="$(mktemp)"

  line="$(snmp_db_get_line_by_tag "$tag")"
  [[ -z "$line" ]] && err "Tag not found: $tag" && rm -f "$tmp" && return 1

  # Write all other lines to tmp
  snmp_db_list_raw | awk -F'|' -v t="$tag" '$2!=t {print $0}' > "$tmp"

  # Insert at position newpos
  local out
  out="$(mktemp)"
  awk -v pos="$newpos" -v ins="$line" 'BEGIN{c=0} {
      c++; 
      if(c==pos) {print ins}
      print $0
    } END {
      if(pos>c+1) print ins
      if(c==0) print ins
      if(pos==c+1) print ins
    }' "$tmp" > "$out"

  sudo cp "$out" "$db"
  rm -f "$tmp" "$out"
  sudo chgrp "${SNMP_OWNER_GID}" "$db" 2>/dev/null || true
  sudo chmod "${SNMP_DB_PERM}" "$db" 2>/dev/null || true
}

snmp_sync_v2c_to_env() {
  # If any v2c entry exists, set NETDISCO_RO_COMMUNITY to the FIRST v2c entry's community.
  cd_install_dir
  local db envf comm
  db="$(snmp_db_path)"
  envf="${INSTALL_DIR}/netdisco.env"
  comm="$(snmp_db_list_raw | awk -F'|' '$1=="v2c" {print $3; exit 0}')"
  [[ -z "$comm" ]] && return 0

  # Ensure netdisco.env exists
  if [[ ! -f "$envf" ]]; then
    : > "$envf"
    chmod 0640 "$envf" || true
  fi

  if grep -q '^NETDISCO_RO_COMMUNITY=' "$envf"; then
    sed -i "s/^NETDISCO_RO_COMMUNITY=.*/NETDISCO_RO_COMMUNITY=${comm}/" "$envf"
  else
    echo "NETDISCO_RO_COMMUNITY=${comm}" >> "$envf"
  fi
}

snmp_regen_deployment_from_db() {
  # Regenerate deployment.yml from DB. If no v3 creds exist, keep discover_snmpver=2 and device_auth: []
  cd_install_dir
  snmp_db_ensure
  local yml="${INSTALL_DIR}/netdisco/environments/deployment.yml"
  local v3count
  v3count="$(snmp_db_list_raw | awk -F'|' '$1=="v3"{c++} END{print (c+0)}')"

  if [[ "$v3count" -gt 0 ]]; then
    {
      echo "# Netdisco deployment config"
      echo "# Managed by NetBox Docker Manager"
      echo "#"
      echo "# SECURITY: this file can contain secrets. Restrict permissions."
      echo "no_auth: false"
      echo "discover_snmpver: 3"
      echo
      echo "device_auth:"
      snmp_db_list_raw | awk -F'|' '$1=="v3"{print $0}' | while IFS='|' read -r typ tag user aproto apass mode pproto ppass; do
        echo "  - tag: ${tag}"
        echo "    user: ${user}"
        echo "    ro: true"
        echo "    auth:"
        echo "      proto: ${aproto}"
        echo "      pass: ${apass}"
        if [[ "${mode}" == "authPriv" ]]; then
          echo "    priv:"
          echo "      proto: ${pproto}"
          echo "      pass: ${ppass}"
        fi
        echo
      done
    } > "$yml"
  else
    {
      echo "# Netdisco deployment config"
      echo "# Managed by NetBox Docker Manager"
      echo "#"
      echo "# SECURITY: this file can contain secrets. Restrict permissions."
      echo "no_auth: true"
      echo "discover_snmpver: 2"
      echo "device_auth: []"
    } > "$yml"
  fi

  chmod 0640 "$yml" || true
  chgrp "${SNMP_OWNER_GID}" "$yml" 2>/dev/null || true

  # Keep v2c env in sync if present
  snmp_sync_v2c_to_env || true
}

snmp_restart_netdisco() {
  cd_install_dir
  snmp_dbg "Restarting Netdisco services"
  as_user docker compose restart netdisco-backend netdisco-web >/dev/null 2>&1 || true
}

snmp_credentials_list() {
  cd_install_dir
  snmp_db_ensure
  netdisco_require_env_mount || return 1
  echo
  echo "=== SNMP Credentials (DB + effective config) ==="
  echo "DB: ${INSTALL_DIR}/${SNMP_DB_REL}"
  if [[ -f "${INSTALL_DIR}/${SNMP_DB_REL}" ]]; then
    echo "[INFO] DB is root-owned for security; reads/writes use sudo."
  fi
  echo

  local i=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    i=$((i+1))
    typ="$(echo "$line" | awk -F'|' '{print $1}')"
    if [[ "$typ" == "v3" ]]; then
      tag="$(echo "$line" | awk -F'|' '{print $2}')"
      user="$(echo "$line" | awk -F'|' '{print $3}')"
      aproto="$(echo "$line" | awk -F'|' '{print $4}')"
      mode="$(echo "$line" | awk -F'|' '{print $6}')"
      pproto="$(echo "$line" | awk -F'|' '{print $7}')"
      echo "[$i] tag: $tag"
      echo "    type: SNMPv3 (RO)"
      echo "    user: $user"
      echo "    auth: $aproto"
      echo "    priv: $([[ "$mode" == "authPriv" ]] && echo "$pproto" || echo "(none)")"
      echo
    elif [[ "$typ" == "v2c" ]]; then
      tag="$(echo "$line" | awk -F'|' '{print $2}')"
      echo "[$i] tag: $tag"
      echo "    type: SNMPv2c (RO)"
      echo "    community: *******"
      echo
    fi
  done < <(snmp_db_list_raw)

  if [[ "$i" -eq 0 ]]; then
    echo "(none)"
    echo
  fi

  echo "Effective Netdisco deployment.yml (redacted):"
  netdisco_profiles_show || true
}

snmp_credentials_add() {
  echo ">>> ENTERED snmp_credentials_add (v1.6.4) <<<"
  # Hard proof marker (host)
  cd_install_dir
  mkdir -p "${INSTALL_DIR}/logs"
  echo "entered $(date '+%Y-%m-%d %H:%M:%S') user=$(whoami) pwd=$(pwd)" | sudo tee "${INSTALL_DIR}/logs/snmp-entered.flag" >/dev/null 2>&1 || true
  snmp_dbg "ENTERED snmp_credentials_add (hard proof). marker=${INSTALL_DIR}/logs/snmp-entered.flag"
  snmp_dbg "SNMP ADD START (user=$(whoami), install_dir=${INSTALL_DIR})"
  cd_install_dir
  mkdir -p "${INSTALL_DIR}/netdisco/environments"
cd_install_dir
  mkdir -p netdisco/environments
  snmp_db_ensure

  echo
  echo "Add SNMP credential"
  echo "------------------"
  echo "1) SNMPv3 (RO)"
  echo "2) SNMPv2c (RO)"
  read -rp "Select [1]: " kind
  kind="${kind:-1}"

  read -rp "Tag (unique) [v3_ro_default]: " tag
  tag="${tag:-v3_ro_default}"
  [[ -z "$tag" ]] && warn "Cancelled." && return 0
  if snmp_db_tag_exists "$tag"; then
    err "Tag already exists: $tag (use Change instead)"
    return 1
  fi

  if [[ "$kind" == "2" ]]; then
    # v2c
    while true; do
      read -rsp "RO community (min 1 char): " comm
      echo
      [[ -z "$comm" ]] && warn "Cancelled." && return 0
      break
    done
    snmp_db_upsert_line "v2c|$tag|$comm"
  snmp_dbg "DB upsert called for tag=$tag"
  snmp_dbg_file_meta "$(snmp_db_path)"
  if ! sudo grep -q "^[^|]*\|${tag}\|" "$(snmp_db_path)" 2>/dev/null; then
    snmp_dbg "ERROR: DB verify failed for tag=$tag"
    err "DB verification failed for tag=$tag"
    return 1
  fi
    snmp_regen_deployment_from_db
    netdisco_require_env_mount || return 1
    snmp_restart_netdisco
    log "Added SNMPv2c credential tag=$tag and synced NETDISCO_RO_COMMUNITY."
    return 0
  fi

  # v3
  read -rp "SNMPv3 username: " user
  [[ -z "$user" ]] && warn "Cancelled." && return 0

  while true; do
    read -rp "Auth protocol (SHA|MD5) [SHA]: " aproto
    aproto="${aproto:-SHA}"
    aproto="$(echo "$aproto" | tr '[:lower:]' '[:upper:]')"
    [[ "$aproto" == "SHA" || "$aproto" == "MD5" ]] && break
    warn "Invalid. Use SHA or MD5."
  done

  while true; do
    read -rsp "Auth passphrase (min 8 chars): " apass
    echo
    [[ -z "$apass" ]] && warn "Cancelled." && return 0
    [[ ${#apass} -ge 8 ]] && break
    warn "Too short. Try again (or ENTER to cancel)."
  done

  echo "Privacy mode: 1) authPriv (recommended)  2) authNoPriv"
  read -rp "Select [1]: " pm
  pm="${pm:-1}"
  if [[ "$pm" == "2" ]]; then
    mode="authNoPriv"
    pproto=""
    ppass=""
  else
    mode="authPriv"
    while true; do
      read -rp "Priv protocol (AES|DES) [AES]: " pproto
      pproto="${pproto:-AES}"
      pproto="$(echo "$pproto" | tr '[:lower:]' '[:upper:]')"
      [[ "$pproto" == "AES" || "$pproto" == "DES" ]] && break
      warn "Invalid. Use AES or DES."
    done
    while true; do
      read -rsp "Priv passphrase (min 8 chars): " ppass
      echo
      [[ -z "$ppass" ]] && warn "Cancelled." && return 0
      [[ ${#ppass} -ge 8 ]] && break
      warn "Too short. Try again (or ENTER to cancel)."
    done
  fi

  snmp_db_upsert_line "v3|$tag|$user|$aproto|$apass|$mode|$pproto|$ppass"
  snmp_dbg "DB upsert called for tag=$tag"
  snmp_dbg_file_meta "$(snmp_db_path)"
  if ! sudo grep -q "^[^|]*\|${tag}\|" "$(snmp_db_path)" 2>/dev/null; then
    snmp_dbg "ERROR: DB verify failed for tag=$tag"
    err "DB verification failed for tag=$tag"
    return 1
  fi
  snmp_regen_deployment_from_db
  netdisco_require_env_mount || return 1
  snmp_restart_netdisco
  log "Added SNMPv3 credential tag=$tag and regenerated deployment.yml."
}

snmp_credentials_change() {
  cd_install_dir
  snmp_db_ensure
  echo
  echo "Change SNMP credential (by tag)"
  echo "-------------------------------"
  snmp_credentials_list
  read -rp "Enter tag to change: " tag
  [[ -z "$tag" ]] && warn "Cancelled." && return 0
  if ! snmp_db_tag_exists "$tag"; then
    err "Tag not found: $tag"
    return 1
  fi

  line="$(snmp_db_get_line_by_tag "$tag")"
  typ="$(echo "$line" | awk -F'|' '{print $1}')"
  if [[ "$typ" == "v2c" ]]; then
    while true; do
      read -rsp "New RO community (ENTER to cancel): " comm
      echo
      [[ -z "$comm" ]] && warn "Cancelled." && return 0
      break
    done
    snmp_db_upsert_line "v2c|$tag|$comm"
  snmp_dbg "DB upsert called for tag=$tag"
  snmp_dbg_file_meta "$(snmp_db_path)"
  if ! sudo grep -q "^[^|]*\|${tag}\|" "$(snmp_db_path)" 2>/dev/null; then
    snmp_dbg "ERROR: DB verify failed for tag=$tag"
    err "DB verification failed for tag=$tag"
    return 1
  fi
  else
    user="$(echo "$line" | awk -F'|' '{print $3}')"
    aproto="$(echo "$line" | awk -F'|' '{print $4}')"
    mode="$(echo "$line" | awk -F'|' '{print $6}')"
    pproto="$(echo "$line" | awk -F'|' '{print $7}')"

    read -rp "SNMPv3 username [$user]: " nuser
    user="${nuser:-$user}"

    while true; do
      read -rp "Auth protocol (SHA|MD5) [$aproto]: " nap
      nap="${nap:-$aproto}"
      nap="$(echo "$nap" | tr '[:lower:]' '[:upper:]')"
      [[ "$nap" == "SHA" || "$nap" == "MD5" ]] && aproto="$nap" && break
      warn "Invalid. Use SHA or MD5."
    done

    while true; do
      read -rsp "New auth passphrase (min 8, ENTER to keep): " apass
      echo
      if [[ -z "$apass" ]]; then
        apass="$(echo "$line" | awk -F'|' '{print $5}')"
        break
      fi
      [[ ${#apass} -ge 8 ]] && break
      warn "Too short. Try again."
    done

    echo "Privacy mode: 1) authPriv  2) authNoPriv"
    read -rp "Select [${mode/authPriv/1}]: " pm
    pm="${pm:-$([ "$mode" == "authNoPriv" ] && echo 2 || echo 1)}"
    if [[ "$pm" == "2" ]]; then
      mode="authNoPriv"
      pproto=""
      ppass=""
    else
      mode="authPriv"
      while true; do
        read -rp "Priv protocol (AES|DES) [${pproto:-AES}]: " npp
        npp="${npp:-${pproto:-AES}}"
        npp="$(echo "$npp" | tr '[:lower:]' '[:upper:]')"
        [[ "$npp" == "AES" || "$npp" == "DES" ]] && pproto="$npp" && break
        warn "Invalid. Use AES or DES."
      done
      while true; do
        read -rsp "New priv passphrase (min 8, ENTER to keep): " ppass
        echo
        if [[ -z "$ppass" ]]; then
          ppass="$(echo "$line" | awk -F'|' '{print $8}')"
          break
        fi
        [[ ${#ppass} -ge 8 ]] && break
        warn "Too short. Try again."
      done
    fi

    snmp_db_upsert_line "v3|$tag|$user|$aproto|$apass|$mode|$pproto|$ppass"
  snmp_dbg "DB upsert called for tag=$tag"
  snmp_dbg_file_meta "$(snmp_db_path)"
  if ! sudo grep -q "^[^|]*\|${tag}\|" "$(snmp_db_path)" 2>/dev/null; then
    snmp_dbg "ERROR: DB verify failed for tag=$tag"
    err "DB verification failed for tag=$tag"
    return 1
  fi
  fi

  snmp_regen_deployment_from_db
  netdisco_require_env_mount || return 1
  snmp_restart_netdisco
  log "Updated credential tag=$tag and regenerated deployment.yml."
}

snmp_credentials_delete() {
  cd_install_dir
  snmp_db_ensure
  echo
  echo "Delete SNMP credential (by tag)"
  echo "-------------------------------"
  snmp_credentials_list
  read -rp "Enter tag to delete: " tag
  [[ -z "$tag" ]] && warn "Cancelled." && return 0
  if ! snmp_db_tag_exists "$tag"; then
    err "Tag not found: $tag"
    return 1
  fi

  echo "Type DELETE to remove credential '$tag':"
  read -r confirm
  [[ "$confirm" != "DELETE" ]] && warn "Cancelled." && return 0

  snmp_db_delete_tag "$tag"
  snmp_regen_deployment_from_db
  netdisco_require_env_mount || return 1
  snmp_restart_netdisco
  log "Deleted credential tag=$tag."
}

snmp_credentials_move() {
  cd_install_dir
  snmp_db_ensure
  echo
  echo "Move SNMP credential priority (by tag)"
  echo "-------------------------------------"
  snmp_credentials_list
  read -rp "Enter tag to move: " tag
  [[ -z "$tag" ]] && warn "Cancelled." && return 0
  if ! snmp_db_tag_exists "$tag"; then
    err "Tag not found: $tag"
    return 1
  fi
  read -rp "New position (1 = highest priority): " pos
  [[ -z "$pos" ]] && warn "Cancelled." && return 0
  if ! [[ "$pos" =~ ^[0-9]+$ ]] || [[ "$pos" -lt 1 ]]; then
    err "Invalid position."
    return 1
  fi
  snmp_db_reorder_tag "$tag" "$pos" || return 1
  snmp_regen_deployment_from_db
  netdisco_require_env_mount || return 1
  snmp_restart_netdisco
  log "Moved credential tag=$tag to position $pos."
}

snmp_credentials_test() {
  cd_install_dir
  snmp_db_ensure
  netdisco_require_env_mount || return 1
  echo
  echo "Test SNMP credential (by tag)"
  echo "-----------------------------"
  snmp_credentials_list
  read -rp "Enter tag to test: " tag
  [[ -z "$tag" ]] && warn "Cancelled." && return 0
  if ! snmp_db_tag_exists "$tag"; then
    err "Tag not found: $tag"
    return 1
  fi
  read -rp "Target device IP/hostname: " target
  [[ -z "$target" ]] && warn "Cancelled." && return 0

  local dbline typ
  dbline="$(snmp_db_get_line_by_tag "$tag")"
  typ="$(echo "$dbline" | awk -F'|' '{print $1}')"

  # Backup current files
  local yml="${INSTALL_DIR}/netdisco/environments/deployment.yml"
  local envf="${INSTALL_DIR}/netdisco.env"
  local yml_bak env_bak
  yml_bak="$(mktemp)"
  env_bak="$(mktemp)"
  [[ -f "$yml" ]] && cp -f "$yml" "$yml_bak" || : > "$yml_bak"
  [[ -f "$envf" ]] && cp -f "$envf" "$env_bak" || : > "$env_bak"

  # Create temp config with ONLY the selected credential
  if [[ "$typ" == "v3" ]]; then
    # Write a deployment.yml with only this v3 credential
    local user aproto apass mode pproto ppass
    IFS='|' read -r _ _tag user aproto apass mode pproto ppass <<<"$dbline"
    {
      echo "# Netdisco deployment config"
      echo "no_auth: false"
      echo "discover_snmpver: 3"
      echo
      echo "device_auth:"
      echo "  - tag: ${_tag}"
      echo "    user: ${user}"
      echo "    ro: true"
      echo "    auth:"
      echo "      proto: ${aproto}"
      echo "      pass: ${apass}"
      if [[ "${mode}" == "authPriv" ]]; then
        echo "    priv:"
        echo "      proto: ${pproto}"
        echo "      pass: ${ppass}"
      fi
    } > "$yml"
  else
    # v2c test: keep deployment.yml as v2c-only (no v3 list)
    local comm
    comm="$(echo "$dbline" | awk -F'|' '{print $3}')"
    {
      echo "# Netdisco deployment config"
      echo "no_auth: true"
      echo "discover_snmpver: 2"
      echo "device_auth: []"
    } > "$yml"
    if grep -q '^NETDISCO_RO_COMMUNITY=' "$envf"; then
      sed -i "s/^NETDISCO_RO_COMMUNITY=.*/NETDISCO_RO_COMMUNITY=${comm}/" "$envf"
    else
      echo "NETDISCO_RO_COMMUNITY=${comm}" >> "$envf"
    fi
  fi

  snmp_restart_netdisco
  echo
  echo "=== Running Netdisco discover (debug) using ONLY credential tag=$tag ==="
  as_user docker compose exec -T netdisco-backend bash -lc \
    "export NETDISCO_LOG_LEVEL=debug; ~/bin/netdisco-do discover -d \"$target\"" || true
  echo

  # Restore originals
  cp -f "$yml_bak" "$yml" || true
  cp -f "$env_bak" "$envf" || true
  rm -f "$yml_bak" "$env_bak"
  snmp_restart_netdisco

  log "Credential test complete; original config restored."
}

snmp_credentials_menu() {
  snmp_reconcile_guard

  cd_install_dir
  while true; do
    clear
    echo "======================================"
    echo " SNMP Credentials (MACD)"
    echo "======================================"
    echo "22) List credentials (RO)"
    echo "23) Add credential (v2c/v3)"
    echo "24) Change credential (by tag)"
    echo "25) Delete credential (by tag)"
    echo "26) Move credential priority (by tag)"
    echo "27) Test credential (by tag)"
    echo "--------------------------------------"
    echo "0) Back"
    echo "======================================"
    read -rp "Select option: " sel
    case "$sel" in
      22) snmp_credentials_list; pause ;;
      23) snmp_credentials_add; pause ;;
      24) snmp_credentials_change; pause ;;
      25) snmp_credentials_delete; pause ;;
      26) snmp_credentials_move; pause ;;
      27) snmp_credentials_test; pause ;;
      0) return 0 ;;
      *) ;;
    esac
  done
}




snmp_reconcile_guard() {
  return 0
}




view_snmp_proof_markers() {
  cd_install_dir
  mkdir -p "${INSTALL_DIR}/logs" 2>/dev/null || true
  echo
  echo "=== SNMP Proof Markers (${INSTALL_DIR}/logs) ==="
  sudo ls -la "${INSTALL_DIR}/logs" 2>/dev/null || true
  echo
  echo "--- option9.flag ---"
  sudo sed -n '1,120p' "${INSTALL_DIR}/logs/option9.flag" 2>/dev/null || echo "(missing)"
  echo
  echo "--- snmp-entered.flag ---"
  sudo sed -n '1,120p' "${INSTALL_DIR}/logs/snmp-entered.flag" 2>/dev/null || echo "(missing)"
  echo
}

# ------------------------------------------------------------
# Menu
# ------------------------------------------------------------

# ------------------------------------------------------------
# Password Management
# ------------------------------------------------------------
change_netbox_admin_password() {
  echo "Change NetBox admin password (TTY-safe, settings-aware)"
  read -rp "Target NetBox username [admin]: " NBUSER
  NBUSER=${NBUSER:-admin}
  read -rsp "New NetBox password (min 12 chars): " PW1; echo
  read -rsp "Confirm password: " PW2; echo

  if [[ "$PW1" != "$PW2" ]]; then
    echo "[ERROR] Passwords do not match."
    return 1
  fi
  if [[ ${#PW1} -lt 12 ]]; then
    echo "[ERROR] Password must be at least 12 characters."
    return 1
  fi

  cd_install_dir

  docker compose exec -T netbox /opt/netbox/netbox/manage.py shell <<PY
from django.contrib.auth import get_user_model
User = get_user_model()
try:
    u = User.objects.get(username="${NBUSER}")
except User.DoesNotExist:
    raise SystemExit("User '${NBUSER}' not found")
u.set_password("${PW1}")
u.save()
print("Password updated for user '${NBUSER}'")
PY

  if [[ $? -eq 0 ]]; then
    echo "[INFO] NetBox password updated successfully."
  else
    echo "[ERROR] Failed to update NetBox password."
  fi
}

netdisco_password_ui_guidance() {
  echo "======================================"
  echo " Netdisco Password Management"
  echo "======================================"
  echo
  echo "Netdisco does NOT provide a supported CLI"
  echo "for changing user passwords."
  echo
  echo "Passwords must be changed via the Web UI:"
  echo
  echo "  1) Log into Netdisco Web UI"
  echo "  2) Click Admin → Users"
  echo "  3) Select the user (e.g. admin)"
  echo "  4) Change password and save"
  echo
  echo "This behavior is by design in Netdisco."
  echo
  pause
}

netdisco_password_emergency_reset() {
  echo "======================================"
  echo " Netdisco EMERGENCY Admin Password Reset"
  echo "======================================"
  echo
  echo "WARNING:"
  echo "This is an UNSUPPORTED recovery workflow"
  echo "documented by the Netdisco community:"
  echo "https://github.com/netdisco/netdisco/issues/689"
  echo
  echo "Use ONLY if you are locked out."
  read -rp "Type RESET to continue: " CONFIRM
  [[ "$CONFIRM" != "RESET" ]] && { echo "Aborted."; return; }

  cd_install_dir

  docker compose exec -it netdisco-backend bash <<'EOF'
set -e
echo "[INFO] Clearing admin flags in Netdisco DB"

if ! command -v netdisco-do >/dev/null 2>&1; then
  echo "[ERROR] netdisco-do not found in container."
  exit 1
fi

netdisco-do psql <<SQL
UPDATE users SET admin = false;
SQL

echo "[INFO] Admin flags cleared."
echo "[INFO] Attempting to re-run netdisco-deploy"

if command -v netdisco-deploy >/dev/null 2>&1; then
  netdisco-deploy
else
  echo "[ERROR] netdisco-deploy not found in this image."
  exit 1
fi
EOF

  echo
  echo "[INFO] Emergency reset workflow completed."
  pause
}




menu_main() {
  clear
  echo "======================================"
  echo " ${SCRIPT_NAME} (v${SCRIPT_VERSION})"
  echo "======================================"
  echo "Install dir: ${INSTALL_DIR:-<not set>}"
  if [[ -n "${SCRIPT_BASENAME:-}" && -n "${SCRIPT_PATH:-}" ]]; then
    echo "Script: ${SCRIPT_BASENAME} (${SCRIPT_PATH})"
  fi
  echo "--------------------------------------"
  echo "01) Install / Update stack (NetBox + Netdisco)"
  echo "02) Start stack"
  echo "03) Stop stack"
  echo "04) Restart stack"
  echo "05) Status"
  echo "06) View ALL logs"
echo "07) Change NetBox admin password"
echo "08) Netdisco: Change admin password (UI guidance)"
  echo "09) Netdisco: EMERGENCY admin password reset (UNSUPPORTED)"
  echo "--------------------------------------"
  echo "10) Netdisco: SNMP & credential guidance (UI hint)"
  echo "--------------------------------------"
  echo "20) SNMP Credentials: List (RO)"
  echo "21) SNMP Credentials: Add"
  echo "22) SNMP Credentials: Change"
  echo "23) SNMP Credentials: Delete"
  echo "24) SNMP Credentials: Reorder priority"
  echo "25) SNMP Credentials: Test credential"
  echo "--------------------------------------"
  echo "30) NetBox plugins: Status"
  echo "31) NetBox plugins: Enable (Topology Views + BGP)"
  echo "32) NetBox plugins: Disable (revert to stock)"
  echo "--------------------------------------"
  echo "40) Discovery: Status / Enabled sources"
  echo "41) Discovery: Toggle sources"
  echo "42) Discovery: Dry-run (validation only)"
  echo "43) Discovery: Apply approved changes"
  echo "44) Discovery: View last discovery report"
  echo "45) Discovery: Topology enrichment (LLDP / CDP)"
  echo "--------------------------------------"
  echo "50) Debug: View SNMP debug log"
  echo "51) Debug: View SNMP proof markers"
  echo "--------------------------------------"
  echo "99) Exit (Q/q)"
  echo "======================================"
  read -rp "Select option: " SEL

  case "$SEL" in
    01|1) install_or_update_stack ; pause ;;
    02|2) start_stack ; pause ;;
    03|3) stop_stack ; pause ;;
    04|4) restart_stack ; pause ;;
    05|5) status_stack ; pause ;;
    06|6) logs_stack ; pause ;;

    07|7) change_netbox_admin_password ; pause ;;
    08|8) netdisco_password_ui_guidance ; pause ;;

    09|9) netdisco_password_emergency_reset ; pause ;;

    10) show_netdisco_credential_ui_hint ; pause ;;

    20) snmp_credentials_list ; pause ;;
    21) snmp_credentials_add ; pause ;;
    22) snmp_credentials_change ; pause ;;
    23) snmp_credentials_delete ; pause ;;
    24) snmp_credentials_move ; pause ;;
    25) snmp_credentials_test ; pause ;;

    30) plugin_status ; pause ;;
    31) enable_netbox_plugins ; pause ;;
    32) disable_netbox_plugins ; pause ;;

    40) with_netbox_ro discovery_status ; pause ;;
    41) discovery_toggle_menu ; pause ;;
    42) with_netbox_ro discovery_diff ; pause ;;
    43) with_netbox_rw discovery_apply_full ; pause ;;
    44) discovery_view_last_report ; pause ;;
    45) with_netbox_rw discovery_import_neighbors ; pause ;;

    50) view_snmp_debug_log ; pause ;;
    51) view_snmp_proof_markers ; pause ;;

    99|Q|q) echo "Bye."; exit 0 ;;
    *) echo "Invalid option"; pause ;;
  esac
}
# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
init_runtime() {
  log_script_identity
  # Extracted init sequence (previously inline)
  install_docker
  ensure_docker_group
  ensure_install_dir
}

# ------------------------------------------------------------
# Execution (v1.9.0): single runnable menu loop only
# ------------------------------------------------------------
main() {
  init_runtime
  while true; do
    menu_main
  done
}

main "$@"

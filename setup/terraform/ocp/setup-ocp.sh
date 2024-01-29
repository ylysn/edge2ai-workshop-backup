#!/bin/bash
set -o nounset
set -o errexit
set -o pipefail
set -o xtrace
trap 'echo Setup return code: $?' 0
BASE_DIR=$(cd $(dirname $0); pwd -L)

if [ "$USER" == "root" ]; then
  echo "ERROR: This script ($0) must be executed by sudo user"
  exit 1
fi

ACTION=${1:-}

THE_PWD=Supersecret1
KEYTABS_DIR=$BASE_DIR/keytabs
KRB_REALM=WORKSHOP.COM

function log_status() {
  local msg=$1
  echo "STATUS:$msg"
}

function yum_install() {
  local packages=$@
  local retries=60
  while true; do
    set +e
    sudo yum install -d1 -y ${packages}
    RET=$?
    set -e
    if [[ ${RET} == 0 ]]; then
      break
    fi
    retries=$((retries - 1))
    if [[ ${retries} -lt 0 ]]; then
      echo 'YUM install failed!'
      exit 1
    else
      sleep 1
      echo 'Retrying YUM...'
    fi
  done
}

function install_ipa_client() {
  local ipa_host=${1:-}
  if [[ $ipa_host == "" ]]; then
    echo "WARN: No IPA server detected."
    exit 0
  fi

  # Install IPA client package
  yum_install ipa-client openldap-clients krb5-workstation krb5-libs

  # Remove IPA config
  echo "no" | sudo ipa-client-install --uninstall || true

  # Install IPA client
  sudo ipa-client-install \
    --principal=admin \
    --password="$THE_PWD" \
    --server="$IPA_HOST" \
    --realm="$KRB_REALM" \
    --domain="$(hostname -f | sed 's/^[^.]*\.//')" \
    --force-ntpd \
    --ssh-trust-dns \
    --all-ip-addresses \
    --ssh-trust-dns \
    --unattended \
    --mkhomedir \
    --force-join

  sudo systemctl stop ntpd || true
  sudo systemctl disable ntpd || true
  sudo systemctl restart chronyd || true

  # Enable enumeration for the SSSD client, so that Ranger Usersync can see users/groups
  sudo sed -i.bak 's/^\[domain.*/&\
enumerate = True\
ldap_enumeration_refresh_timeout = 50/;'\
's/^\[nss\].*/&\
enum_cache_timeout = 45/' /etc/sssd/sssd.conf
  sudo systemctl restart sssd
  sleep 60 # wait a bit and do it a second time for good measure
  sudo systemctl restart sssd

  # Adjust krb5.conf
  sudo sed -i 's/udp_preference_limit.*/udp_preference_limit = 1/;/KEYRING/d' /etc/krb5.conf

  # Copy keytabs from IPA server
  mkdir -p $KEYTABS_DIR
  rm -rf /tmp/keytabs
  wget --recursive --no-parent --no-host-directories "http://${IPA_HOST}/keytabs/" -P /tmp/keytabs
  mv -f /tmp/keytabs/keytabs/* ${KEYTABS_DIR}/
  find ${KEYTABS_DIR} -name "index.html*" -delete
  chmod 755 ${KEYTABS_DIR}
  chmod -R 444 ${KEYTABS_DIR}/*
}

function create_ca() {
  if [[ -s $ROOT_PEM ]]; then
    return
  fi

  mkdir -p $CA_DIR/newcerts
  touch $CA_DIR/index.txt
  echo "unique_subject = no" > $CA_DIR/index.txt.attr
  hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/random > $CA_DIR/serial

  # Generate CA key
  openssl genrsa \
    -out ${CA_KEY} \
    -aes256 \
    -passout pass:${CA_KEY_PWD} \
    2048
  chmod 400 ${CA_KEY}

  # Create the CA configuration
  cat > $CA_CONF <<EOF
HOME = ${CA_DIR}
RANDFILE = ${CA_DIR}/.rnd

[ ca ]
default_ca = CertToolkit # The default ca section

[ CertToolkit ]
dir = $HOME
database = $CA_DIR/index.txt # database index file.
serial = $CA_DIR/serial # The current serial number
new_certs_dir = $CA_DIR/newcerts # default place for new certs.
certificate = $ROOT_PEM # The CA certificate
private_key = $CA_KEY # The private key
default_md = sha256 # use public key default MD
unique_subject = no # Set to 'no' to allow creation of
# several ctificates with same subject.
policy = policy_any
preserve = no # keep passed DN ordering
default_days = 4000

name_opt = ca_default # Subject Name options
cert_opt = ca_default # Certificate field options

copy_extensions = copy

[ req ]
default_bits = 2048
default_md = sha256
distinguished_name = req_distinguished_name
string_mask = utf8only

[ req_distinguished_name ]
countryName_default = XX
countryName_min = 2
countryName_max = 2
localityName_default = Default City
0.organizationName_default = Default Company Ltd
commonName_max = 64
emailAddress_max = 64

[ policy_any ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ v3_common_extensions ]

[ v3_user_extensions ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer

[ v3_ca_extensions ]
basicConstraints = CA:TRUE
subjectAltName=email:${CA_EMAIL}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

  # Generate CA certificate
  openssl req -x509 -new -nodes \
    -sha256 \
    -key ${CA_KEY} \
    -days 4000 \
    -out ${ROOT_PEM} \
    -passin pass:${CA_KEY_PWD} \
    -passout pass:${CA_KEY_PWD} \
    -extensions v3_ca_extensions \
    -config ${CA_CONF} \
    -subj '/C=US/ST=California/L=San Francisco/O=Cloudera/OU=PS/CN=CertToolkitRootCA'
}


function wait_for_ipa() {
  local ipa_host=${1:-}
  local retries=300
  while [[ $retries -gt 0 ]]; do
    set +e
    ret=$(curl -s -o /dev/null -w "%{http_code}" "http://${ipa_host}/ca.crt")
    err=$?
    set -e
    if [[ $err == 0 && $ret == "200" ]]; then
      break
    fi
    retries=$((retries - 1))
    sleep 5
    echo "Waiting for IPA to be ready (retries left: $retries)"
  done
}

function create_certs() {
  local ipa_host=${1:-}

  mkdir -p $(dirname $KEY_PEM) $(dirname $CSR_PEM) $(dirname $HOST_PEM) ${SEC_BASE}/jks

  # Create private key
  openssl genrsa -des3 -out ${KEY_PEM} -passout pass:${KEY_PWD} 2048

  # Create CSR
  local public_ip=$(curl -sL http://ifconfig.me || curl -sL http://api.ipify.org/ || curl -sL https://ipinfo.io/ip)
  ALT_NAMES=""
  if [[ ! -z ${LOCAL_HOSTNAME:-} ]] && [ $LOCAL_HOSTNAME != $PUBLIC_DNS ] ; then
    ALT_NAMES="DNS:${LOCAL_HOSTNAME},"
  fi
  export ALT_NAMES="${ALT_NAMES}DNS:${PUBLIC_DNS},DNS:*.${PUBLIC_DNS},DNS:api.${PUBLIC_DNS},DNS:console.apps.${PUBLIC_DNS},DNS:oauth.apps.${PUBLIC_DNS},DNS:*.apps.${PUBLIC_DNS},DNS:*.crc.testing,DNS:*.apps-crc.testing"

  openssl req\
    -new\
    -key ${KEY_PEM} \
    -subj "/C=US/ST=California/L=San Francisco/O=Cloudera/OU=PS/CN=$(hostname -f)" \
    -out ${CSR_PEM} \
    -passin pass:${KEY_PWD} \
    -config <( cat <<EOF
[ req ]
default_bits = 2048
default_md = sha256
distinguished_name = req_distinguished_name
req_extensions = v3_user_req
string_mask = utf8only

[ req_distinguished_name ]
countryName_default = XX
countryName_min = 2
countryName_max = 2
localityName_default = Default City
0.organizationName_default = Default Company Ltd
commonName_max = 64
emailAddress_max = 64

[ v3_user_req ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = $ALT_NAMES
EOF
  )

  # Create an unencrypted version of the key (required for CDSW internal termination)
  openssl rsa -in "$KEY_PEM" -passin pass:"$KEY_PWD" > "$UNENCRYTED_KEY_PEM"

  # Sign cert
  if [[ $ipa_host != "" ]]; then
    kinit -kt $KEYTABS_DIR/admin.keytab admin
    set +e
    if [[ ! -z ${LOCAL_HOSTNAME:-} ]]; then
      ipa host-add-principal $(hostname -f) "host/${LOCAL_HOSTNAME}" || true
    fi

    ipa host-add-principal $(hostname -f) "host/*.${PUBLIC_DNS}"
    ipa host-add-principal $(hostname -f) "host/api.${PUBLIC_DNS}"
    ipa host-add-principal $(hostname -f) "host/console.apps.${PUBLIC_DNS}"
    ipa host-add-principal $(hostname -f) "host/oauth.apps.${PUBLIC_DNS}"
    ipa host-add-principal $(hostname -f) "host/*.apps.${PUBLIC_DNS}"
    ipa host-add-principal $(hostname -f) "host/*.crc.testing"
    ipa host-add-principal $(hostname -f) "host/*.apps-crc.testing"
    set -e
    ipa cert-request ${CSR_PEM} --principal=host/$(hostname -f)
    echo -e "-----BEGIN CERTIFICATE-----\n$(ipa host-find $(hostname -f) | grep Certificate: | tail -1 | awk '{print $NF}')\n-----END CERTIFICATE-----" | openssl x509 > ${HOST_PEM}

    # Wait for IPA to be ready and download IPA cert
    mkdir -p $(dirname $ROOT_PEM)
    wait_for_ipa "$ipa_host"
    curl -s -o $ROOT_PEM -w "%{http_code}" "http://${ipa_host}/ca.crt"
    if [[ ! -s $ROOT_PEM ]]; then
      echo "ERROR: Cannot download the IPA CA certificate"
      exit 1
    fi
  else
    create_ca

    openssl ca \
      -config ${CA_CONF} \
      -in ${CSR_PEM} \
      -key ${CA_KEY_PWD} \
      -batch \
      -extensions v3_user_extensions | \
    openssl x509 > ${HOST_PEM}
  fi

  # Create PEM truststore
  rm -f $TRUSTSTORE_PEM
  cp $ROOT_PEM $TRUSTSTORE_PEM

  # Create PEM combined certificate
  cp $HOST_PEM $CERT_PEM
}

function enable_nfs() {
  sudo dnf install nfs-utils
  sudo mkdir /nfs/workshop -p
  sudo chown 8536:8536 /nfs/workshop
  sudo chmod g+srwx /nfs/workshop
  echo "/nfs/workshop  *(rw,sync,no_root_squash,no_all_squash,no_subtree_check)" | sudo tee -a /etc/exports
  sudo systemctl enable nfs-server
  sudo systemctl start nfs-server
  sudo firewall-cmd --permanent --add-service=nfs
  sudo firewall-cmd --permanent --add-service=mountd
  sudo firewall-cmd --permanent --add-service=rpc-bind
  sudo firewall-cmd --reload
}

function configure_haproxy {
  SERVER_IP=$(hostname --ip-address)
  CRC_IP=$(crc ip)
  HAPROXY_CONF=/etc/haproxy/haproxy.cfg
  sudo bash -c "cat > ${HAPROXY_CONF} <<EOL
global
  log         127.0.0.1 local2
  pidfile     /var/run/haproxy.pid
  daemon
defaults
  mode                    http
  log                     global
  option                  dontlognull
  option http-server-close
  option                  redispatch
  retries                 3
  timeout http-request    10s
  timeout queue           1m
  timeout connect         10s
  timeout client          1m
  timeout server          1m
  timeout http-keep-alive 10s
  timeout check           10s
  maxconn                 3000
listen ingress-router-80 
  bind SERVER_IP:80
  mode tcp
  server crcvm CRC_IP:80 check inter 1s
listen ingress-router-443 
  bind SERVER_IP:443
  mode tcp
  server crcvm CRC_IP:443 check inter 1s
listen api-server-6443 
  bind SERVER_IP:6443
  mode tcp
  server crcvm CRC_IP:6443 check inter 1s
EOL"

  sudo sed -i -e "s/SERVER_IP/$SERVER_IP/g" -e "s/CRC_IP/$CRC_IP/g" $HAPROXY_CONF
  # Allow port 6443 binding
  sudo semanage port -a -t http_port_t -p tcp 6443 || true
  # Start HAProxy
  sudo systemctl reload NetworkManager
  sudo systemctl restart haproxy
}

function patch_crc {
  echo "Patch OpenShift CRC to use nip.io hostname for apps"
   # test block 
  # PUBLIC_DNS=$(hostname -f)
  # OCP_PATCH_JSON=patch.$$.json
  # TRUSTSTORE_PEM=/home/rocky/ocp/security/x509/truststore.pem
  # CERT_PEM=/home/rocky/ocp/security/x509/host.pem
  # UNENCRYTED_KEY_PEM=/home/rocky/ocp/security/x509/unencrypted-key.pem
  # test block 
  oc_patch_string=''
  OCP_PATCH_JSON=/tmp/patch.$$.json

  apps_domain=$(oc get ingresses.config/cluster -o json | jq -r '.spec.appsDomain')
  if [[ $apps_domain != "null" ]]; then
      oc patch ingresses.config/cluster --type json --patch '[{ "op": "remove", "path": "/spec/appsDomain" }]'
  fi

  # add custom-ca
  echo "Adding Custom CA to OpenShift..."
  PROXY_CA_NAME=$(oc get proxy cluster -o json | jq -r '.spec.trustedCA.name')
  echo "CA_NAME=$PROXY_CA_NAME"
  if [[ $PROXY_CA_NAME = "" ]]; then
    # ingress-custom
    oc create configmap custom-ca --from-file=ca-bundle.crt=$ROOT_PEM -n openshift-config
    oc patch proxy/cluster --type=merge --patch='{"spec":{"trustedCA":{"name":"custom-ca"}}}'
    oc create secret tls default-ingress-custom --cert=$HOST_PEM --key=$UNENCRYTED_KEY_PEM -n openshift-ingress
    oc patch ingresscontroller.operator default --type=merge -p '{"spec":{"defaultCertificate": {"name": "default-ingress-custom"}}}' -n openshift-ingress-operator
    # console-custom
    oc create secret tls console-custom --cert=$HOST_PEM --key=$UNENCRYTED_KEY_PEM -n openshift-config
  fi

  # add appsDomains
  cat > $OCP_PATCH_JSON <<PATCH
{
  "spec": {
    "appsDomain": "apps.$PUBLIC_DNS"
    }
}
PATCH
  oc_patch_string=$(cat $OCP_PATCH_JSON)
  oc patch ingresses.config/cluster --type merge -p "${oc_patch_string//[[:blank:]]/}"

  # add componentRoutes
  cat > $OCP_PATCH_JSON <<PATCH
{
  "spec": {
    "componentRoutes": [
      {
        "name": "oauth-openshift",
        "namespace": "openshift-authentication",
        "hostname": "oauth.apps.$PUBLIC_DNS"
      },
      {
        "name": "console",
        "namespace": "openshift-console",
        "hostname": "console.apps.$PUBLIC_DNS",
        "servingCertKeyPairSecret": {
          "name": "console-custom"
        }
      }
    ]
  }
}
PATCH
  oc_patch_string=$(cat $OCP_PATCH_JSON)
  oc patch ingresses.config/cluster --type merge -p "${oc_patch_string//[[:blank:]]/}"

  # get api ca-cert
  API_ROOT_PEM=/tmp/api-ca-cert.pem
  echo quit | openssl s_client -connect api.crc.testing:6443 -showcerts -servername api.crc.testing:6443 2>/dev/null </dev/null |  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > $API_ROOT_PEM
  CA_PEM_JSON=$(cat $TRUSTSTORE_PEM | sed -e 's/^/      /')
  HOST_PEM_JSON=$(cat $CERT_PEM | sed -e 's/^/      /')
  API_CA_PEM_JSON=$(cat $API_ROOT_PEM | sed -e 's/^/      /')
  KEY_PEM_JSON=$(cat $UNENCRYTED_KEY_PEM | sed -e 's/^/      /')
  cat > $OCP_PATCH_JSON <<PATCH
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  labels:
    component: apiserver
    provider: kubernetes
  name: api
  namespace: default
spec:
  host: api.$PUBLIC_DNS
  to:
    kind: Service
    name: kubernetes
    weight: 100
  port:
    targetPort: https
  tls:
    caCertificate: |-
$CA_PEM_JSON
    certificate: |
$HOST_PEM_JSON
    destinationCACertificate: |-
$API_CA_PEM_JSON
    insecureEdgeTerminationPolicy: Redirect
    key: |
$KEY_PEM_JSON
    termination: reencrypt
  wildcardPolicy: None
PATCH
  # add api route
  retries=300
  while [[ $retries -gt 0 ]]; do
    set +e
    oc create -n default -f $OCP_PATCH_JSON
    err=$?
    set -e
    if [[ $err == 0 ]]; then
      break
    fi
    retries=$((retries - 1))
    sleep 5
    echo "Waiting for OpenShift cluster to be ready (retries left: $retries)"
  done
  # enable autostart for crc vm
  sudo virsh autostart crc
  
}

if [[ $ACTION == "install" ]]; then

  export IPA_HOST=${2:-}
  export IPA_PRIVATE_IP=${3:-}

  # Save params
  if [[ ! -f $BASE_DIR/.setup-ocp.install.params ]]; then
    echo "bash -x $0 '$IPA_HOST' '$IPA_PRIVATE_IP'" > $BASE_DIR/.setup-ocp.params
  fi

  # CA details
  SEC_BASE=$BASE_DIR/security
  CA_DIR=${SEC_BASE}/ca
  CA_KEY=$CA_DIR/ca-key.pem
  CA_KEY_PWD=${THE_PWD}
  CA_CONF=$CA_DIR/openssl.cnf
  CA_EMAIL=admin@cloudera.com
  ROOT_PEM=$CA_DIR/ca-cert.pem

  KEY_PEM=${SEC_BASE}/x509/key.pem
  UNENCRYTED_KEY_PEM=${SEC_BASE}/x509/unencrypted-key.pem
  CSR_PEM=${SEC_BASE}/x509/host.csr
  HOST_PEM=${SEC_BASE}/x509/host.pem
  KEY_PWD=${THE_PWD}
  KEYSTORE_PWD=$KEY_PWD
  TRUSTSTORE_PWD=${THE_PWD}

  # Generated files
  CERT_PEM=${SEC_BASE}/x509/cert.pem
  TRUSTSTORE_PEM=${SEC_BASE}/x509/truststore.pem
  HAPROXY_SSL=${SEC_BASE}/haproxy.pem

  log_status "Setting host and domain names"
  PRIVATE_IP=$(hostname -I | awk '{print $1}')
  LOCAL_HOSTNAME=$(hostname -f)
  PUBLIC_IP=$(curl -sL http://ifconfig.me || curl -sL http://api.ipify.org/ || curl -sL https://ipinfo.io/ip)
  PUBLIC_DNS=ocp.${PUBLIC_IP}.nip.io

  sudo sed -i.bak "/${LOCAL_HOSTNAME}/d;/^${PRIVATE_IP}/d;/^::1/d" /etc/hosts
  if [[ "$LOCAL_HOSTNAME" == "$PUBLIC_DNS" ]]; then
    echo "$PRIVATE_IP $PUBLIC_DNS" | sudo tee -a /etc/hosts
  else
    echo "$PRIVATE_IP $PUBLIC_DNS $LOCAL_HOSTNAME" | sudo tee -a /etc/hosts  
  fi

  sudo sed -i.bak '/kernel.domainname/d' /etc/sysctl.conf
  echo "kernel.domainname=${PUBLIC_DNS#*.}" | sudo tee -a /etc/sysctl.conf
  sudo sysctl -p

  sudo hostnamectl set-hostname $PUBLIC_DNS
  if [[ -f /etc/sysconfig/network ]]; then
    sudo sed -i "/HOSTNAME=/ d" /etc/sysconfig/network
  fi
  echo "HOSTNAME=${PUBLIC_DNS}" | sudo tee -a /etc/sysconfig/network

  log_status "Setup Packages..."
  yum_install wget libvirt qemu-kvm haproxy cockpit cockpit-machines git
  
  log_status "Creating TLS certificates"
  echo "$IPA_PRIVATE_IP $IPA_HOST" | sudo tee -a /etc/hosts
  wait_for_ipa "$IPA_HOST"
  install_ipa_client "$IPA_HOST"
  create_certs "$IPA_HOST"

  log_status "Start required services"
  sudo systemctl start cockpit.socket
  sudo systemctl enable cockpit.socket
  sudo systemctl enable libvirtd
  sudo systemctl start libvirtd

  log_status "Opening required ports"
  # Open ports
  if [[ $(sudo  firewall-cmd --state) == running ]]; then
      zone=$(firewall-cmd --get-active-zones | awk '{print $1}' | head -1)
      sudo firewall-cmd --permanent --add-service=cockpit
      sudo firewall-cmd --permanent --add-port=80/tcp 
      sudo firewall-cmd --permanent --add-port=6443/tcp
      sudo firewall-cmd --permanent --add-port=443/tcp
      sudo firewall-cmd --reload
  fi

  log_status "Set password for current user to login to Cockpit"
  echo $THE_PWD | sudo passwd --stdin $USER

  log_status "Installing OpenShift CRC server"
  # Install CRC
  wget https://mirror.openshift.com/pub/openshift-v4/clients/crc/2.31.0/crc-linux-amd64.tar.xz -O /tmp/crc-linux-2.31.0-amd64.tar.xz
  tar xvf /tmp/crc-linux-2.31.0-amd64.tar.xz -C /tmp
  sudo mv /tmp/crc-linux-2.31.0-amd64/crc /usr/local/bin/crc

  # Config CRC (OpenShift 4.12)
  THE_PWD=Supersecret1
  CRC_CPU=$(( $(lscpu -J | jq -r '.lscpu[]? | select(.field=="CPU(s):") | .data') * 95/100))
  CRC_MEM=$(awk '/MemFree/ { printf "%.0f \n", $2/1024 }' /proc/meminfo)
  CRC_DISK=$(( $(df -BG . | tail -n1 | awk '{print $4}' | grep -o -E '[0-9]+') * 95/100))
  crc config set consent-telemetry no
  crc config set preset okd
  crc config set disable-update-check true
  crc config set kubeadmin-password $THE_PWD
  crc config set cpus $CRC_CPU
  crc config set memory $CRC_MEM
  crc config set disk-size $CRC_DISK
  crc config set bundle 'docker://quay.io/crcont/okd-bundle:4.12.0-0.okd-2023-02-18-033438'
  crc config view
  # Prep CRC Image
  LOG_FILE=crc_setup_stderr.log
  crc setup --log-level DEBUG 2>>$LOG_FILE 
  # Start CRC VM
  LOG_FILE=crc_start_stderr.log
  set +e
  crc start --log-level DEBUG 2>>$LOG_FILE 
  set -e
  # Enable oc command
  eval $(crc oc-env)
  # Login to OpenShift cluster
  oc login https://api.crc.testing:6443 --username=kubeadmin --password=$THE_PWD

  log_status "Configure HAProxy"
  configure_haproxy

  log_status "Enable NFS"
  enable_nfs

  log_status "Patching OpenShift CRC"
  patch_crc

  log_status "Installed CRC Successfully"

else
  echo "USAGE: $0 install [IPA_HOSTNAME] [IPA_IP]"
fi
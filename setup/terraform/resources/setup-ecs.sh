#! /bin/bash
set -o nounset
set -o errexit
set -o pipefail
set -o xtrace
trap 'echo Setup return code: $?' 0
BASE_DIR=$(cd "$(dirname $0)"; pwd -L)

if [ "$USER" != "root" ]; then
  echo "ERROR: This script ($0) must be executed by root"
  exit 1
fi

source $BASE_DIR/common.sh

ACTION=$1

if [[ $ACTION == "install-prereqs" ]]; then
  log_status "ECS: Starting ECS Host Setup Script"

  CLOUD_PROVIDER=${2:-aws}
  SSH_USER=${3:-}
  SSH_PWD=${4:-}
  NAMESPACE=${5:-}
  IPA_HOST=${6:-}
  IPA_PRIVATE_IP=${7:-}
  HAS_ECS=1
  export IPA_HOST HAS_ECS

  get_public_ip
  load_stack $NAMESPACE

  # Save params
  if [[ ! -f $BASE_DIR/.setup-ecs.install-prereqs.params ]]; then
    echo "bash -x $0 install-prereqs '$CLOUD_PROVIDER' '$SSH_USER' '$SSH_PWD' '$NAMESPACE' '$IPA_HOST' '$IPA_PRIVATE_IP'" > $BASE_DIR/.setup-ecs.install-prereqs.params
  fi

  deploy_os_prereqs
  # Install dependencies on python38
  yum_install centos-release-scl
  yum_install rh-python38 rh-python38-python-devel
  # Enable python38 and add yaml
  enable_py3
  pip install --quiet --upgrade pip pyyaml
  rm -f /usr/bin/python3 /usr/bin/pip3 /usr/local/bin/python3.8
  ln -s /opt/rh/rh-python38/root/bin/python3 /usr/bin/python3
  ln -s /opt/rh/rh-python38/root/bin/pip3 /usr/bin/pip3
  ln -s /opt/rh/rh-python38/root/usr/bin/python3.8 /usr/local/bin/python3.8
  
  complete_host_initialization "ecs"

  log_status "Ensure domain search list only contains ec2.internal, and not nip.io"
  sed -i 's/^ *search.*/search ec2.internal/' /etc/resolv.conf

  log_status "Ensure Systemd permissions for ECS"
  mkdir -p /etc/systemd/system.conf.d/
  cat > /etc/systemd/system.conf.d/ecs.conf << EOF
[Manager]
DefaultCPUAccounting=yes
DefaultBlockIOAccounting=yes
DefaultMemoryAccounting=yes
EOF
  cat /etc/systemd/system.conf.d/ecs.conf
  kill -1 1 # reload systemd

  wait_for_ipa "$IPA_HOST"
  log_status "ECS: Installing IPA client"
  install_ipa_client "$IPA_HOST"

  # Install Java (need keytool to handle certs)
  log_status "Installing JDK package ${JAVA_PACKAGE_NAME}"
  yum_install ${JAVA_PACKAGE_NAME}
  if ! javac; then
    set_java_alternatives
  fi

  log_status "ECS: Creating TLS certificates"
  # This is done even if ENABLE_TLS == no, since ShellInABox always needs a cert
  create_certs "$IPA_HOST"

  log_status "ECS: Installing k9s"
  # install golang from tar
  cd /tmp
  wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
  rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  git clone https://github.com/derailed/k9s
  cd k9s/
  make build
  cp ./execs/k9s /usr/local/bin

  log_status "ECS: Cleaning up"
  rm -f $BASE_DIR/stack.*.sh* $BASE_DIR/stack.sh*

elif [[ $ACTION == "install-cloudera-agent" ]]; then
  CDP_PUBLIC_DNS=$2
  CDP_PRIVATE_ID=$3
  AGENT_CONFIG_FILE=$4

  # Save params
  if [[ ! -f $BASE_DIR/.setup-ecs.install-cloudera-agent.params ]]; then
    echo "bash -x $0 install-cloudera-agent '$CDP_PUBLIC_DNS' '$CDP_PRIVATE_ID' '$AGENT_CONFIG_FILE'" > $BASE_DIR/.setup-ecs.install-cloudera-agent.params
  fi

  log_status "ECS: Add CDP node to /etc/hosts"
  echo "$CDP_PRIVATE_ID $CDP_PUBLIC_DNS" >> /etc/hosts

  log_status "ECS: Install CM agent and start it"
  rpm --import "$(grep baseurl /etc/yum.repos.d/cloudera-manager.repo | sed 's/.*= *//;s/\/ *$//')/RPM-GPG-KEY-cloudera"
  yum_install cloudera-manager-agent
  mv ${AGENT_CONFIG_FILE} /etc/cloudera-scm-agent/config.ini
  chown cloudera-scm:cloudera-scm /etc/cloudera-scm-agent/config.ini
  systemctl enable cloudera-scm-agent
  systemctl start cloudera-scm-agent

  nohup bash $0 configure-coredns > ${BASE_DIR}/configure-coredns.log 2>&1 &

  nohup bash $0 configure-cml > ${BASE_DIR}/configure-cml.log 2>&1 &

elif [[ $ACTION == "configure-coredns" ]]; then
  export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
  export PATH=$PATH:/var/lib/rancher/rke2/bin
  cat >> ~/.bash_profile <<EOF
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
export PATH=$PATH:/var/lib/rancher/rke2/bin
EOF

  yum_install dnsmasq
  systemctl enable dnsmasq
  systemctl start dnsmasq

  SCRIPT_FILE=/tmp/cm.py.$$
  YAML_FILE=/tmp/cm.yaml.$$
  trap 'rm -f $SCRIPT_FILE $YAML_FILE' 0

  cat > $SCRIPT_FILE <<EOF
import yaml
import socket
import sys
FWD = '''
nip.io:53 {
    errors
    cache 30
    forward . %s
}
''' % (socket.gethostbyname(socket.gethostname()),)
cm = yaml.load(sys.stdin, Loader=yaml.Loader)
cm['data']['Corefile'] += FWD
print(yaml.dump(cm, Dumper=yaml.Dumper))
EOF

  set +e
  # It takes about 5 minutes to get the pod ready, use kubectl wait
  while ! kubectl wait --for=condition=ready pod -n kube-system -l k8s-app=kube-dns --timeout=60s; do
    echo "$(date) - Waiting for rke2-coredns-rke2-coredns to be created"
    sleep 5
  done
  set -e
  sleep 10
  # Enable python38
  enable_py3
  kubectl get configmap -n kube-system rke2-coredns-rke2-coredns -o yaml | python $SCRIPT_FILE > $YAML_FILE
  kubectl apply -f $YAML_FILE

elif [[ $ACTION == "configure-cml" ]]; then
  export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
  export PATH=$PATH:/var/lib/rancher/rke2/bin

  set +e
  echo "$(date) - It takes about 5 minutes to get the pod ready, use kubectl wait on kube-dns"
  while ! kubectl wait --for=condition=ready pod -n kube-system -l k8s-app=kube-dns --timeout=60s > /dev/null 2>&1; do
    echo "$(date) - Waiting for rke2-coredns-rke2-coredns to be created"
    sleep 60
  done
  set -e
  echo "$(date) - Prepare namespace for edge2ai CML Workspace"
  edge2ai_ns=$(kubectl get ns -o json | jq -r '.items[] | select(.metadata.name == "edge2ai").metadata.name')
  if [[ $edge2ai_ns != "edge2ai" ]]; then
    kubectl create namespace edge2ai
    echo "$(date) - namespace for edge2ai CML Workspace created"
  else
    echo "$(date) - namespace for edge2ai CML Workspace exists"
  fi

  echo "$(date) - Upload cml-tls-secret"
  cml_tls_secret=$(kubectl get secret -n edge2ai -o json | jq -r '.items[] | select(.metadata.name == "cml-tls-secret").metadata.name')
  if [[ -z "$cml_tls_secret" ]]; then
    kubectl create secret tls cml-tls-secret --cert=$HOST_PEM --key=$UNENCRYTED_KEY_PEM -o yaml --dry-run=client | kubectl -n edge2ai create -f -
    echo "$(date) - cml-tls-secret for edge2ai CML Workspace created"
  else
    echo "$(date) - cml-tls-secret for edge2ai CML Workspace exits"
  fi

  echo "$(date) - Patch CML site_config"
  ROOT_PEM=/opt/cloudera/security/ca/ca-cert.pem
  root_ca_cert=$(<$ROOT_PEM)
  set +e
  while ! kubectl wait --for=condition=ready pod db-0 -n edge2ai --timeout=60s > /dev/null 2>&1; do
    echo "$(date) - Waiting for CML backend db to be ready"
    sleep 60
  done
  set -e
  
  while ! kubectl exec -it db-0 -c db -n edge2ai -- psql -P pager=off --expanded -U sense -c "select root_ca from site_config" > /dev/null 2>&1; do
    echo "$(date) - Waiting for CML backend table to be ready"
    sleep 60
  done
  kubectl exec -it db-0 -c db -n edge2ai -- psql -P pager=off --expanded -U sense -c "update site_config set root_ca='$root_ca_cert' where id=1"

  tries=99
  while [[ $tries -ne 0 ]]; do
    echo "$(date) - Clean up deleted environment monitoring namespace"
    [[ $(kubectl get ns -o json | jq -r '.items[] | select(.metadata.name | test("ecs-[A-Za-z0-9]+-monitoring-platform")).metadata.name') != "" ]] && break
    ((tries--))
    sleep 60
  done
  ecs_prometheus_ns=$(kubectl get ns -o json | jq -r '.items[] | select(.metadata.name | test("ecs-[A-Za-z0-9]+-monitoring-platform")).metadata.name')
  nohup kubectl delete namespace $ecs_prometheus_ns >/dev/null 2>&1 &

  log_status "CML deployed successfully"
fi

if [[ ! -z ${CLUSTER_ID:-} ]]; then
  echo "At this point you can login into Cloudera Manager host on port 7180 and follow the deployment of the cluster"
  figlet -f small -w 300  "ECS  ${CLUSTER_ID:-???}  deployed successfully"'!' | cowsay -n -f "$(ls -1 /usr/share/cowsay | grep "\.cow" | sed 's/\.cow//' | egrep -v "bong|head-in|sodomized|telebears" | shuf -n 1)"
  echo "Completed successfully: ECS ${CLUSTER_ID:-???}"
  log_status "ECS deployed successfully"
fi

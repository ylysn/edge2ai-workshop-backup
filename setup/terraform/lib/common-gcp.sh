#!/bin/bash

# The GCP provider is still under development, scripts testing is in progress.

AVAILABLE_SCRIPTS=(
  launch
  terminate
  list-details
  check-services
  check-setup-status
  connect-to-cluster
  browse-cluster
  browse-cluster-socks
  close-registration
  manage-instances
  manage-ip
  open-registration
  run-on-all-clusters
  run-on-cluster
  start-instances
  stop-instances
  sync-ip-addresses
  update-registration-code
  upload-instance-details
)

GCP_PRICING_YAML='https://raw.githubusercontent.com/Cyclenerd/google-cloud-pricing-cost-calculator/master/pricing.yml'
tmp_yaml_file=/tmp/.get_cost.yaml.$NAMESPACE
tmp_json_file=/tmp/.get_cost.json.$NAMESPACE

function _get_cost_file() {
  if [[ -f "${tmp_yaml_file}" ]] &&  [[ -f "${tmp_json_file}" ]]; then
    return 0
  else
    local ret=$(curl -w "%{http_code}" "$GCP_PRICING_YAML" -o $tmp_yaml_file --stderr /dev/null)
    if [[ $ret == 200 ]]; then
      python3 -c 'import sys, yaml, json; print(json.dumps(yaml.safe_load(sys.stdin)))' < $tmp_yaml_file > $tmp_json_file
      return 0
    fi
    return 1
  fi
}
function get_instance_hourly_cost() {
  local instance_type=${1:-n1-highmem-16}
    if _get_cost_file; then
    jq -r ".compute.instance.\"$instance_type\".cost.\"$TF_VAR_gcp_region\".hour" $tmp_json_file | awk '{print ($1 == "null" ? 0 : $1)}'
  fi
}

function validate_cloud_parameters() {
  if [[ ${TF_VAR_gcp_project:-} == "" || ${TF_VAR_gcp_region:-} == "" ]]; then
    echo "${C_RED}ERROR: The following properties must be set in the .env.${NAMESPACE} file:"
    echo "         - TF_VAR_gcp_project"
    echo "         - TF_VAR_gcp_region"
    echo "${C_NORMAL}"
    exit 1
  fi
  if [[ ${TF_VAR_aws_profile:-} ]]; then
    export AWS_PROFILE=${TF_VAR_aws_profile}
  else
    echo "${C_RED}ERROR: the following must be set in the .env.${NAMESPACE} file:"
    echo "         - TF_VAR_aws_profile"
    echo "${C_NORMAL}"
    exit 1
  fi
}

function is_cli_available() {
  [[ $(get_cli_version) == "2"* ]] && echo yes || echo no
}

function get_cli_version() {
  gcloud --version 2>/dev/null | egrep -o '[0-9.][0-9.]*' | head -1 || true
}

function get_cloud_account_info() {
  ADC_FILE=$HOME/.config/gcloud/application_default_credentials.json
  if test -f "$ADC_FILE"; then
    gcloud auth list
  else
    echo "google: could not find default credentials. See"
    echo "https://cloud.google.com/docs/authentication/external/set-up-adc"
    echo "for more information"
    exit 1
  fi
}

function cloud_login() {
  gcloud auth application-default login
}

function pre_launch_setup() {
  # noop
  true
}

function list_cloud_instances() {
  local instance_ids=$1
  # Returns: id, state, name, owner, enddate
  # Order by: state
  # $TF_VAR_gcp_region 
  #gcloud compute instances describe yalyasin-build107-cluster-0 --zone us-central1-a --format="json(id,name,status,labels)" | jq -r '. | "\(.status) \(.labels.owner) \(.labels.enddate) \(.name) \(.id)" ' 
  for i in $instance_ids ; do
    gcloud compute instances describe $i --zone ${TF_VAR_gcp_region}-a --format="json(id,name,status,labels)" | jq -r '. | "\(.status) \(.labels.owner) \(.labels.enddate) \(.name) \(.id)" ' 
  done
} 

function start_instances() {
  local instance_ids=$1
  gcloud compute instances start $instance_ids --zone ${TF_VAR_gcp_region}-a 
}

function stop_instances() {
  local instance_ids=$1
  gcloud compute instances stop $instance_ids --zone ${TF_VAR_gcp_region}-a 
}

function terminate_instances() {
  local instance_ids=$1
  gcloud compute instances delete $instance_ids --zone ${TF_VAR_gcp_region}-a --delete-disks=all
}

function set_instances_tag() {
  local instance_ids=$1
  local tag=$2
  local value=$3
  for i in $instance_ids ; do
    gcloud compute instances add-labels $i --zone ${TF_VAR_gcp_region}-a --labels=${tag}=${value}
  done
}

function is_instance_protected() {
  local instance_id=$1
  gcloud compute instances describe $instance_id --zone ${TF_VAR_gcp_region}-a | grep "deletionProtection" | awk {'print $2'}
}

function protect_instance() {
  local instance_id=$1
  gcloud compute instances update $instance_id --zone ${TF_VAR_gcp_region}-a --deletion-protection
}

function unprotect_instance() {
  local instance_id=$1
  gcloud compute instances update $instance_id --zone ${TF_VAR_gcp_region}-a --no-deletion-protection
}

function security_groups() {
  local sg_type=$1
  echo ${TF_VAR_owner}-${NAMESPACE}-${sg_type}-access
}

function get_ingress() {
  # Return the matched ingress rule. One rule per line with the following format: cidr protocol port
  local sg_id=$1
  local cidr=${2:-}
  local protocol=${3:-}
  local port=${4:-}
  local description=${5:-}
  ensure_tf_json_file
  jq -r '.values.root_module.resources[]?.values | select(.name == "'"$sg_id"'") | . as $parent | "\(.source_ranges[]) \(.allow[].protocol) \(if $parent.allow[].ports == [] then "all" else $parent.allow[].ports end)"' $TF_JSON_FILE
}

function add_sec_group_ingress_rule() {
  local group_id=$1
  local cidr=$2
  local protocol=$3
  local port=${4:-}
  local description=${5:-default}

  local tmp_file=/tmp/add-ingress.$$
  local CURRENT_PROTO_RANGE=$(gcloud compute firewall-rules describe ${group_id} --format="value[delimiter=',',terminator=','](IPProtocol)")
  local CURRENT_IP_RANGE=$(gcloud compute firewall-rules describe ${group_id} --format="value[delimiter=',',terminator=','](sourceRanges)")
  local CURRENT_PORT_RANGE=$(gcloud compute firewall-rules describe ${group_id} --format="value[delimiter=',',terminator=','](ports)")
  local NEW_PORT_RANGE=""
  if [[ $CURRENT_PORT_RANGE == "," ]]; then
    NEW_PORT_RANGE="all"
  elif [[ ",$x," = *",$y,"* ]]; then
    NEW_PORT_RANGE=$CURRENT_PORT_RANGE
  else
    NEW_PORT_RANGE=${CURRENT_PORT_RANGE}${port}
  fi
  gcloud compute firewall-rules update ${group_id}  --source-ranges="${CURRENT_IP_RANGE}${cidr}"
  echo "  Granted access on ${group_id}, protocol=${protocol}, port=${port} to ${cidr} $([[ $description == "" ]] || echo "($description)") $([[ $force == "force" ]] && echo " - (forced)" || true)"

}

function remove_sec_group_ingress_rule() {
  local group_id=$1
  local cidr=$2
  local protocol=$3
  local port=${4:-}
  local CURRENT_IP_RANGE=$(gcloud compute firewall-rules describe ${group_id} --format="value[delimiter=',',terminator=','](sourceRanges)")
  gcloud compute firewall-rules update ${group_id} --source-ranges="${CURRENT_IP_RANGE#${cidr},}"
  echo "  Revoked access on ${group_id}, protocol=${protocol}, port=${port} from ${cidr} $([[ $force == "force" ]] && echo "(forced)" || true)"
}
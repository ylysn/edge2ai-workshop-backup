variable "cluster_count" {
  description = "Number of clusters to create"
}

variable "launch_web_server" {
  description = "Whether or not to launch the web server"
  default     = true
}

variable "deploy_cdsw_model" {
  description = "Whether to deploy the CDSW model during launch or not"
  type        = bool
  default     = true
}

variable "ssh_private_key" {
  description = "SSH private key to connect to instances"
}

variable "ssh_public_key" {
  description = "SSH public key to connect to instances"
}

variable "web_ssh_private_key" {
  description = "SSH private key to connect to the Web Server instances"
}

variable "web_ssh_public_key" {
  description = "SSH public key to connect to the Web Server instances"
}

variable "my_public_ip" {
  description = "Public IP address of the local network"
}

variable "owner" {
  description = "Owner user name"
}

variable "ssh_username" {
  description = "SSH username to connect to instances"
}

variable "ssh_password" {
  description = "SSH password to connect to instances"
}

variable "cluster_instance_type" {
  description = "Instance type for the CDH cluster"
}

variable "ecs_instance_type" {
  description = "Instance type for the ECS host"
}

variable "name_prefix" {
  description = "Name prefix for resources"
}

variable "project" {
  description = "Project name"
}

variable "enddate" {
  description = "Resource expiration date (MMDDYYYY)"
}

variable "namespace" {
  description = "Namespace for the cluster deployment"
}

variable "cidr_block_1" {
  description = "CIDR for subnet 1"
  default     = "10.0.1.0/24"
}

variable "extra_cidr_blocks" {
  description = "Extra CIDR blocks to add to security groups"
  type        = list(string)
  default     = []
}

variable "use_ipa" {
  description = "Whether or not to launch an IPA server"
  type        = bool
  default     = false
}

variable "base_dir" {
  description = "Deployment base dir"
  type        = string
}

variable "gcp_region" {
  description = "GCP Region"
}

variable "gcp_az" {
  description = "GCP AZ"
  default     = "a"
}

variable "gcp_project" {
  description = "Abort this with CTRL-C, set the TF_VAR_gcp_project environment variable in your shell and try again."
  default = null
}

variable "key_name" {
  description = "Name of the SSH Key in AWS"
}

variable "web_key_name" {
  description = "Name of the SSH Key for the Web Server in AWS"
}

variable "base_ami" {
  description = "GCP image for the Web Service"
  default = "centos-7-v20231212"
}

variable "cluster_ami" {
  description = "GCP image for the CDH cluster"
  default = "centos-7-v20231212"

}

variable "ecs_ami" {
  description = "GCP image for the ECS host"
  default = "centos-7-v20231212"
}

variable "vpc_id" {
  description = "GCP VPC id"
  default     = ""
}

variable "managed_security_group_ids" {
  type    = list(string)
  default = []
}

variable "use_elastic_ip" {
  description = "Whether or not to use Elastic IPs"
  type        = bool
  default     = false
}

variable "pvc_data_services" {
  description = "Whether or not to deploy PVC Data Services"
  type        = bool
  default     = false
}

variable "cdp_license_file" {
  description = "CDP license file"
  type        = string
  default     = ""
}

variable "deploy_ocp" {
  description = "Whether to deploy the CRC instance or not"
  type        = bool
  default     = false
}

variable "ocp_instance_type" {
  description = "Instance type for the OCP host"
  default = "n2-highmem-16"
}

variable "ocp_ami" {
  description = "GCP image for the OCP host"
  default = "rocky-linux-8-optimized-gcp"
}

variable "ocp_ssh_username" {
  default = "rocky"
}
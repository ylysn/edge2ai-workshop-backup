
resource "null_resource" "deploy_ecs" {
  count = (var.pvc_data_services ? var.cluster_count : 0)

  depends_on = [
    azurerm_network_security_rule.workshop_public_ips_sg_rule,
    azurerm_virtual_machine.ecs
  ]

  connection {
    host        = azurerm_public_ip.ip_ecs[count.index].ip_address
    type        = "ssh"
    user        = var.ssh_username
    private_key = file(var.ssh_private_key)
  }

  provisioner "file" {
    source      = "${var.base_dir}/resources"
    destination = "/tmp/"
  }

  provisioner "remote-exec" {
    inline = [
      "set -o errexit",
      "set -o xtrace",
      "sudo nohup bash -x /tmp/resources/setup-ecs.sh install-prereqs azure \"${var.ssh_username}\" \"${var.ssh_password}\" \"${var.namespace}\"  \"${(var.use_ipa ? "ipa.${azurerm_public_ip.ip_ipa.0.ip_address}.nip.io" : "")}\" \"${(var.use_ipa ? azurerm_network_interface.nic_ipa.0.private_ip_address : "")}\" > /tmp/resources/setup-ecs.install-prereqs.log 2>&1 &",
      "sleep 1 # don't remove - needed for the nohup to work",
    ]
  }
}

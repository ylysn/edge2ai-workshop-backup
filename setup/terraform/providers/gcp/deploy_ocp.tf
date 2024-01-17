resource "null_resource" "deploy_ocp" {
  count      = (var.deploy_ocp ? 1 : 0)
  
  depends_on = [
    google_compute_instance.ocp
  ]

  connection {
    host        = google_compute_address.ocp-public-ip[0].address
    type        = "ssh"
    user        = var.ocp_ssh_username
    private_key = file(var.ssh_private_key)
  }

  provisioner "file" {
    source      = "${var.base_dir}/ocp"
    destination = "/home/${var.ocp_ssh_username}/ocp"
  }

  provisioner "file" {
    source      = "${var.base_dir}/resources/check-setup-status.sh"
    destination = "/home/${var.ocp_ssh_username}/ocp/check-setup-status.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "set -o errexit",
      "set -o xtrace",
      "cd ocp/",
      "nohup bash -x ./setup-ocp.sh install \"${(var.use_ipa ? "ipa.${google_compute_address.ipa-public-ip[0].address}.nip.io" : "")}\" \"${(var.use_ipa ? google_compute_instance.ipa[0].network_interface.0.network_ip : "")}\" > ./setup-ocp.log 2>&1 &",
      "sleep 1 # don't remove - needed for the nohup to work",
    ]
  }
}

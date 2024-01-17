resource "null_resource" "deploy_ipa" {
  count      = (var.use_ipa ? 1 : 0)
  
  depends_on = [
    google_compute_instance.ipa
  ]

  connection {
    host        = google_compute_address.ipa-public-ip[0].address
    type        = "ssh"
    user        = var.ssh_username
    private_key = file(var.ssh_private_key)
  }

  provisioner "file" {
    source      = "${var.base_dir}/ipa"
    destination = "/home/${var.ssh_username}/ipa"
  }

  provisioner "file" {
    source      = "${var.base_dir}/resources/check-setup-status.sh"
    destination = "/home/${var.ssh_username}/ipa/check-setup-status.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "set -o errexit",
      "set -o xtrace",
      "cd ipa/",
      "sudo nohup bash -x ./setup-ipa.sh > ./setup-ipa.log 2>&1 &",
      "sleep 1 # don't remove - needed for the nohup to work",
    ]
  }
}

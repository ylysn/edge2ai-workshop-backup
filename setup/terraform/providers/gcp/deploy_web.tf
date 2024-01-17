resource "null_resource" "deploy_web" {
  count = (var.launch_web_server ? 1 : 0)

  depends_on = [
    google_compute_instance.web
  ]

  connection {
    host        = google_compute_address.web-public-ip[0].address
    type        = "ssh"
    user        = var.ssh_username
    private_key = file(var.web_ssh_private_key)
  }

  provisioner "file" {
    source      = "${var.base_dir}/web"
    destination = "/home/${var.ssh_username}/web"
  }

  provisioner "file" {
    source      = "${var.base_dir}/resources/check-setup-status.sh"
    destination = "/home/${var.ssh_username}/web/check-setup-status.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "set -o errexit",
      "set -o xtrace",
      "cd web/",
      "nohup bash -x ./start-web.sh > ./start-web.log 2>&1 &",
      "sleep 1 # don't remove - needed for the nohup to work",
    ]
  }
}

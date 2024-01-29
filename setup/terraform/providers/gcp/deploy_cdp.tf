resource "null_resource" "deploy_cdp" {
  count = var.cluster_count

  depends_on = [
    google_compute_instance.cluster
  ]

  connection {
    host        = element((google_compute_address.cluster-public-ip.*.address), count.index)
    type        = "ssh"
    user        = var.ssh_username
    private_key = file(var.ssh_private_key)
  }

  provisioner "file" {
    source      = var.ssh_private_key
    destination = "/home/${var.ssh_username}/.ssh/${var.namespace}.pem"
  }

  provisioner "file" {
    source      = "${var.base_dir}/resources"
    destination = "/tmp/"
  }

  provisioner "file" {
    source      = (var.cdp_license_file == "" ? "/dev/null" : var.cdp_license_file)
    destination = "/tmp/resources/.license"
  }

  provisioner "remote-exec" {
    inline = [
      "set -o errexit",
      "set -o xtrace",
      "sudo bash -c 'echo -e \"export CLUSTERS_PUBLIC_DNS=${join(",", formatlist("cdp.%s.nip.io", google_compute_address.cluster-public-ip.*.address))}\" >> /etc/workshop.conf'",
      "sudo nohup bash -x /tmp/resources/setup.sh gcp \"${var.ssh_username}\" \"${var.ssh_password}\" \"${var.namespace}\" \"\" \"${(var.use_ipa ? "ipa.${google_compute_address.ipa-public-ip[0].address}.nip.io" : "")}\" \"${(var.use_ipa ? google_compute_instance.ipa[0].network_interface.0.network_ip : "")}\" \"${(var.pvc_data_services ? "ecs.${google_compute_address.ecs-public-ip[count.index].address}.nip.io" : "")}\" \"${(var.pvc_data_services ? google_compute_instance.ecs[count.index].network_interface.0.network_ip : "")}\" \"${(var.deploy_ocp ? "ocp.${google_compute_address.ocp-public-ip[count.index].address}.nip.io" : "")}\"> /tmp/resources/setup.log 2>&1 &",
      "sleep 1 # don't remove - needed for the nohup to work",
    ]
  }
}


packer {
  required_plugins {
    googlecompute = {
      version = ">= 1.1.4"
      source  = "github.com/hashicorp/googlecompute"
    }
  }
}

variable "project_id" {
  default = "webapp-414216"
}

variable "source_image_family" {
  default = "centos-stream-8"
}

variable "zone" {
  default = "us-central1-a"
}

variable "ssh_username" {
  default = "itssahane_rasika"
}

variable "image_name" {
  default = "centos8-custom-image"
}

variable "instance_name" {
  default = "centos8"
}

variable "network" {
  default = "default"
}

source "googlecompute" "csye6225-5" {
  project_id          = var.project_id
  source_image_family = var.source_image_family
  zone                = var.zone
  ssh_username        = var.ssh_username
  image_name          = var.image_name
  instance_name       = var.instance_name
  disk_size           = 20
}

build {
  sources = [
    "googlecompute.csye6225-5"
  ]

  provisioner "shell" {
    inline = [
      "set -o xtrace",
      "sudo useradd -r -s /usr/sbin/nologin csye6225",
      "sudo mkdir -p /home/csye6225/application",
      "sudo chmod 777 /home/csye6225/application",
      "sudo yum -y install python3",
      "sudo yum -y install python3-pip",
      "sudo chmod 777 /etc/systemd/system"
    ]
  }

  provisioner "file" {
    source      = "csye6225.service"
    destination = "/etc/systemd/system/csye6225.service"
  }

  provisioner "file" {
    source      = "dist/healthcheck-0.1.tar.gz"
    destination = "/home/csye6225/application/healthcheck-0.1.tar.gz"
  }

  provisioner "file" {
    source      = "requirements.txt"
    destination = "/home/csye6225/application/requirements.txt"
  }

  provisioner "shell" {
    inline = [
      "sudo yum -y install python3-devel",
      "sudo yum groupinstall -y 'Development Tools'",
      "sudo pip3 install greenlet",
      "sudo pip3 install --upgrade pip",
      "pip3 install --user -r /home/csye6225/application/requirements.txt",
      "sudo chown -R csye6225:csye6225 /home/csye6225/application/",
      "sudo chmod 777 /home/csye6225/application/",
      "sudo pip3 install --upgrade pip",
      "sleep 3",
      "sudo pip3 install /home/csye6225/application/healthcheck-0.1.tar.gz",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable --now csye6225",
      "sudo systemctl start csye6225"
    ]
  }
}

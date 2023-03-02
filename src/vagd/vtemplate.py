VAGRANT_TEMPLATE = '''# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

$script = <<SCRIPT
    sudo apt update
    sudo apt install libc6-dbg gdbserver  -y
SCRIPT

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vm.box = "{}"

  config.vm.provision "shell", inline: $script

end'''

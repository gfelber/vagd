VAGRANT_TEMPLATE = '''# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

$script = <<SCRIPT
    sudo apt update
    sudo apt install {packages}  -y
SCRIPT

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vm.box = "{box}"

  config.vm.provision "shell", inline: $script

end'''

DOCKER_TEMPLATE = '''FROM {image}

# install packages
RUN apt-get update && \\
    apt-get install -y {packages} \\
    systemctl 

# init user and ssh
EXPOSE 22
RUN useradd --create-home --shell /bin/bash {user}
USER {user}

WORKDIR /home/{user}
COPY {keyfile} .ssh/authorized_keys

USER root
RUN mkdir -p /run/sshd && \\
    chmod 755 /run/sshd
    
    
CMD /usr/sbin/sshd; \\
    while true; do sleep 1m; done
'''
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
    apt-get install -y {packages}

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

DOCKER_ALPINE_TEMPLATE = '''FROM {image}

# install packages
RUN apk update
# we need make and linux-headers to compile gdb
RUN apk add python3
RUN apk add --no-cache musl-dbg
# install gdb
RUN apk add --no-cache gdb
# install ssh server support and keys
RUN apk add --no-cache openssh

EXPOSE 22
RUN adduser -h /home/vagd -s /bin/ash -D vagd
RUN echo "vagd:vagd" | chpasswd

USER vagd

WORKDIR /home/vagd

COPY keyfile.pub .ssh/authorized_keys

USER root
RUN ssh-keygen -A
RUN mkdir -p /run/sshd && \
    chmod 755 /run/sshd


CMD /usr/sbin/sshd; \
    while true; do sleep 1m; done

'''

VAGRANT_TEMPLATE = """# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vm.box = "{box}"

end"""

LOCK_PACKAGES = """
ADD https://raw.githubusercontent.com/reproducible-containers/repro-sources-list.sh/v0.1.4/repro-sources-list.sh \
    /usr/local/bin/repro-sources-list.sh
RUN bash /usr/local/bin/repro-sources-list.sh
"""

DOCKER_TEMPLATE = """FROM {image}

USER root

{lock}

# install packages
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt install -y {packages}
RUN apt clean && rm -rf /var/lib/apt/lists/*

# init user and ssh
EXPOSE 22
RUN useradd --create-home --shell /bin/bash -g sudo {user}
RUN chown -R {user}:sudo /home/{user}
RUN chmod u+s /usr/bin/sudo
RUN echo "{user} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/{user} && chmod 0440 /etc/sudoers.d/{user}
USER {user}

WORKDIR /home/{user}
COPY {keyfile} .ssh/authorized_keys

USER root
COPY {keyfile} /root/.ssh/authorized_keys
RUN mkdir -p /run/sshd && \\
  chmod 755 /run/sshd

ENTRYPOINT []

CMD /usr/sbin/sshd; \\
  while true; do sleep 1m; done
"""


# TODO: proper template generation for alpine
DOCKER_ALPINE_TEMPLATE = """FROM {image}

USER root

# install packages
RUN apk update
RUN apk add --no-cache python3
RUN apk add --no-cache musl-dbg
# install gdb
RUN apk add --no-cache gdb
# install ssh server support and keys
RUN apk add --no-cache openssh
# install sudo
RUN apk add --no-cache sudo

EXPOSE 22
RUN chmod u+s /usr/bin/sudo
RUN adduser -h /home/{user} -s /bin/ash -g sudo -D {user}
RUN echo "{user} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/{user} && chmod 0440 /etc/sudoers.d/{user}
RUN echo "{user}:{user}" | chpasswd
RUN sed "s/AllowTcpForwarding no/AllowTcpForwarding yes/" -i /etc/ssh/sshd_config

USER {user}

WORKDIR /home/{user}

COPY {keyfile} .ssh/authorized_keys

USER root
COPY {keyfile} /root/.ssh/authorized_keys
RUN ssh-keygen -A
RUN mkdir -p /run/sshd && \
  chmod 755 /run/sshd

ENTRYPOINT []

CMD /usr/sbin/sshd; \
  while true; do sleep 1m; done

"""

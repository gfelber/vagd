import vagrant
from fabric import Config, task, Connection

v = vagrant.Vagrant('./test')
# v.init('ubuntu/focal64')
# print(v.status)
v.up()
conn = Connection(
    host=v.hostname(),
    user=v.user(),
    port=v.port(),
    connect_kwargs={
        'key_filename': v.keyfile(),
    }
)
conn.put('./test/sysinfo')
conn.run('./sysinfo')

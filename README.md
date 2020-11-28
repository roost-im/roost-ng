# roost-ng
Django-based roost backend server

Roost-ng is a Python rewrite of [Roost](https://github.com/roost-im/roost).

## Installing

To install, first you'll need a database server (eg, Postgres or sqlite3, but anything supported by Django should be fine), a web server as a frontend (eg, nginx), Redis, and various dev libraries. On Ubuntu, the following packages might be good:
* postgresql
* krb5-user     # Helpful for diagnostics
* libpq-dev     # needed for building psycopg2 python extension
* libkrb5-dev
* libzephyr-dev
* redis-server
* libzephyr4-krb5
* zephyr-clients # needed for zhm
* nginx

Examples in this file and defaults in the repo sometimes assume you're running Roost-ng as the `roost-ng` user, with the checkout at `/opt/roost-ng/roost-ng/` -- you can adjust this if you wish, or may choose to just copy it.

Then clone this repo, create a virtualenv if you want, and install all the Python dependencies:
```shell
virtualenv --python=python3 /opt/roost-ng/ve/
. /opt/roost-ng/ve/bin/activate
pip install Cython    # you may need to do this early -- python-zephyr's setup.py uses it, and may crash if it's not installed already
pip install psycopg2  # only if using Postgres
pip install -r requirements.txt
```

### Configuring roost-ng

Configuration for roost-ng generally lives in `/etc/roost-ng/config.yml` -- you can look at `roost_ng/settings/*.py` to get a feel for what's available, but many of the settings will be pulled from the `filename:setting` key in `/etc/roost-ng/config.yml` if it's present, so setting things there may be more convenient. A minimal example might look like:

```yaml
database:
  default:
    ENGINE: django.db.backends.postgresql_psycopg2
    NAME: roost-ng
    USER: roost-ng
gssapi:
  client_keytab: /etc/roost-ng/daemon.keytab
  server_keytab: /etc/roost-ng/HTTP.keytab
```

The Django `SECRET_KEY` can be specified in its own file -- `/etc/roost-ng/django-SECRET_KEY` (the entire contents will be used) -- which may be easier to manage than putting it with the less-sensitive contents of `config.yml`.

### Other setup

You should also have a functioning `zhm` on your machine -- on a plain Ubuntu machine, `/etc/default/zephyr-clients` should have a line like `zhm_args="z1.mit.edu z2.mit.edu"`.

You'll likely need to create your database -- make sure to use UTF-8 for your encoding. Once it's created, use `./manage.py migrate` to create all the tables roost-ng needs.

There's a `systemd` service file at `misc/systemd/roost-ng.service` that may be helpful.

Configure your web server to point at your roost-ng install -- for example, with nginx, you might add the following to a vhost:
```nginx
    # START ROOST-NG
    location /roost-api/v1/ {
        proxy_set_header Script_Name /roost-api;
        proxy_set_header Daphne-Root-Path /roost-api;
        include proxy_params;
        proxy_pass http://unix:/opt/roost-ng/roost-ng.sock;
        break;
    }
    location /roost-api/v1/socket/ {
        proxy_http_version 1.1;
        proxy_set_header Script_Name /roost-api;
        proxy_set_header Daphne-Root-Path /roost-api;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_pass http://unix:/opt/roost-ng/roost-ng.sock;
        break;
    }
    # END ROOST-NG
```

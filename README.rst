pdnsupdate
==========

Use RFC2136 to update record on powerdns with a call to external IP resolver

RFC236 par is inspired from certbot_dns_rfc2136

PowerDNS config
---------------
You need to configure PowerDNS to a;;ow dynamic update (server wide or per zone) :
https://doc.powerdns.com/authoritative/dnsupdate.html#setting-up-dhcpd

For example for per zone settings :

First allow DNSUPDATE for the domain example.com (if yu can determine the IP range your ISP use to restrict update for this range)

.. code-block:: SQL

    select id from domains where name='example.org';
    5
    insert into domainmetadata(domain_id, kind, content) values(5, ‘ALLOW-DNSUPDATE-FROM’,’0.0.0.0’);

Generate a tsig key (named test for the example)

.. code-block:: shell

    pdnsutil generate-tsig-key test hmac-md5
    Create new TSIG key test hmac-md5 kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=

Latest version of powerDNS add automaticaly the key in the database

Link the key for the domain

.. code-block:: SQL

    insert into domainmetadata (domain_id, kind, content) values (5, 'TSIG-ALLOW-DNSUPDATE', 'test');

Test the configuration with nsupdate:

.. code-block:: shell

    nsupdate <<!
    server <ip> <port>
    zone example.org
    update add test1.example.org 3600 A 203.0.113.1
    key test kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=
    send
    !

pdnsupdate config
-----------------
Copy the config.ini-dist to config.ini and set your value

.. code-block:: ini

    [DEFAULT]
    public_ip_provider = http://ifconfig.me
    local_name = <hostname to be updated>

    [DNS]
    dns_server = <pdsn address>
    dns_port = 53
    dns_tsig_name = <tsig key name>
    dns_tsig_value = <tsig key value>
    dns_tsig_algorithm = hmac-md5

    [PERSIST]
    persit_file = data/persistance.db

I use ifconfig.me as public IP finder, you can use any http(s) site that return only the IP address in the body

you can set the file used to track the previous ip address
This software is an eCAP adapter used to inject or enable a promotional
network by injecting an ad/promotion into the users http browser session.
However the mechanism is broad enough to allow any javascript to be injected
into a users session. 

Available adapters (installed in /usr/local/lib/ by default):

    slurm: injects an html script tag into the header of any valid http web
           request. Requests are validated against an extension list, a
           domain whitelist, and request/response headers including:
           Cache-Control "no-transform", Content-MD5, Content-Type
           "text/html", and Content-Encoding.

           After validation the headers are then mangled to include no-cache
           controls and date last modified to limit the amount of caching by
           the browser.

The libecap-0.0.3 library is required to build and use these adapters. You can
get the library from http://www.e-cap.org/. The adapters can be built and
installed from source, usually by running:

    % ./configure
    % make
    % sudo make install

For documentation, the libecap library implementation, and support
information, please visit the eCAP project web site: http://www.e-cap.org/

This adapter and libecap work in conjunction with squid-3.1.15 proxy server.
You can get squid from http://www.squid-cache.org/. Squid can be built in a
similar manor, usually by running:

    % ./configure --enable-ecap --prefix=/usr
    % make
    % sudo make install

For documentation and support please see the squid projects website
http://www.squid-cache.org/.

Next we need to build the ecap slurm adapter.

    % ./bootstrap.sh
    % ./configure
    % make
    % sudo make install

After installing the slurm adapter we just need to setup squid config. Copy
the example configuration file over to /etc/squid/slurm.conf and setup squid
to using this config. Or you can replace the default config.

    % sudo cp config/slurm.conf /etc/squid/squid.conf

Now you can start squid either using the manual configuration or using the
newly copied default config.

    % /usr/sbin/squid -f /etc/config/slurm.conf
or
    % /etc/init.d/squid start

To shutdown squid you can use the stop or the shutdown command

    % /usr/sbin/squid -f /etc/config/slurm.conf -k shutdown
or
    % /etc/init.d/squid stop

Make sure to also open up any firewall to use the port configured in
slurm.conf.

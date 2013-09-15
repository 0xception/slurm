#!/bin/sh

LIBECAP_VERSION=0.0.3
SQUID_VERSION=3.1.15

LIBECAP_SOURCE=http://www.measurement-factory.com/tmp/ecap/libecap-$LIBECAP_VERSION.tar.gz
SQUID_SOURCE=http://www.squid-cache.org/Versions/v3/3.1/squid-$SQUID_VERSION.tar.gz

BASE=/opt/

wget --timeout 90 $LIBECAP_SOURCE -O $BASE/libecap-$LIBECAP_VERSION.tar.gz
if [ "$?" -ne 0 ]; then
    echo "Failed to obtain libecap source. Please install manually"
    exit
fi

tar -xzf $BASE/libecap-$LIBECAP_VERSION.tar.gz

VPATH=$BASE/libecap-$LIBECAP_VERSION/
$BASE/libecap-$LIBECAP_VERSION/configure
$BASE/libecap-$LIBECAP_VERSION/make
sudo $BASE/libecap-$LIBECAP_VERSION/make install

wget --timeout 90 $BASE/$LIBECAP_VERSION.tar.gz
if [ "$?" -ne 0 ]; then
    echo "Failed to obtain squid source. Please install manually"
    exit
fi

VPATH=$BASE/squid-$SQUID_VERSION/
tar -xzf $BASE/squid-$SQUID_VERSION.tar.gz
$BASE/squid-$SQUID_VERSION/configure --enable-ecap --prefix=/usr
$BASE/squid-$SQUID_VERSION/make
sudo $BASE/squid-$SQUID_VERSION/make install

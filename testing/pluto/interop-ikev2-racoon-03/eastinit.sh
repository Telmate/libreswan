: ==== start ====
TESTNAME=interop-ikev2-racoon-03

#source /testing/pluto/bin/eastlocal.sh
mkdir /tmp/racoon2
cp -r /testing/pluto/$TESTNAME/east-racoon/* /tmp/racoon2/
chmod 700 /tmp/racoon2/psk/test.psk   
/usr/local/racoon2/etc/init.d/spmd start
/usr/local/racoon2/etc/init.d/iked start

sleep 3

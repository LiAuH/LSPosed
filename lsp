#!/bin/bash
cp classes.dex /data/app
cp liblspd.so /data/app
cp hooks.apk /data/app
chmod 777 /data/app/classes.dex
chmod 777 /data/app/liblspd.so
chmod 777 /data/app/hooks.apk
chown system.system /data/app/classes.dex
chown system.system /data/app/liblspd.so
chown system.system /data/app/hooks.apk
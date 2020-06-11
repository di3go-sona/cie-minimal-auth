#! /bin/sh
sudo rmmod pn533_usb
sudo rmmod pn533
systemctl restart pcscd

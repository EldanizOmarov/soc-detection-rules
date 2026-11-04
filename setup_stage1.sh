#!/usr/bin/env bash
# Merhele 1 qurasdirmasi - Ubuntu WSL (root)
set -u
PACK="$(cd "$(dirname "$0")" && pwd)"
REPO=/root/soc-detection-rules
STACK=/root/elastic-stack
OLD="$STACK/docker-compose.yml"
say(){ echo; echo "=== $* ==="; }
fail(){ echo "XETA: $*"; exit 1; }

[ "$(id -u)" = 0 ] || fail "root olmalidir"
command -v docker >/dev/null || fail "docker tapilmadi"
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
[ -d "$REPO" ] || fail "$REPO yoxdur"
[ -f "$OLD" ] || fail "$OLD yoxdur"

say "1/9 Yaddas yoxlamasi"
free -m | sed -n 1,2p
TOT=$(free -m | awk '/Mem:/{print $2}')
[ "$TOT" -lt 6000 ] && echo "DIQQET: WSL RAM ($TOT MB) azdir, .wslconfig-da memory=8GB lazim ola biler."

say "2/9 Qovluqlar"
mkdir -p /var/log/cold_storage /var/log/soc-web
touch /var/log/soc-web/access.log /var/log/auth.log
chmod 755 /var/log/cold_storage /var/log/soc-web; chmod 644 /var/log/soc-web/access.log
echo OK

say "3/9 Git identity"
git config --global user.name "Eldaniz Omarov"
git config --global user.email "eldanizomarov2007@gmail.com"
git config --global init.defaultBranch main
echo OK

say "4/9 Fayllari repoya kopyalama"
cp -a "$PACK"/. "$REPO"/
rm -f "$REPO/setup_stage1.sh.bak"
cd "$REPO" && ls

say "5/9 .env (parollar git-e dusmur)"
if [ -f "$STACK/.env" ]; then
  echo ".env artiq var, toxunulmur"
else
  getv(){ grep -oP "$1\"?[=:] *\"?\K[^\s\"']+" "$OLD" 2>/dev/null | head -1; }
  EP=$(getv ELASTIC_PASSWORD)
  [ -n "$EP" ] || fail "kohne compose-dan ELASTIC_PASSWORD oxunmadi; $OLD faylini yoxlayin"
  KP=$(getv ELASTICSEARCH_PASSWORD); [ -n "$KP" ] || KP=$(openssl rand -hex 12)
  K1=$(getv XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY); [ ${#K1} -ge 32 ] || K1=$(openssl rand -hex 16)
  K2=$(getv XPACK_SECURITY_ENCRYPTIONKEY);              [ ${#K2} -ge 32 ] || K2=$(openssl rand -hex 16)
  K3=$(getv XPACK_REPORTING_ENCRYPTIONKEY);             [ ${#K3} -ge 32 ] || K3=$(openssl rand -hex 16)
  umask 077
  { echo "ELASTIC_PASSWORD=$EP"; echo "KIBANA_PASSWORD=$KP"; echo "KB_KEY_ENC=$K1"; echo "KB_KEY_SEC=$K2"; echo "KB_KEY_REP=$K3"; } > "$STACK/.env"
  echo ".env yaradildi (parollar ekrana cixarilmir)"
fi
set -a; . "$STACK/.env"; set +a

say "6/9 Compose yedek + yenisi"
cp "$OLD" "$OLD.bak.$(date +%s)"
cp "$REPO/elastic-stack/docker-compose.yml" "$OLD"
echo OK

say "7/9 Logstash konfiqurasiya testi (ilk defe image yuklenir, 2-4 deq)"
docker run --rm -e ELASTIC_PASSWORD=x -v "$REPO/logstash/pipeline":/usr/share/logstash/pipeline:ro \
  docker.elastic.co/logstash/logstash:8.11.3 logstash -t --path.data /tmp/lsdata > /tmp/ls_test.log 2>&1
if grep -q "Configuration OK" /tmp/ls_test.log; then echo "Logstash konfiqurasiyasi: OK"; else tail -n 25 /tmp/ls_test.log; fail "Logstash konfiqurasiya xetasi (yuxaridaki xetani gonderin)"; fi

say "8/9 Stack-in qaldirilmasi"
cd "$STACK"
$DC up -d elasticsearch
echo -n "Elasticsearch gozlenilir"
for i in $(seq 1 60); do
  if curl -s -u "elastic:$ELASTIC_PASSWORD" http://127.0.0.1:9201/_cluster/health | grep -qE '"status":"(green|yellow)"'; then echo " hazir"; break; fi
  echo -n "."; sleep 3
done
curl -s -u "elastic:$ELASTIC_PASSWORD" -X POST -H 'Content-Type: application/json' \
  http://127.0.0.1:9201/_security/user/kibana_system/_password -d "{\"password\":\"$KIBANA_PASSWORD\"}" >/dev/null
$DC up -d
echo -n "Logstash gozlenilir"
for i in $(seq 1 40); do curl -s http://127.0.0.1:9600 >/dev/null && { echo " hazir"; break; }; echo -n "."; sleep 3; done

say "9/9 ES obyektlerinin API ile tetbiqi + git commit"
python3 "$REPO/deploy/soc_deploy.py" es
cd "$REPO" && git add -A && git commit -q -m "Merhele 1: Logstash router, 6 dedicated indeks, ILM, enrichment, deploy skriptleri" && echo "git commit OK" || echo "(commit edilecek yeni deyisiklik yoxdur)"
echo
$DC -f "$STACK/docker-compose.yml" ps 2>/dev/null | sed -n 1,12p
echo; echo "HAZIRDIR. Novbeti: python3 $REPO/deploy/soc_deploy.py status"

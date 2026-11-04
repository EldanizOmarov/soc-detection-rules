#!/usr/bin/env bash
# Routing deyisikliyini: test -> git commit/push -> Logstash hot-reload -> API ile tesdiq
REPO=/root/soc-detection-rules; cd $REPO
rel(){ curl -s http://127.0.0.1:9600/_node/stats/reloads | python3 -c "import sys,json;r=json.load(sys.stdin)['reloads'];print('  successes=%s failures=%s last_success=%s'%(r['successes'],r['failures'],r.get('last_success_timestamp')))"; }
echo "[1/4] Konfiqurasiya testi"
docker run --rm -e ELASTIC_PASSWORD=x -v $REPO/logstash/pipeline:/usr/share/logstash/pipeline:ro docker.elastic.co/logstash/logstash:8.11.3 logstash -t --path.data /tmp/lsdata 2>&1 | grep -q "Configuration OK" && echo "  OK" || { echo "  XETA - tetbiq edilmedi"; exit 1; }
echo "[2/4] Evvelki reload saygaci"; rel
echo "[3/4] git commit + push"
git add logstash docs deploy && git commit -q -m "${1:-routing update}" && echo "  commit OK" || echo "  (yeni deyisiklik yoxdur)"
git push origin HEAD 2>&1 | tail -n 3
echo "[4/4] Logstash hot-reload (config.reload.automatic) - 15 san gozlenilir"; sleep 15; rel

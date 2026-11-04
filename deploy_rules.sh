#!/usr/bin/env bash
# SIGMA (GitHub) -> konvertasiya -> API ile iki SIEM-e tetbiq. UI-da qayda yazilmir.
set -e
cd "$(dirname "$0")"
python3 deploy/sigma_convert.py all
python3 deploy/deploy_elastic.py
python3 deploy/deploy_wazuh.py

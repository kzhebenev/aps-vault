#!/bin/bash
# Backend tests in a throwaway container (no local venv needed).
#   ./run_tests.sh            — pytest on SQLite (single node + the two-node cluster test on a shared file)
#   ./run_tests.sh pg         — the same suite against a throwaway PostgreSQL 16 (what a cluster runs on)
#   ./run_tests.sh gost       — the same suite with VAULT_CIPHER=gost (Kuznyechik-MGM / Streebog / KDF_TREE)
# Every mode ends with tests/compat_fixture_check.py: a 0.17.1 database must still open.
#   ./run_tests.sh audit      — pip-audit of runtime dependencies
#   PYTEST_ARGS=tests/test_rotation.py ./run_tests.sh   — a subset (any mode)
set -e
cd "$(dirname "$0")"
IMG=python:3.11-slim
# SoftHSM2 inside the test container: a PKCS#11 token for the HSM tests (test_hsm.py). Installed
# from Debian, token initialised in /tmp; the tests see it through VAULT_PKCS11_MODULE. Without
# it the HSM tests are skipped with "НЕ НАСТРОЕНО".
SOFTHSM_PREP='(apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y softhsm2 >/dev/null 2>&1) && mkdir -p /tmp/softhsm && printf "directories.tokendir = /tmp/softhsm\nobjectstore.backend = file\n" > /tmp/softhsm2.conf && export SOFTHSM2_CONF=/tmp/softhsm2.conf && softhsm2-util --init-token --free --label aps-vault --pin 1234 --so-pin 12345678 >/dev/null && export VAULT_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so VAULT_PKCS11_TOKEN_LABEL=aps-vault TEST_PKCS11_PIN=1234;'

# LocalStack (community image, AWS KMS only) as the cloud-KMS emulator for test_kms.py: same wire
# protocol as AWS (SigV4, EncryptionContext). Without it the KMS tests are skipped with "НЕ НАСТРОЕНО".
KMS_IMG=localstack/localstack:3.8.1
NET=aps-vault-test-$$; PG=aps-vault-test-pg-$$; LS=aps-vault-test-kms-$$
# -v: postgres, mariadb, openldap and localstack declare VOLUME — without it every run left anonymous volumes behind
cleanup() { docker rm -fv "$PG" "$LS" "$MY" "$LD" "$SSHC" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
KMS_ENV=()
PG_TARGET_ENV=()
# PostgreSQL as a rotation *target* (test_rotation.py: ALTER ROLE + login with the new password).
# Without it the postgres-target tests are skipped with "НЕ НАСТРОЕНО". The pg mode uses the same server as the store.
start_pg() {
  docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=vault -e POSTGRES_PASSWORD=vault -e POSTGRES_DB=vault postgres:16-alpine >/dev/null
  for i in $(seq 1 30); do docker exec "$PG" pg_isready -U vault -q && break; sleep 1; done
  PG_TARGET_ENV=(-e "TEST_ROTATION_PG_DSN=postgresql://vault:vault@$PG:5432/vault")
}
MY=aps-vault-test-my-$$
MY_TARGET_ENV=()
# MariaDB as a rotation *target* (test_rotation.py: ALTER USER + login with the new password); skipped with "НЕ НАСТРОЕНО" when absent
start_mysql() {
  docker run -d --name "$MY" --network "$NET" -e MARIADB_ROOT_PASSWORD=rootpw -e MARIADB_DATABASE=app mariadb:11 >/dev/null || return 0
  for i in $(seq 1 60); do docker exec "$MY" mariadb -uroot -prootpw -e 'select 1' >/dev/null 2>&1 && break; sleep 1; done
  MY_TARGET_ENV=(-e "TEST_ROTATION_MYSQL_DSN=mysql://root:rootpw@$MY:3306/app")
}
LD=aps-vault-test-ldap-$$; SSHC=aps-vault-test-ssh-$$
LD_TARGET_ENV=(); SSH_TARGET_ENV=()
# OpenLDAP as a rotation target (test_rotation.py: userPassword replaced through the bind account, bind with the
# new password). Without it the ldap-target test is skipped with "НЕ НАСТРОЕНО".
start_ldap() {
  docker run -d --name "$LD" --network "$NET" -e LDAP_ORGANISATION=Example -e LDAP_DOMAIN=example.org -e LDAP_ADMIN_PASSWORD=adminpw osixia/openldap:1.5.0 >/dev/null || return 0
  for i in $(seq 1 60); do docker exec "$LD" ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w adminpw -s base >/dev/null 2>&1 && break; sleep 1; done
  LD_TARGET_ENV=(-e "TEST_ROTATION_LDAP_URL=ldap://$LD:389" -e "TEST_ROTATION_LDAP_BIND_DN=cn=admin,dc=example,dc=org" -e TEST_ROTATION_LDAP_BIND_PW=adminpw -e "TEST_ROTATION_LDAP_BASE=dc=example,dc=org")
}
# An sshd on Alpine as a rotation target (test_rotation.py: chpasswd through sudo, login with the new password).
# Accounts: admin/adminpw (sudo NOPASSWD), app, denied (DenyUsers → the probe fails and the old password is restored).
start_ssh() {
  docker run -d --name "$SSHC" --network "$NET" alpine:3.20 sh -c '
    apk add -q openssh sudo shadow >/dev/null 2>&1 && ssh-keygen -A >/dev/null 2>&1 &&
    adduser -D admin && echo "admin:adminpw" | chpasswd && echo "admin ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/admin &&
    adduser -D app && echo "app:old-ssh-pw-1" | chpasswd &&
    adduser -D denied && echo "denied:old-denied-pw-1" | chpasswd &&
    echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs &&
    printf "PasswordAuthentication yes\nPermitRootLogin no\nDenyUsers denied\n" >> /etc/ssh/sshd_config &&
    exec /usr/sbin/sshd -D -e' >/dev/null || return 0
  for i in $(seq 1 90); do docker exec "$SSHC" sh -c 'pgrep -x sshd >/dev/null' 2>/dev/null && break; sleep 1; done
  SSH_TARGET_ENV=(-e "TEST_ROTATION_SSH_HOST=$SSHC" -e TEST_ROTATION_SSH_ADMIN=admin -e TEST_ROTATION_SSH_ADMIN_PW=adminpw)
}
start_kms() {
  docker run -d --name "$LS" --network "$NET" -e SERVICES=kms -e EAGER_SERVICE_LOADING=1 $KMS_IMG >/dev/null || return 0
  for i in $(seq 1 60); do
    KEY=$(docker exec "$LS" awslocal kms create-key --query KeyMetadata.KeyId --output text 2>/dev/null) && [ -n "$KEY" ] && break
    sleep 2; KEY=
  done
  if [ -n "$KEY" ]; then
    KMS_ENV=(-e VAULT_KMS_PROVIDER=aws -e VAULT_KMS_KEY_ID="$KEY" -e VAULT_KMS_REGION=us-east-1 -e "VAULT_KMS_ENDPOINT=http://$LS:4566/" -e VAULT_KMS_AWS_ACCESS_KEY=test -e VAULT_KMS_AWS_SECRET_KEY=test)
  else
    echo "KMS emulator did not come up — test_kms.py will be skipped (НЕ НАСТРОЕНО)" >&2
  fi
}

case "${1:-}" in
  audit)
    docker run --rm -v "$PWD:/repo:ro" -w /repo/backend $IMG bash -c \
      "pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && pip-audit -r requirements.txt" ;;
  pg)
    trap cleanup EXIT
    docker network create "$NET" >/dev/null
    start_kms
    start_pg
    start_mysql
    start_ldap
    start_ssh
    URL="postgresql+psycopg://vault:vault@$PG:5432/vault"
    docker run --rm --network "$NET" -v "$PWD:/repo:ro" -w /repo/backend -e PYTHONDONTWRITEBYTECODE=1 "${KMS_ENV[@]}" "${PG_TARGET_ENV[@]}" "${MY_TARGET_ENV[@]}" "${LD_TARGET_ENV[@]}" "${SSH_TARGET_ENV[@]}" \
      -e VAULT_DATABASE_URL="$URL" -e TEST_DATABASE_URL="$URL" $IMG bash -c \
      "$SOFTHSM_PREP pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && python -m pytest -q -p no:cacheprovider ${PYTEST_ARGS:-tests/} && python tests/compat_fixture_check.py" ;;
  gost)
    trap cleanup EXIT
    docker network create "$NET" >/dev/null
    start_kms
    start_pg
    start_mysql
    start_ldap
    start_ssh
    docker run --rm --network "$NET" -v "$PWD:/repo:ro" -w /repo/backend -e PYTHONDONTWRITEBYTECODE=1 -e VAULT_CIPHER=gost "${KMS_ENV[@]}" "${PG_TARGET_ENV[@]}" "${MY_TARGET_ENV[@]}" "${LD_TARGET_ENV[@]}" "${SSH_TARGET_ENV[@]}" $IMG bash -c \
      "$SOFTHSM_PREP pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && python -m pytest -q -p no:cacheprovider ${PYTEST_ARGS:-tests/} && python tests/compat_fixture_check.py" ;;
  *)
    trap cleanup EXIT
    docker network create "$NET" >/dev/null
    start_kms
    start_pg
    start_mysql
    start_ldap
    start_ssh
    docker run --rm --network "$NET" -v "$PWD:/repo:ro" -w /repo/backend -e PYTHONDONTWRITEBYTECODE=1 "${KMS_ENV[@]}" "${PG_TARGET_ENV[@]}" "${MY_TARGET_ENV[@]}" "${LD_TARGET_ENV[@]}" "${SSH_TARGET_ENV[@]}" $IMG bash -c \
      "$SOFTHSM_PREP pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && python -m pytest -q -p no:cacheprovider ${PYTEST_ARGS:-tests/} && python tests/compat_fixture_check.py" ;;
esac

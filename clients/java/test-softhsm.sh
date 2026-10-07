#!/usr/bin/env bash
# Runs VaultClientTest in Docker (no JDK needed on the host), including the hardware-key part on SoftHSM2 reached
# through SunPKCS11. Two SunPKCS11 facts shape the recipe:
#   1. the SunPKCS11 KeyStore shows a private key only when a certificate with the same CKA_ID sits next to it, and
#      `pkcs11-tool --keypairgen` writes none — so a CA-issued certificate for the token's public key is made with
#      `openssl x509 -force_pubkey` (no PKCS#11 engine required) and written into the token;
#   2. without `attributes = compatibility` the provider sends only CKA_CLASS/CKA_KEY_TYPE on C_DeriveKey, SoftHSM2
#      then creates the derived secret CKA_SENSITIVE=true and generateSecret() fails with CKR_ATTRIBUTE_SENSITIVE.
set -euo pipefail
cd "$(dirname "$0")/.."
exec docker run --rm -v "$PWD:/clients" -w /clients/java eclipse-temurin:17-jdk bash -c '
set -e
apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y softhsm2 opensc >/dev/null 2>&1
M=/usr/lib/softhsm/libsofthsm2.so
mkdir -p /tmp/sh && printf "directories.tokendir = /tmp/sh\nobjectstore.backend = file\n" > /tmp/sh.conf && export SOFTHSM2_CONF=/tmp/sh.conf
softhsm2-util --init-token --free --label node --pin 1234 --so-pin 12345678 >/dev/null
pkcs11-tool --module $M --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label vault-node --id 01 >/dev/null 2>&1
pkcs11-tool --module $M --read-object --type pubkey --label vault-node -o /tmp/pub.der >/dev/null 2>&1
# certificate for the token key, issued by a throwaway CA (what an org CA does for a TPM key in life)
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/ca.key 2>/dev/null
openssl req -new -x509 -key /tmp/ca.key -subj /CN=test-ca -days 1 -out /tmp/ca.crt 2>/dev/null
openssl req -new -key /tmp/ca.key -subj /CN=vault-node -out /tmp/node.csr 2>/dev/null
openssl x509 -req -in /tmp/node.csr -CA /tmp/ca.crt -CAkey /tmp/ca.key -force_pubkey /tmp/pub.der -keyform DER -days 1 -set_serial 1 -outform DER -out /tmp/node.der 2>/dev/null
pkcs11-tool --module $M --login --pin 1234 --write-object /tmp/node.der --type cert --id 01 --label vault-node >/dev/null 2>&1
printf "name = test\nlibrary = %s\nslotListIndex = 0\nattributes = compatibility\n" "$M" > /tmp/p11.cfg
mkdir -p /tmp/out && javac -Xlint:all -d /tmp/out src/main/java/io/apsvault/*.java src/test/java/io/apsvault/*.java
VAULT_TEST_PKCS11_CONF=/tmp/p11.cfg VAULT_TEST_PKCS11_PUB=/tmp/pub.der java -cp /tmp/out io.apsvault.VaultClientTest
'

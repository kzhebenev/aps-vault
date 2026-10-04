# -*- coding: utf-8 -*-
# APS Vault lookup plugin for Ansible (0.25). MIT.
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: aps_vault
author: APS Vault
version_added: "0.28.2"
short_description: Read secrets from APS Vault with a folder-scoped service token
description:
  - Fetches a secret from an APS Vault machine API (C(GET /api/v1/m/secret/<name>)) and returns its
    value, its login, its notes, the current TOTP code, or the whole record.
  - Works with plaintext tokens out of the box (standard library only). A token with sealed delivery
    (docs/SEALED.md) needs the C(aps-vault) Python client installed on the controller
    (C(pip install aps-vault)) and the node's private key in C(client_key) / C(VAULT_CLIENT_KEY).
options:
  _terms:
    description: Secret names (the C(name) in the vault; use C(/) in names for a tree).
    required: true
  url:
    description: Vault base URL.
    type: str
    env: [{name: VAULT_URL}]
    ini: [{section: aps_vault, key: url}]
  token:
    description: Service token (C(vlt_…)). Prefer C(token_file) or the environment over a literal in a playbook.
    type: str
    env: [{name: VAULT_TOKEN}]
    ini: [{section: aps_vault, key: token}]
  token_file:
    description: File holding the token (mode 0600), used when C(token) is empty.
    type: path
    env: [{name: VAULT_TOKEN_FILE}]
    ini: [{section: aps_vault, key: token_file}]
  client_key:
    description: Base64 private key for sealed delivery (X25519 32 B, GOST 64 B or P-256 scalar).
    type: str
    env: [{name: VAULT_CLIENT_KEY}]
  field:
    description: What to return.
    type: str
    choices: [value, login, notes, totp, full]
    default: value
  version:
    description: Read an older version of the value (C(?version=N)); the current one when omitted.
    type: int
  validate_certs:
    description: Verify the vault's TLS certificate.
    type: bool
    default: true
  timeout:
    description: HTTP timeout in seconds.
    type: int
    default: 10
notes:
  - Values are never logged by the plugin; mark the tasks that use them with C(no_log) anyway.
  - A 401 means the token is invalid, revoked or expired; a 403 that it is outside its where-and-when
    policy or may not read the requested field; a 404 that there is no such secret in the token's
    folder. All fail the task with the server's message.
"""

EXAMPLES = r"""
- name: Database password from the vault (VAULT_URL / VAULT_TOKEN in the environment)
  ansible.builtin.set_fact:
    db_password: "{{ lookup('aps_vault', 'db-password') }}"
  no_log: true

- name: Login and value of the same secret, explicit connection
  ansible.builtin.debug:
    msg: "user={{ lookup('aps_vault', 'db-password', field='login', url='https://vault.example.com', token_file='/etc/app/vault.token') }}"

- name: The whole record (value, login, notes, totp, version)
  ansible.builtin.set_fact:
    db: "{{ lookup('aps_vault', 'db-password', field='full') }}"
  no_log: true

- name: Previous version of a key while re-encrypting
  ansible.builtin.set_fact:
    old_key: "{{ lookup('aps_vault', 'file-encryption-key', version=3) }}"
  no_log: true
"""

RETURN = r"""
_raw:
  description: One item per term — the requested field (string) or the whole record (dict) for C(field=full).
  type: list
"""

import json
import ssl

from ansible.errors import AnsibleError, AnsibleLookupError
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.six.moves.urllib.request import Request, urlopen
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()
_FIELDS = ("value", "login", "notes", "totp", "full")


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        url = (self.get_option("url") or "").rstrip("/")
        if not url:
            raise AnsibleLookupError("aps_vault: no vault url — set VAULT_URL or url=")
        token = self.get_option("token") or ""
        if not token and self.get_option("token_file"):
            with open(self.get_option("token_file"), "r") as f:
                token = f.read().strip()
        if not token:
            raise AnsibleLookupError("aps_vault: no token — set VAULT_TOKEN, VAULT_TOKEN_FILE, token= or token_file=")
        field = self.get_option("field") or "value"
        if field not in _FIELDS:
            raise AnsibleLookupError("aps_vault: field must be one of %s" % ", ".join(_FIELDS))
        version = self.get_option("version")
        ctx = None
        if not self.get_option("validate_certs"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        out = []
        for term in terms:
            name = str(term)
            record = self._fetch(url, token, name, version, ctx, int(self.get_option("timeout") or 10))
            if "sealed" in record and "value" not in record:
                record = self._unseal(record, name)
            if field == "full":
                out.append(record)
            elif field == "totp":
                if record.get("totp") is None:
                    raise AnsibleLookupError("aps_vault: %s has no TOTP, or the token may not read it" % name)
                out.append(record["totp"])
            else:
                if field != "value" and field not in record:
                    raise AnsibleLookupError("aps_vault: the token may not read '%s' of %s (grant it on the token)" % (field, name))
                out.append(record.get(field, ""))
        return out

    def _fetch(self, url, token, name, version, ctx, timeout):
        path = "%s/api/v1/m/secret/%s" % (url, quote(name, safe="/"))
        if version:
            path += "?version=%d" % int(version)
        req = Request(path, headers={"Authorization": "Bearer %s" % token, "Accept": "application/json",
                                     "User-Agent": "ansible-aps-vault/0.28.2"})
        try:
            with urlopen(req, timeout=timeout, context=ctx) as r:   # nosemgrep: dynamic-urllib-use — url from the play's options
                return json.loads(r.read().decode("utf-8"))
        except HTTPError as e:
            try:
                detail = json.loads(e.read().decode("utf-8")).get("detail", "")
            except Exception:
                detail = ""
            if e.code == 404:
                raise AnsibleLookupError("aps_vault: no secret '%s' in the token's folder" % name)
            if e.code == 401:
                raise AnsibleLookupError("aps_vault: 401 for '%s' — the service token is invalid, revoked or expired%s" % (name, (": " + detail) if detail else ""))
            if e.code == 403:
                raise AnsibleLookupError("aps_vault: 403 for '%s' — the token is outside its where-and-when policy or may not read this%s" % (name, (": " + detail) if detail else ""))
            raise AnsibleLookupError("aps_vault: HTTP %d for '%s'%s" % (e.code, name, (": " + detail) if detail else ""))
        except URLError as e:
            raise AnsibleLookupError("aps_vault: cannot reach %s: %s" % (url, e.reason))

    def _unseal(self, record, name):
        key = self.get_option("client_key") or ""
        if not key:
            raise AnsibleLookupError("aps_vault: the token delivers sealed values — set client_key= or VAULT_CLIENT_KEY (the node's private key)")
        try:
            import aps_vault  # the Python client: pip install aps-vault
        except ImportError:
            raise AnsibleError("aps_vault: sealed delivery needs the aps-vault Python client on the controller: pip install aps-vault")
        plain = aps_vault.unseal(record["sealed"], key, name)
        merged = dict(record)
        merged.pop("sealed", None)
        merged.update(plain)
        return merged

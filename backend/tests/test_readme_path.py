"""0.41.5: the README's path (install → store → connect → recover) is executed by ops/checks/golden-path.sh on every
release. These checks keep the README and that script from drifting apart without anyone noticing: the number of
checks the README promises, the backup commands it tells people to type, the UI labels it names, and the facts it
states about the clients' cache."""
import os
import re

import backup

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
read = lambda *p: open(os.path.join(ROOT, *p), encoding="utf-8").read()
READMES = {"README.md": read("README.md"), "README.ru.md": read("README.ru.md")}
SCRIPT = read("ops", "checks", "golden-path.sh")


def test_the_number_of_checks_in_the_readme_is_the_scripts():
    n = len(re.findall(r'\bok "', SCRIPT))
    for name, text in READMES.items():
        claimed = re.findall(r"(\d+) (?:checks|проверок)", text)
        assert claimed == [str(n)], f"{name} promises {claimed} checks, golden-path.sh has {n}"


def test_every_backup_command_in_the_readme_exists_and_the_script_runs_it():
    import contextlib
    import io
    for name, text in READMES.items():
        cmds = set(re.findall(r"python -m backup (\w+)", text))
        assert {"list", "fetch", "decrypt", "restore"} <= cmds, f"{name}: the recovery path lost a step: {cmds}"
        for cmd in cmds:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                try:
                    backup._cli([cmd, "--help"])
                except SystemExit as e:      # argparse: --help exits 0, an unknown command exits 2
                    assert e.code == 0, f"{name}: `python -m backup {cmd}` is not a command of the backup tool"
    for cmd in ("list", "fetch", "decrypt", "restore"):
        assert f"python -m backup {cmd}" in SCRIPT, f"golden-path.sh does not run `python -m backup {cmd}` the README shows"


def test_ui_labels_named_in_the_readme_exist():
    pages = read("frontend", "pages.js") + read("frontend", "app.js")
    en = read("frontend", "i18n-en.js")
    for ru, english in (("Новый токен", "New token"), ("Резервные копии в S3", "Backups to S3"),
                        ("Восстановление по recovery-коду", "Recover with the recovery code")):
        assert f"tr('{ru}')" in pages, ru
        assert f'"{ru}": "{english}"' in en, english
        assert ru in READMES["README.ru.md"] and english in READMES["README.md"]


def test_cache_facts_in_the_readme_match_the_python_client():
    import inspect
    import sys
    sys.path.insert(0, os.path.join(ROOT, "clients", "python"))
    from aps_vault import Vault
    params = inspect.signature(Vault.__init__).parameters
    assert params["cache_ttl"].default == 300 and params["max_stale"].default == 86400
    assert "5 minutes" in READMES["README.md"] and "24 hours" in READMES["README.md"]
    assert "5 минут" in READMES["README.ru.md"] and "24 часов" in READMES["README.ru.md"]

#!/usr/bin/env python3
"""Select Sequel Ace connections in a terminal and export encrypted DBX JSON."""

import argparse
import base64
import curses
import getpass
import json
import os
import plistlib
import subprocess
import sys
import uuid
from pathlib import Path


FAVORITES = Path.home() / (
    "Library/Containers/com.sequel-ace.sequel-ace/Data/Library/"
    "Application Support/Sequel Ace/Data/Favorites.plist"
)

# Matches DBX's configCrypto.ts: PBKDF2-SHA256, 100,000 rounds, AES-256-GCM.
ENCRYPT_JS = r"""
const crypto = require('node:crypto');
let text = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => text += chunk);
process.stdin.on('end', () => {
  const { bundle, passphrase } = JSON.parse(text);
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.from(JSON.stringify(bundle), 'utf8');
  const encrypted = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
  const result = {
    format: 'dbx-encrypted', version: 1,
    salt: salt.toString('base64'), iv: iv.toString('base64'),
    data: encrypted.toString('base64')
  };
  // Catch accidental changes to the envelope before writing the file.
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(encrypted.subarray(encrypted.length - 16));
  const restored = Buffer.concat([
    decipher.update(encrypted.subarray(0, -16)), decipher.final()
  ]);
  if (!restored.equals(data)) throw new Error('Encryption round trip failed');
  process.stdout.write(JSON.stringify(result));
});
"""

# Sequel Ace's encrypted SPF uses AES-128-CBC without PKCS padding. The
# decrypted bytes contain an NSKeyedArchiver plist followed by padding and a
# four-byte big-endian plaintext length.
DECRYPT_SPF_JS = r"""
const crypto = require('node:crypto');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  const { data, password } = JSON.parse(input);
  const bytes = Buffer.from(data, 'base64');
  if (bytes.length < 32 || bytes.length % 16) throw new Error('Invalid SPF ciphertext');
  const key = crypto.createHash('sha1').update(password, 'utf8').digest().subarray(0, 16);
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, bytes.subarray(0, 16));
  decipher.setAutoPadding(false);
  const plain = Buffer.concat([decipher.update(bytes.subarray(16)), decipher.final()]);
  const size = plain.readUInt32BE(plain.length - 4);
  if (size > plain.length - 16) throw new Error('Wrong SPF password or corrupt file');
  process.stdout.write(plain.subarray(0, size).toString('base64'));
});
"""


def keychain_password(service, account):
    """Return None for an absent item. Abort if an existing item cannot be read."""
    result = subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w"],
        capture_output=True,
    )
    if result.returncode == 44:
        return None
    if result.returncode != 0:
        raise RuntimeError("Pęk kluczy: odmowa lub błąd odczytu hasła; eksport przerwany")
    password = result.stdout.decode("utf-8")
    return password[:-1] if password.endswith("\n") else password


def valid_port(value, default):
    port = int(value or default)
    if not 1 <= port <= 65535:
        raise ValueError("Nieprawidłowy port w ulubionym połączeniu")
    return port


def favorite_entries(root):
    entries = []

    def visit(node, group=""):
        if "Children" in node:
            next_group = f"{group}/{node.get('Name', '')}" if group else str(node.get("Name", ""))
            for child in node["Children"]:
                visit(child, next_group)
            return
        entries.append({
            "kind": "favorite", "key": str(node["id"]), "node": node,
            "name": str(node.get("name") or "(unnamed)"),
            "host": str(node.get("host") or ""), "group": group,
        })

    for child in root.get("Children", []):
        visit(child)
    return entries


def choose_connections(entries):
    """Curses list with selection and search; returns selected entry indices."""
    selected = set(range(len(entries)))

    def run(screen):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        query = ""
        searching = False
        cursor = 0
        offset = 0
        while True:
            height, width = screen.getmaxyx()
            visible = [i for i, entry in enumerate(entries) if query.casefold() in (
                f"{entry['name']} {entry['host']} {entry['group']} {entry['kind']}"
            ).casefold()]
            cursor = min(cursor, max(0, len(visible) - 1))
            rows = max(1, height - 5)
            offset = max(0, min(offset, max(0, len(visible) - rows)))
            if cursor < offset:
                offset = cursor
            if cursor >= offset + rows:
                offset = cursor - rows + 1
            screen.erase()
            if height < 7 or width < 35:
                screen.addnstr(0, 0, "Enlarge terminal (min. 35x7)", max(1, width - 1))
            else:
                screen.addnstr(0, 0, f"Sequel Ace -> DBX | {len(selected)}/{len(entries)} selected", width - 1, curses.A_BOLD)
                screen.addnstr(1, 0, "Up/Down move  Space toggle  A all  N none  / search  Enter export  Q quit", width - 1)
                for row, index in enumerate(visible[offset:offset + rows], start=3):
                    entry = entries[index]
                    mark = "x" if index in selected else " "
                    source = "Favorite" if entry["kind"] == "favorite" else "File"
                    label = f"[{mark}] {entry['name']}  |  {entry['host']}  |  {source} {entry['group']}"
                    style = curses.A_REVERSE if offset + row - 3 == cursor else curses.A_NORMAL
                    screen.addnstr(row, 0, label, width - 1, style)
                status = f"Search: {query}" if searching or query else f"Showing {len(visible)} connections"
                screen.addnstr(height - 1, 0, status, width - 1)
            screen.refresh()
            key = screen.get_wch()
            if searching:
                if key in ("\n", "\r", "\x1b"):
                    searching = False
                elif key in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                    query = query[:-1]
                    cursor = offset = 0
                elif isinstance(key, str) and key.isprintable():
                    query += key
                    cursor = offset = 0
                continue
            if key in (curses.KEY_UP, "k"):
                cursor = max(0, cursor - 1)
            elif key in (curses.KEY_DOWN, "j"):
                cursor = min(max(0, len(visible) - 1), cursor + 1)
            elif key == " " and visible:
                index = visible[cursor]
                selected.symmetric_difference_update({index})
            elif key in ("a", "A"):
                selected.update(visible)
            elif key in ("n", "N"):
                selected.difference_update(visible)
            elif key == "/":
                searching = True
            elif key in ("q", "Q", "\x1b"):
                return None
            elif key in ("\n", "\r", curses.KEY_ENTER):
                return selected.copy()

    return curses.wrapper(run)


def decode_archive(data):
    archive = plistlib.loads(data)
    objects = archive["$objects"]

    def value(item):
        if isinstance(item, plistlib.UID):
            return value(objects[item.data])
        if isinstance(item, dict):
            if "NS.keys" in item and "NS.objects" in item:
                return {value(k): value(v) for k, v in zip(item["NS.keys"], item["NS.objects"])}
            if "NS.string" in item:
                return item["NS.string"]
            if "NS.data" in item:
                return item["NS.data"]
            return {k: value(v) for k, v in item.items() if k != "$class"}
        if isinstance(item, list):
            return [value(v) for v in item]
        return item

    return value(archive["$top"]["data"])


def read_spf(path, session_password):
    spf = plistlib.loads(path.read_bytes())
    if spf.get("format") != "connection":
        raise ValueError(f"Niepoprawny plik połączenia: {path}")
    if spf.get("encrypted"):
        if session_password is None:
            session_password = getpass.getpass(f"Password for file {path.name}: ")
        payload = json.dumps({
            "data": base64.b64encode(spf["data"]).decode(),
            "password": session_password,
        }).encode()
        result = subprocess.run(["node", "-e", DECRYPT_SPF_JS], input=payload, capture_output=True)
        if result.returncode:
            raise ValueError(f"Błędne hasło albo uszkodzony plik: {path}")
        data = decode_archive(base64.b64decode(result.stdout))
    else:
        data = spf["data"]
    if not isinstance(data, dict) or not isinstance(data.get("connection"), dict):
        raise ValueError(f"Brak danych połączenia: {path}")
    return data["connection"]


def session_files(path):
    info = plistlib.loads((path / "info.plist").read_bytes())
    if info.get("format") != "connection bundle":
        raise ValueError(f"Niepoprawny plik sesji: {path}")
    for window in info.get("windows", []):
        for tab in window.get("tabs", []):
            file = Path(tab["path"]) if tab.get("isAbsolutePath") else path / "Contents" / tab["path"]
            if not file.is_file():
                raise FileNotFoundError(f"Brak połączenia sesji: {file}")
            yield file


def config_from_spf(connection, source):
    kind = connection.get("type")
    if kind not in ("SPTCPIPConnection", "SPSSHTunnelConnection"):
        raise ValueError(f"Nieobsługiwany typ połączenia {kind} w {source}")
    config = {
        "id": str(uuid.uuid4()),
        "name": str(connection.get("name") or source.stem),
        "db_type": "mysql",
        "host": str(connection.get("host") or ""),
        "port": valid_port(connection.get("port"), 3306),
        "username": str(connection.get("user") or ""),
        "password": str(connection.get("password") or ""),
        "database": str(connection.get("database") or "") or None,
        "save_password": True,
        "ssl": bool(connection.get("useSSL")),
    }
    for enabled, location, target in (
        ("sslCACertFileLocationEnabled", "sslCACertFileLocation", "ca_cert_path"),
        ("sslCertificateFileLocationEnabled", "sslCertificateFileLocation", "client_cert_path"),
        ("sslKeyFileLocationEnabled", "sslKeyFileLocation", "client_key_path"),
    ):
        if connection.get(enabled) and connection.get(location):
            config[target] = str(connection[location])
    if kind == "SPSSHTunnelConnection":
        key_path = str(connection.get("ssh_keyLocation") or "") if connection.get("ssh_keyLocationEnabled") else ""
        ssh_password = str(connection.get("ssh_password") or "")
        method = "key+password" if key_path and ssh_password else "key" if key_path else "password" if ssh_password else "agent"
        config["transport_layers"] = [{
            "type": "ssh", "host": str(connection.get("ssh_host") or ""),
            "port": valid_port(connection.get("ssh_port"), 22),
            "user": str(connection.get("ssh_user") or ""),
            "password": ssh_password, "key_path": key_path,
            "key_passphrase": "", "auth_method": method,
            "use_ssh_agent": method == "agent",
        }]
    return config


def build_bundle(root, read_password=keychain_password, selected_ids=None):
    connections = []
    groups = []
    order = []
    counts = {"db_passwords": 0, "ssh_passwords": 0, "key_passphrases": 0}

    def visit(node, target, is_root=False):
        children = node.get("Children")
        if children is not None:
            if is_root:
                destination = target
            else:
                group_id = str(uuid.uuid4())
                groups.append({
                    "id": group_id,
                    "name": node.get("Name") or "Grupa Sequel Ace",
                    "collapsed": not bool(node.get("IsExpanded", True)),
                })
                entry = {"type": "group", "id": group_id, "children": []}
                target.append(entry)
                destination = entry["children"]
            for child in children:
                visit(child, destination)
            if not is_root and not destination:
                target.pop()
                groups.pop()
            return

        if selected_ids is not None and str(node["id"]) not in selected_ids:
            return

        connection_type = int(node.get("type", 0))
        if connection_type not in (0, 2):
            raise ValueError(
                f"Nieobsługiwany typ połączenia Sequel Ace ({connection_type}) — "
                "eksport przerwany, aby nie zgubić ustawień"
            )
        name = str(node["name"])
        favorite_id = str(node["id"])  # plistlib preserves the full 64-bit value
        host = str(node.get("host") or "")
        user = str(node.get("user") or "")
        database = str(node.get("database") or "")
        db_password = read_password(
            f"Sequel Ace : {name} ({favorite_id})", f"{user}@{host}/{database}"
        )
        if db_password is not None:
            counts["db_passwords"] += 1
        connection_id = str(uuid.uuid4())
        config = {
            "id": connection_id,
            "name": name,
            "db_type": "mysql",
            "host": host,
            "port": valid_port(node.get("port"), 3306),
            "username": user,
            "password": db_password or "",
            "database": database or None,
            "save_password": True,
            "ssl": bool(node.get("useSSL")),
        }
        for enabled, source, destination in (
            ("sslCACertFileLocationEnabled", "sslCACertFileLocation", "ca_cert_path"),
            ("sslCertificateFileLocationEnabled", "sslCertificateFileLocation", "client_cert_path"),
            ("sslKeyFileLocationEnabled", "sslKeyFileLocation", "client_key_path"),
        ):
            if node.get(enabled) and node.get(source):
                config[destination] = str(node[source])

        if connection_type == 2:
            ssh_host = str(node.get("sshHost") or "")
            ssh_user = str(node.get("sshUser") or "")
            ssh_password = read_password(
                f"Sequel Ace SSHTunnel : {name} ({favorite_id})",
                f"{ssh_user}@{ssh_host}",
            )
            if ssh_password is not None:
                counts["ssh_passwords"] += 1
            key_path = str(node.get("sshKeyLocation") or "") if node.get("sshKeyLocationEnabled") else ""
            key_passphrase = read_password("SSH", key_path) if key_path else None
            if key_passphrase is not None:
                counts["key_passphrases"] += 1
            method = (
                "key+password" if key_path and ssh_password else
                "key" if key_path else "password" if ssh_password else "agent"
            )
            config["transport_layers"] = [{
                "type": "ssh",
                "host": ssh_host,
                "port": valid_port(node.get("sshPort"), 22),
                "user": ssh_user,
                "password": ssh_password or "",
                "key_path": key_path,
                "key_passphrase": key_passphrase or "",
                "auth_method": method,
                "use_ssh_agent": method == "agent",
            }]

        connections.append(config)
        target.append({"type": "connection", "id": connection_id})
    if root is not None:
        visit(root, order, is_root=True)
    return {"connections": connections, "layout": {"groups": groups, "order": order}}, counts


def add_file_connections(bundle, configs):
    existing = {
        (c["name"], c["host"], c["port"], c["username"], c.get("database")): c
        for c in bundle["connections"]
    }
    added = 0
    for config in configs:
        key = (config["name"], config["host"], config["port"], config["username"], config.get("database"))
        previous = existing.get(key)
        if previous is not None:
            if not previous["password"] and config["password"]:
                previous["password"] = config["password"]
            if previous.get("transport_layers") and config.get("transport_layers"):
                if not previous["transport_layers"][0]["password"]:
                    previous["transport_layers"][0]["password"] = config["transport_layers"][0]["password"]
            continue
        existing[key] = config
        bundle["connections"].append(config)
        bundle["layout"]["order"].append({"type": "connection", "id": config["id"]})
        added += 1
    return added


def encrypt_bundle(bundle, passphrase):
    data = json.dumps({"bundle": bundle, "passphrase": passphrase}, ensure_ascii=False).encode()
    result = subprocess.run(["node", "-e", ENCRYPT_JS], input=data, capture_output=True)
    if result.returncode:
        raise RuntimeError("Nie udało się zaszyfrować eksportu przy użyciu Node.js")
    envelope = json.loads(result.stdout)
    if envelope.get("format") != "dbx-encrypted" or envelope.get("version") != 1:
        raise RuntimeError("Niepoprawny format szyfrowanego eksportu")
    return json.dumps(envelope, indent=2).encode() + b"\n"


def main():
    if sys.platform != "darwin":
        raise RuntimeError("Skrypt działa na macOS")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, help="New encrypted DBX JSON file")
    parser.add_argument("--favorites", type=Path, default=FAVORITES, help="Sequel Ace Favorites.plist path")
    parser.add_argument("--session", type=Path, action="append", default=[], help="Sequel Ace .spfs session (repeatable)")
    parser.add_argument("--spf", type=Path, action="append", default=[], help="Sequel Ace .spf connection (repeatable)")
    args = parser.parse_args()
    favorites = args.favorites.expanduser().resolve()
    if not favorites.is_file() and not args.session and not args.spf:
        raise FileNotFoundError("No Favorites.plist found; provide a session or connection file")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("Run this tool in an interactive terminal")
    subprocess.run(["node", "--version"], check=True, capture_output=True)

    source = plistlib.loads(favorites.read_bytes())["Favorites Root"] if favorites.is_file() else None
    entries = favorite_entries(source) if source is not None else []
    for session in args.session:
        session = session.expanduser().resolve()
        info = plistlib.loads((session / "info.plist").read_bytes())
        session_password = getpass.getpass(f"Password for session {session.name}: ") if info.get("encrypted") else None
        for file in session_files(session):
            password = session_password if file.is_relative_to(session / "Contents") else None
            config = config_from_spf(read_spf(file, password), file)
            entries.append({"kind": "file", "config": config, "name": config["name"],
                            "host": config["host"], "group": session.name})
    for file in args.spf:
        file = file.expanduser().resolve()
        config = config_from_spf(read_spf(file, None), file)
        entries.append({"kind": "file", "config": config, "name": config["name"],
                        "host": config["host"], "group": file.name})
    if not entries:
        raise ValueError("No connections found")
    chosen = choose_connections(entries)
    if chosen is None:
        print("Cancelled.")
        return 0
    if not chosen:
        raise ValueError("No connections selected")
    selected_favorites = {entries[i]["key"] for i in chosen if entries[i]["kind"] == "favorite"}
    selected_files = [entries[i]["config"] for i in sorted(chosen) if entries[i]["kind"] == "file"]
    print(f"Selected {len(chosen)} connections; reading passwords for selected Favorites only.")

    if args.output is None:
        default = str(Path.home() / "Desktop" / "dbx-connections.json")
        output_text = input(f"Output file [{default}]: ").strip() or default
        output = Path(output_text).expanduser().resolve()
    else:
        output = args.output.expanduser().resolve()
    if output.exists():
        raise FileExistsError("Output file already exists; choose another path")
    if not output.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {output.parent}")
    passphrase = getpass.getpass("DBX export passphrase: ")
    if not passphrase:
        raise ValueError("Export passphrase cannot be empty")
    if passphrase != getpass.getpass("Confirm passphrase: "):
        raise ValueError("Passphrases do not match")

    files_by_identity = {
        (c["name"], c["host"], c["port"], c["username"], c.get("database")): c
        for c in selected_files
    }
    password_cache = {}
    for entry in entries:
        if entry["kind"] != "favorite" or entry["key"] not in selected_favorites:
            continue
        node = entry["node"]
        identity = (str(node["name"]), str(node.get("host") or ""),
                    valid_port(node.get("port"), 3306), str(node.get("user") or ""),
                    str(node.get("database") or "") or None)
        match = files_by_identity.get(identity)
        if match is None:
            continue
        service = f"Sequel Ace : {node['name']} ({node['id']})"
        account = f"{node.get('user') or ''}@{node.get('host') or ''}/{node.get('database') or ''}"
        if match["password"]:
            password_cache[(service, account)] = match["password"]
        layer = (match.get("transport_layers") or [None])[0]
        if layer and layer["password"]:
            service = f"Sequel Ace SSHTunnel : {node['name']} ({node['id']})"
            account = f"{node.get('sshUser') or ''}@{node.get('sshHost') or ''}"
            password_cache[(service, account)] = layer["password"]

    def selected_password(service, account):
        return password_cache.get((service, account)) or keychain_password(service, account)

    bundle, _ = build_bundle(source, read_password=selected_password, selected_ids=selected_favorites)
    added = add_file_connections(bundle, selected_files)
    if not bundle["connections"]:
        raise ValueError("No connections selected after deduplication")
    encrypted = encrypt_bundle(bundle, passphrase)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(encrypted)
            target.flush()
            os.fsync(target.fileno())
    except Exception:
        output.unlink(missing_ok=True)
        raise
    print(f"Saved: {output}")
    connections = bundle["connections"]
    layers = [layer for config in connections for layer in config.get("transport_layers", []) if layer.get("type") == "ssh"]
    print(
        f"Connections: {len(connections)} ({added} from files), "
        f"database passwords included: {sum(bool(c['password']) for c in connections)}, "
        f"SSH passwords included: {sum(bool(layer.get('password')) for layer in layers)}, "
        f"SSH key passphrases: {sum(bool(layer.get('key_passphrase')) for layer in layers)}"
    )
    print("In DBX, choose Import above the connection list and select this file.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

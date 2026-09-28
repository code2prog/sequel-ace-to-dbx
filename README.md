# Sequel Ace to DBX

A small terminal tool for choosing Sequel Ace connections and exporting them to a password-protected file that DBX can import.

The tool reads saved Favorites, including connections that are currently disconnected. You can also provide Sequel Ace `.spfs` sessions and `.spf` connection files. A session contains the connected windows and tabs that Sequel Ace saved when you chose **File → Save Session**.

## Requirements

- macOS with Sequel Ace installed
- Python 3.9 or newer
- Node.js 18 or newer (used for encryption and encrypted `.spf` files)
- DBX with configuration import support

No Python packages need to be installed.

## Install and run

```bash
git clone https://github.com/code2prog/sequel-ace-to-dbx.git
cd sequel-ace-to-dbx
python3 sequel_ace_to_dbx.py
```

The terminal screen starts with all discovered connections selected. Use **↑/↓** (or **j/k**) to move, **Space** to toggle, **/** to search, **A** to select all visible items, **N** to clear visible items, **Enter** to export, and **Q** to quit. Search matches the connection name, host, source, and Favorites group. Selection changes made while searching remain in place when you clear the search.

After you press Enter, choose the output path and enter a passphrase twice. The output is encrypted DBX JSON and is created with owner-only permissions. In DBX, choose **Import** above the connection list and select the JSON file. Enter the same passphrase.

You can set the output path on the command line:

```bash
python3 sequel_ace_to_dbx.py ~/Desktop/dbx-connections.json
```

An existing output file is never overwritten.

## Include open connections outside Favorites

In Sequel Ace, choose **File → Save Session**. Enable **Include passwords** and **Encrypt with password**, then save a `.spfs` file. Pass it to the tool:

```bash
python3 sequel_ace_to_dbx.py ~/Desktop/dbx-connections.json --session "/path/to/My Session.spfs"
```

You can repeat `--session` and `--spf` to include several files. The tool asks for the session's encryption password once and lists each connection for selection. If a selected session connection matches a selected Favorite and contains its database or SSH password, the tool reuses that password instead of asking Keychain for it. The tool merges duplicate connections with the same name, host, port, user, and database.

Sequel Ace only saves **currently connected** windows and tabs in a session. A disconnected connection is available to this tool if it was saved as a Favorite or an `.spf` file. An unsaved, disconnected connection cannot be recovered from Sequel Ace's files.

## Keychain and security

Passwords for selected Favorites are read from the macOS Keychain. macOS may ask for access separately for each Keychain item; unlocking the Keychain once does not grant another program access to every saved password. The selection screen itself does not read any Favorite passwords. Sequel Ace session files with **Include passwords** can reduce Keychain prompts for matching connections.

The tool never writes a plaintext password export. It reads passwords into process memory, encrypts the DBX file with PBKDF2-SHA256 and AES-256-GCM, and writes the file with mode `0600`. Keep the passphrase safe, and do not commit exported files to Git.

The current converter supports Sequel Ace TCP/IP and SSH tunnel MySQL connections. If a selected connection uses an unsupported type, the export stops with an error instead of silently dropping it. Socket, AWS IAM, and Vault connection settings are not converted.

## Options

```text
python3 sequel_ace_to_dbx.py [output.json] [--favorites Favorites.plist]
                             [--session session.spfs] [--spf connection.spf]
```

Run `python3 sequel_ace_to_dbx.py --help` for details.

## Development

```bash
python3 -m unittest discover -s tests
```

## License

MIT. See [LICENSE](LICENSE).

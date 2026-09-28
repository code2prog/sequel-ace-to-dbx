# Sequel Ace to DBX

Choose Sequel Ace connections in a terminal and save them, with their passwords, as an encrypted file for DBX. **The tool creates an import file; it does not add connections to DBX by itself.** No DBX plugin is required.

It reads saved Sequel Ace Favorites, including disconnected connections. You can also add saved `.spfs` sessions and `.spf` connection files. This transfers connection settings, not the contents of your databases.

## Requirements

- macOS with Sequel Ace connection data; Sequel Ace does not need to be running
- Python 3.9 or newer
- Node.js 18 or newer
- DBX with configuration import support

No Python packages need to be installed.

## Quick start

### 1. Run the exporter

```bash
git clone https://github.com/code2prog/sequel-ace-to-dbx.git
cd sequel-ace-to-dbx
python3 sequel_ace_to_dbx.py
```

The tool automatically lists Favorites saved for the current macOS user. All discovered connections start selected. Change the selection as needed, then press **Enter**. Choose an output path and enter an export passphrase twice. The suggested path is `~/Desktop/dbx-connections.json`.

You can provide the output path when starting the tool:

```bash
python3 sequel_ace_to_dbx.py ~/Desktop/dbx-connections.json
```

The file is encrypted and never overwrites an existing file. Keep the passphrase: DBX will ask for it during import.

### 2. Import the file into DBX

1. Open DBX and click **Import** in the connection sidebar header.
2. Choose the JSON file created by the exporter, for example `~/Desktop/dbx-connections.json`.
3. Enter the **export passphrase**. DBX decrypts the file and shows a preview before saving connections.
4. Select the connections to import and complete the import. DBX selects all of them by default. If offered, choose whether to apply their sidebar groups and ordering.
5. Check the imported connections in the DBX sidebar and try connecting to one.

DBX may skip a connection that already exists with the same name, host, and port. See [DBX's configuration import documentation](https://github.com/t8y2/dbx/blob/main/docs/content/docs/config-export.mdx) for its import behavior.

## Selecting connections

| Key | Action |
| --- | --- |
| **↑ / ↓** or **j / k** | Move through the list |
| **Space** | Select or deselect the highlighted connection |
| **/** | Search by name, host, source, or Favorites group |
| **A / N** | Select all or clear all visible connections |
| **Enter** | Continue to export |
| **Q** | Quit without exporting |

Search filters the visible list; selections made while searching remain when you clear the search. Favorite passwords are read from Keychain **after** you finish selecting connections.

## Where connections come from

By default, the tool reads this fixed path for the current macOS user:

```text
~/Library/Containers/com.sequel-ace.sequel-ace/Data/Library/Application Support/Sequel Ace/Data/Favorites.plist
```

It does not detect the Sequel Ace application or search the disk for connection files. To use a Favorites file in another location:

```bash
python3 sequel_ace_to_dbx.py --favorites "/path/to/Favorites.plist"
```

If the default file is missing and you provide no other source, the tool exits with an error.

### Include open connections outside Favorites

In Sequel Ace, choose **File → Save Session**, enable **Include passwords** and **Encrypt with password**, and save a `.spfs` file. Then run:

```bash
python3 sequel_ace_to_dbx.py ~/Desktop/dbx-connections.json --session "/path/to/My Session.spfs"
```

Use `--spf "/path/to/Connection.spf"` for an individual saved connection. You can repeat `--session` and `--spf` to include several files; the tool does not discover them automatically. For an encrypted session, it asks for the session password once before showing the selection screen.

Sequel Ace saves only **currently connected** windows and tabs in a session. Disconnected connections are available if saved as Favorites or `.spf` files. An unsaved, disconnected connection cannot be recovered from Sequel Ace's files.

If a selected session connection matches a selected Favorite and contains its database or SSH password, the tool reuses that password instead of asking Keychain for it. Duplicate entries with the same name, host, port, user, and database are merged in the export file.

## Passwords and limitations

- macOS may ask for Keychain access separately for each selected Favorite password. Unlocking Keychain once does not grant this tool access to every item.
- The export file is encrypted with PBKDF2-SHA256 and AES-256-GCM and written with owner-only permissions (`0600`). The tool does not write a plaintext password export. Do not commit exported files to Git.
- TCP/IP and SSH tunnel MySQL connections are supported. If you select an unsupported connection type, the export stops with an error rather than silently omitting it. Socket, AWS IAM, and Vault connection settings are not converted.
- Saved SQL queries, database schema, and database contents are not exported.

## Command-line options

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

import base64
import json
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path

import sequel_ace_to_dbx as exporter


def archive_connection(connection):
    objects = ["$null", None, "connection", None, {"$classname": "NSDictionary", "$classes": ["NSDictionary", "NSObject"]}]
    keys = []
    values = []
    for key, value in connection.items():
        keys.append(plistlib.UID(len(objects)))
        objects.append(key)
        values.append(plistlib.UID(len(objects)))
        objects.append(value)
    objects[1] = {"NS.keys": [plistlib.UID(2)], "NS.objects": [plistlib.UID(3)], "$class": plistlib.UID(4)}
    objects[3] = {"NS.keys": keys, "NS.objects": values, "$class": plistlib.UID(4)}
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000,
                           "$top": {"data": plistlib.UID(1)}, "$objects": objects},
                          fmt=plistlib.FMT_BINARY)


class ExporterTests(unittest.TestCase):
    def test_only_selected_favorite_reads_its_password(self):
        first = {"id": 1, "name": "One", "host": "one.test", "user": "alice", "type": 0}
        second = {"id": 2, "name": "Two", "host": "two.test", "user": "bob", "type": 0}
        root = {"Children": [{"Name": "Group", "Children": [first, second]}]}
        calls = []

        def password(service, account):
            calls.append((service, account))
            return "dummy-password"

        bundle, _ = exporter.build_bundle(root, read_password=password, selected_ids={"2"})
        self.assertEqual([c["name"] for c in bundle["connections"]], ["Two"])
        self.assertEqual(calls, [("Sequel Ace : Two (2)", "bob@two.test/")])
        self.assertEqual(len(bundle["layout"]["groups"]), 1)

    def test_encrypted_spf_and_dbx_export(self):
        connection = {"type": "SPTCPIPConnection", "name": "Demo", "host": "db.test",
                      "user": "alice", "port": 3306, "password": "dummy-password"}
        archive = archive_connection(connection)
        encrypt = """const c=require('node:crypto'); let s='';process.stdin.on('data',x=>s+=x);
process.stdin.on('end',()=>{const data=Buffer.from(s,'base64');const size=data.length+32-(data.length%16);
const raw=Buffer.alloc(size);data.copy(raw);raw.writeUInt32BE(data.length,size-4);const iv=Buffer.alloc(16,7);
const key=c.createHash('sha1').update('dummy-passphrase').digest().subarray(0,16);
const cipher=c.createCipheriv('aes-128-cbc',key,iv);cipher.setAutoPadding(false);
process.stdout.write(Buffer.concat([iv,cipher.update(raw),cipher.final()]));});"""
        encrypted = subprocess.run(["node", "-e", encrypt], input=base64.b64encode(archive),
                                   capture_output=True, check=True).stdout
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "demo.spf"
            path.write_bytes(plistlib.dumps({"format": "connection", "encrypted": True, "data": encrypted}))
            parsed = exporter.read_spf(path, "dummy-passphrase")
            self.assertEqual(parsed, connection)
            config = exporter.config_from_spf(parsed, path)
            bundle = {"connections": [], "layout": {"groups": [], "order": []}}
            self.assertEqual(exporter.add_file_connections(bundle, [config, config]), 1)
            envelope = json.loads(exporter.encrypt_bundle(bundle, "export-passphrase"))
            self.assertEqual(envelope["format"], "dbx-encrypted")
            self.assertEqual(envelope["version"], 1)
            self.assertNotIn("dummy-password", json.dumps(envelope))


if __name__ == "__main__":
    unittest.main()

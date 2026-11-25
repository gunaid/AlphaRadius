"""Cloned MACs: one MAC shared by many phones (often on different VLANs).

A hotspot MAC cookie lets a returning device log in automatically. With
cloned MACs that cookie logs other phones in with somebody else's card, or
makes sessions flap. For MACs listed in wisp_cloned_macs, RADIUS keeps the
package's own hotspot user profile but switches it to its copy named
``<profile>-nocookie`` (add-mac-cookie=no), created on each router by
services.cloned_mac_service. The copy is used only when that service has
confirmed it exists on the same router (wisp_cloned_mac_profiles), so a
router never receives a profile it does not have. Works on RouterOS 6 and 7.
"""

PROFILE_SUFFIX = '-nocookie'

# Known cloned MACs supplied by the operator, inserted once (source 'preset').
# A settings flag records the seed, so a MAC deleted later is never re-added.
SEED_FLAG = 'cloned_mac_seed_20261125'
SEED_MACS = (
    '9C:B2:B2:E1:31:64',
    'D0:D7:83:3D:49:99',
    '34:79:16:78:6D:A4',
    'A0:4F:85:FB:FF:F6',
    '00:00:11:CF:D5:71',
    '00:90:4C:C5:12:38',
    'A0:C9:A0:98:CA:81',
    'D8:31:CF:78:B2:BD',
    '1C:99:4C:C3:A4:0E',
    '00:05:49:38:3A:0B',
    'F0:08:F1:69:FF:46',
    '00:03:7F:04:02:12',
    '44:6D:57:D0:24:AA',
    'FC:42:03:DD:A5:AC',
    'A0:91:69:F5:C2:70',
    'D8:90:E8:10:98:09',
    '90:06:28:E2:44:51',
    '80:5A:04:A4:F9:3C',
    'D0:5B:A8:DA:3D:A8',
    '38:AA:3C:10:C6:79',
    '00:90:4C:C5:12:77',
    'A0:91:69:C2:CF:4B',
    'A0:91:69:F7:45:18',
    'FC:C7:34:20:F9:A4',
    'E0:19:1D:1F:B3:FF',
    'FC:2D:5E:9B:85:20',
    '50:F5:20:5F:50:8F',
    '2C:FD:AB:0E:14:4E',
    '00:AE:FA:5A:64:BF',
    '98:F1:70:12:AE:B4',
    '4C:66:41:0F:29:D3',
    'B0:C1:9E:AD:4D:67',
    'FC:2D:5E:23:7B:21',
    'D0:5B:A8:A8:6D:6E',
    'B0:C1:9E:29:9C:4A',
    '14:F4:2A:C9:E8:BB',
    '10:A5:D0:47:69:ED',
    'BC:3F:4E:1A:D8:1C',
    'B8:D7:AF:69:4C:A5',
    '84:10:0D:B4:35:EE',
    '08:D4:6A:F2:33:7E',
    'B8:B4:2E:B0:EB:98',
    'A0:8D:16:DB:41:2F',
    'B0:C1:9E:2F:0A:99',
    '98:00:C6:7C:39:31',
    'B0:C1:9E:B8:4C:A5',
    'F8:4E:73:35:AE:AF',
    'C8:FE:30:FF:C3:E5',
    'B4:79:A7:15:84:E0',
)

MACS_SQL = """CREATE TABLE IF NOT EXISTS wisp_cloned_macs (
 mac VARCHAR(17) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL PRIMARY KEY,
 note VARCHAR(250) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 source VARCHAR(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'manual',
 created_by VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 created_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""

PROFILES_SQL = """CREATE TABLE IF NOT EXISTS wisp_cloned_mac_profiles (
 nasipaddress VARCHAR(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 profile VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 synced_at DATETIME NOT NULL,
 PRIMARY KEY (nasipaddress, profile)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""

FUNCTION_SQL = f"""CREATE FUNCTION fn_cloned_mac_profile(
 p_station VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 p_nasip VARCHAR(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 p_group VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci)
 RETURNS VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci READS SQL DATA
BEGIN
 DECLARE target VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
 IF p_station IS NULL OR p_station='' THEN RETURN ''; END IF;
 IF COALESCE((SELECT s.`value` FROM wisp_system_settings s WHERE s.`key`='cloned_mac_enabled' LIMIT 1),'0')<>'1'
 THEN RETURN ''; END IF;
 IF NOT EXISTS(SELECT 1 FROM wisp_cloned_macs c WHERE c.mac=UPPER(REPLACE(p_station,'-',':')))
 THEN RETURN ''; END IF;
 SET target=CONCAT(COALESCE(NULLIF(p_group,''),'default'),'{PROFILE_SUFFIX}');
 IF EXISTS(SELECT 1 FROM wisp_cloned_mac_profiles p WHERE p.nasipaddress=p_nasip AND p.profile=target)
 THEN RETURN target; END IF;
 RETURN '';
END"""


def install_cloned_mac_schema(cur, maria=True):
    from database.schema_objects import ensure_schema_object
    cur.execute(MACS_SQL)
    cur.execute(PROFILES_SQL)
    seed_cloned_macs(cur)
    return ensure_schema_object(cur, FUNCTION_SQL, maria=maria)


def seed_cloned_macs(cur):
    """Insert SEED_MACS once; returns how many were added."""
    cur.execute("SELECT `key` FROM wisp_system_settings WHERE `key`=%s", (SEED_FLAG,))
    if cur.fetchone():
        return 0
    added = 0
    for mac in SEED_MACS:
        cur.execute("""INSERT IGNORE INTO wisp_cloned_macs(mac,note,source,created_by,created_at)
                       VALUES (%s,'قائمة مبدئية','preset','system',NOW())""", (mac,))
        added += cur.rowcount
    cur.execute("INSERT INTO wisp_system_settings(`key`,`value`,`description`) VALUES (%s,%s,%s)",
                (SEED_FLAG, str(added), 'تم إدخال القائمة المبدئية للماكات المستنسخة'))
    return added

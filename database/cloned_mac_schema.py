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
    return ensure_schema_object(cur, FUNCTION_SQL, maria=maria)

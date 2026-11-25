"""Speed and options chosen in the hotspot "domain" (user@512k/2M|yes).

Hotspot login pages may append choices to the card as a domain, separated by
``|`` or ``_``: a speed ``<upload>/<download>`` in RouterOS rate-limit order
(e.g. ``512k/2M``) and ``yes`` = block app/system updates for this device.
The router sends it either inside User-Name (``user@domain``,
split-user-domain=no) or as Mikrotik-Realm.

fn_realm_policy(domain) validates the whole domain and returns
``'<rate>;<address-list>'`` for a valid domain (either part may be empty) or
'' for anything else. Only a valid domain makes FreeRADIUS strip it from
User-Name (docker/freeradius/alpha-realm-policy.conf), so cards and
accounting always use the bare card name, while ordinary usernames
containing '@' are untouched. Validation does not depend on the feature
switch; only the returned effects do.

The rate applies only when the card's package has no speed (open speed);
a package speed always wins. ``yes`` adds Mikrotik-Address-List with the
configured list name (default ``block-updates``); the router's firewall
rules for that list do the blocking.
"""

DEFAULT_BLOCK_LIST = 'block-updates'

CHOICES_SQL = """CREATE TABLE IF NOT EXISTS wisp_realm_choices (
 username VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL PRIMARY KEY,
 nasipaddress VARCHAR(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 callingstationid VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 realm VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 rate VARCHAR(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 block_updates TINYINT NOT NULL DEFAULT 0,
 updated_at DATETIME NOT NULL,
 KEY idx_realm_choices_time (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""

# rlm_sql escapes '|' as '=7C' (verified with FreeRADIUS 3.2 + rlm_sql_mysql);
# '_' and '/' pass unchanged.
POLICY_SQL = r"""CREATE FUNCTION fn_realm_policy(p_realm VARCHAR(253) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci)
 RETURNS VARCHAR(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci READS SQL DATA
BEGIN
 DECLARE s VARCHAR(253) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
 DECLARE token VARCHAR(253) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
 DECLARE rate VARCHAR(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT '';
 DECLARE block INT DEFAULT 0;
 DECLARE n INT DEFAULT 0;
 DECLARE list_name VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
 IF p_realm IS NULL THEN RETURN ''; END IF;
 SET s=TRIM(REPLACE(REPLACE(REPLACE(p_realm,'=7C','|'),'=7c','|'),'_','|'));
 IF s='' OR CHAR_LENGTH(s)>64 THEN RETURN ''; END IF;
 WHILE s<>'' DO
  SET n=n+1;
  IF n>4 THEN RETURN ''; END IF;
  SET token=SUBSTRING_INDEX(s,'|',1);
  SET s=IF(LOCATE('|',s)>0,SUBSTRING(s,LOCATE('|',s)+1),'');
  IF rate='' AND token REGEXP '^[0-9]{1,6}(\\.[0-9]{1,3})?[kKmMgG]?/[0-9]{1,6}(\\.[0-9]{1,3})?[kKmMgG]?$' THEN
   SET rate=REPLACE(REPLACE(REPLACE(token,'K','k'),'m','M'),'g','G');
  ELSEIF LOWER(token)='yes' THEN SET block=1;
  ELSEIF LOWER(token)='no' THEN SET block=0;
  ELSE RETURN '';
  END IF;
 END WHILE;
 IF COALESCE((SELECT x.`value` FROM wisp_system_settings x WHERE x.`key`='realm_speed_enabled' LIMIT 1),'1')<>'1'
 THEN RETURN ';'; END IF;
 IF rate REGEXP '^0+(\\.0+)?[kMG]?/0+(\\.0+)?[kMG]?$' THEN SET rate=''; END IF;
 SET list_name=COALESCE(NULLIF(TRIM((SELECT x.`value` FROM wisp_system_settings x
   WHERE x.`key`='realm_block_list' LIMIT 1)),''),'""" + DEFAULT_BLOCK_LIST + r"""');
 RETURN CONCAT(rate,';',IF(block=1,list_name,''));
END"""

RECORD_SQL = """CREATE FUNCTION fn_record_realm_choice(
 p_user VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 p_nas VARCHAR(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 p_station VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 p_realm VARCHAR(253) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 p_policy VARCHAR(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci)
 RETURNS INT MODIFIES SQL DATA
BEGIN
 DECLARE EXIT HANDLER FOR SQLEXCEPTION RETURN 0;
 -- rlm_sql escapes ';' as '=3B' and '|' as '=7C' in expanded attributes.
 SET p_policy=REPLACE(REPLACE(COALESCE(p_policy,''),'=3B',';'),'=3b',';');
 INSERT INTO wisp_realm_choices(username,nasipaddress,callingstationid,realm,rate,block_updates,updated_at)
 VALUES(LEFT(p_user,64),LEFT(COALESCE(p_nas,''),45),LEFT(COALESCE(p_station,''),50),
  LEFT(REPLACE(REPLACE(COALESCE(p_realm,''),'=7C','|'),'=7c','|'),80),
  LEFT(SUBSTRING_INDEX(p_policy,';',1),40),IF(SUBSTRING_INDEX(p_policy,';',-1)<>'',1,0),NOW())
 ON DUPLICATE KEY UPDATE nasipaddress=VALUES(nasipaddress),callingstationid=VALUES(callingstationid),
  realm=VALUES(realm),rate=VALUES(rate),block_updates=VALUES(block_updates),updated_at=VALUES(updated_at);
 RETURN 1;
END"""


def install_realm_policy_schema(cur, maria=True):
    from database.schema_objects import ensure_schema_object
    cur.execute(CHOICES_SQL)
    changed = ensure_schema_object(cur, POLICY_SQL, maria=maria)
    return ensure_schema_object(cur, RECORD_SQL, maria=maria) or changed

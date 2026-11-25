"""Reject texts FreeRADIUS sends to the NAS, editable in settings (radius_msg_*).

fn_rmsg('quota') returns the saved setting, or the User Manager style default.
The authorize query must stay under FreeRADIUS's 8192-byte config string limit,
so the texts live in this function instead of inline sub-queries.
"""

DEFAULTS = (
    ('expired', 'no valid profile found'),
    ('recharged', 'no valid profile found'),
    ('quota', 'transfer limit reached'),
    ('uptime', 'uptime limit reached'),
    ('disabled', 'user is disabled'),
    ('invalid', 'invalid username or password'),
    ('simultaneous', 'simultaneous session limit reached'),
    ('roaming', 'simultaneous session limit reached, retry in one minute'),
    ('mac', 'MAC address is not allowed for this account'),
    ('capacity', 'Concurrent session capacity reached'),
    ('license', 'License verification unavailable or license invalid'),
    ('reconcile', 'Accounting cycle requires reconciliation'),
)

FUNCTION_SQL = '''CREATE FUNCTION fn_rmsg(p_kind VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci)
    RETURNS VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci READS SQL DATA
    BEGIN
      RETURN COALESCE((SELECT NULLIF(TRIM(s.`value`),'') FROM wisp_system_settings s
                       WHERE s.`key`=CONCAT('radius_msg_',p_kind) LIMIT 1),
        CASE p_kind ''' + ' '.join(f"WHEN '{k}' THEN '{v}'" for k, v in DEFAULTS) + ''' ELSE '' END);
    END'''


def install_radius_message_function(cur, maria=True):
    from database.schema_objects import ensure_schema_object
    return ensure_schema_object(cur, FUNCTION_SQL, maria=maria)

"""Random-MAC roaming: requests raised by RADIUS, outcomes kept for reports.

When an account is at its Simultaneous-Use limit and a login arrives from
another MAC, fn_reserve_license_slot rejects it (result 4) and upserts one
pending row per account here. services.roaming_service reads the old
session's live idle time from the router and disconnects it only if idle;
the device's next attempt then passes the normal limit. RADIUS never
admits a second seat on its own, and an accepted disconnect is not a Stop.
"""

REQUESTS_SQL = """CREATE TABLE IF NOT EXISTS wisp_roaming_requests (
 username VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL PRIMARY KEY,
 nasipaddress VARCHAR(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 callingstationid VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 nasportid VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 requested_at DATETIME NOT NULL,
 status VARCHAR(24) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'pending',
 processed_at DATETIME NULL,
 detail VARCHAR(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 attempts INT NOT NULL DEFAULT 0,
 KEY idx_roaming_pending (status, requested_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""

EVENTS_SQL = """CREATE TABLE IF NOT EXISTS wisp_roaming_events (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,
 username VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 nasipaddress VARCHAR(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 new_mac VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 old_mac VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 idle_seconds INT NULL,
 outcome VARCHAR(24) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 created_at DATETIME NOT NULL,
 KEY idx_roaming_events_time (created_at),
 KEY idx_roaming_events_user (username, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""


def install_roaming_schema(cur):
    cur.execute(REQUESTS_SQL)
    cur.execute(EVENTS_SQL)

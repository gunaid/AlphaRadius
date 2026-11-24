-- Default Initial Super Admin Credentials for ALPHA RADIUS on Ubuntu
-- Username: max
-- Password: max123

INSERT INTO `wisp_admins` (`id`, `username`, `password`, `full_name`, `email`, `role`, `is_active`)
VALUES (1, 'max', 'max123', 'المدير العام', 'admin@alpharadius.local', 'superadmin', 1)
ON DUPLICATE KEY UPDATE `username`='max', `password`='max123', `is_active`=1;

INSERT INTO `wisp_managers` (`id`, `username`, `password_hash`, `full_name`, `email`, `role_id`, `is_active`)
VALUES (1, 'max', 'max123', 'المدير العام', 'admin@alpharadius.local', 1, 1)
ON DUPLICATE KEY UPDATE `username`='max', `password_hash`='max123', `is_active`=1;

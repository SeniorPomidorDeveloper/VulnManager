INSERT INTO tenant (id, max_report_bytes)
VALUES ('local', 104857600)
ON CONFLICT (id) DO NOTHING;

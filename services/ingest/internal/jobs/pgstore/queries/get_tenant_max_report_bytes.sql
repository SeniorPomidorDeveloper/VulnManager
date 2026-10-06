-- name: GetTenantMaxReportBytes :one
SELECT max_report_bytes FROM tenant WHERE id = $1;

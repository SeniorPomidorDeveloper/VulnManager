-- name: SetTenant :exec
SELECT set_config('app.tenant_id', $1, true);

DO $$
DECLARE
    victims text;
BEGIN
    SELECT string_agg(format('%I.%I', schemaname, tablename), ', ')
    INTO victims
    FROM pg_tables
    WHERE schemaname = 'public'
      AND tablename NOT IN ('schema_version', 'tenant', 'product');
    EXECUTE 'TRUNCATE ' || victims || ' RESTART IDENTITY CASCADE';
END
$$;

import hashlib
import json
import typing
import uuid

import settings

SCAN_ID = 'scan-1'
COMPLETED = 'completed'
KIND = 'kind'
VULN = 'CVE-2024-{number:04d}'
PURL = 'pkg:npm/lib{number}@1.0.0'
TRIVY = 'trivy'
SEMGREP = 'semgrep'
INSERT_RUN = (
    'INSERT INTO import_run (tenant_id, scope_key, product_id, context_id, '
    'tool_name, scan_id, raw_key, raw_sha256, status) '
    'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id'
)
UPSERT_COMPONENT = (
    'INSERT INTO component (tenant_id, purl, type, namespace, name, version) '
    "VALUES (%s, %s, 'npm', '', %s, '1.0.0') "
    'ON CONFLICT (tenant_id, purl) DO UPDATE SET purl = EXCLUDED.purl '
    'RETURNING id'
)
INSERT_FINDING = (
    'INSERT INTO finding (tenant_id, import_run_id, scope_key, product_id, '
    'context_id, tool_finding_id, kind, title, description, severity_raw, '
    'raw, provenance, algo_version, detected_at, rule_id, vuln_source, '
    'vuln_id, location, component_id) '
    "VALUES (%s, %s, %s, %s, %s, %s, %s, 'title', 'description', 'HIGH', "
    "'{}', %s, 'seed@1', now(), %s, %s, %s, %s, %s)"
)


class Run(typing.NamedTuple):
    run_id: str
    scope: tuple
    tool: str


class Seeder:
    def __init__(self, cursor):
        self._cursor = cursor

    def run(self, scope, tool, status=COMPLETED):
        tenant, product, context = scope
        sha = uuid.uuid4().hex
        self._cursor.execute(INSERT_RUN, (
            tenant, scope_key(scope), product, context, tool, SCAN_ID,
            f'{tenant}/{SCAN_ID}/{sha}', sha, status,
        ))
        return Run(str(self._cursor.fetchone()[0]), scope, tool)

    def trivy_run(self, scope, count=settings.FINDINGS):
        run = self.run(scope, TRIVY)
        for number in range(count):
            self._finding(run, number, {
                KIND: 'sca',
                'vuln': ('cve', VULN.format(number=number)),
                'component': self._component(scope, number),
                'location': {'target': 'package-lock.json'},
            })
        return run

    def semgrep_run(self, scope, count=settings.FINDINGS):
        run = self.run(scope, SEMGREP)
        for number in range(count):
            self._finding(run, number, {
                KIND: 'sast',
                'rule': f'rules.js-{number}',
                'location': {
                    'uri': f'src/file{number}.js',
                    'start_line': 10 + number,
                    'snippet': f'eval(input{number})',
                },
            })
        return run

    def unknown_tool_run(self, scope, tool, count=settings.FINDINGS):
        run = self.run(scope, tool)
        for number in range(count):
            self._finding(run, number, {KIND: 'unknown'})
        return run

    def _component(self, scope, number):
        self._cursor.execute(
            UPSERT_COMPONENT,
            (scope[0], PURL.format(number=number), f'lib{number}'),
        )
        return self._cursor.fetchone()[0]

    def _finding(self, run, number, attributes):
        tenant, product, context = run.scope
        source, vuln_id = attributes.get('vuln', (None, None))
        self._cursor.execute(INSERT_FINDING, (
            tenant, run.run_id, scope_key(run.scope), product, context,
            f'{run.tool}-{number}', attributes[KIND],
            json.dumps({'tool': run.tool}),
            attributes.get('rule'), source, vuln_id,
            json.dumps(attributes.get('location', {})),
            attributes.get('component'),
        ))


def scope_key(scope):
    return hashlib.sha256('/'.join(scope).encode()).hexdigest()

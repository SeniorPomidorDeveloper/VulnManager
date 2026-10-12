import http

from jsonschema import Draft202012Validator

REPORTS_PATH = '/api/v1/reports'


def ref_name(node):
    return node['$ref'].rsplit('/', 1)[1]


def documented_response(openapi, status):
    operation = openapi['paths'][REPORTS_PATH]['post']
    response = operation['responses'].get(str(int(status)))
    assert response is not None, f'status {status} is not in the spec'
    reference = response.get('$ref')
    if reference is None:
        return response
    return openapi['components']['responses'][ref_name(response)]


def matches_spec(openapi, response, body):
    media_types = documented_response(
        openapi, http.HTTPStatus(response.status),
    )['content']
    assert response.content_type in media_types, (
        f'content type {response.content_type} is not in the spec'
    )
    schema = media_types[response.content_type]['schema']
    if schema.get('$ref') is not None:
        schema = openapi['components']['schemas'][ref_name(schema)]
    Draft202012Validator(schema).validate(body)

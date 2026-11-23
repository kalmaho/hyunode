"""Ollama transport pinned to loopback; no cloud fallback or tools."""
import http.client
import json
from pathlib import Path

SETTINGS = Path(__file__).resolve().parent / 'data' / 'ai_provider.json'


def selected():
    if not SETTINGS.exists():
        return None
    value = json.loads(SETTINGS.read_text(encoding='utf-8'))
    if value.get('provider') != 'ollama':
        raise ValueError('지원하지 않는 AI 제공업체 설정입니다.')
    model = value.get('model', '')
    if not model or 'cloud' in model.lower() or '/' in model:
        raise ValueError('로컬 모델 ID만 사용할 수 있습니다.')
    return model


def request(method, path, payload=None, timeout=3):
    conn = http.client.HTTPConnection('127.0.0.1', 11434, timeout=timeout)
    try:
        conn.request(method, path, body=json.dumps(payload).encode('utf-8') if payload is not None else None,
                     headers={'Content-Type': 'application/json'})
        response = conn.getresponse()
        raw = response.read(1_000_001)
        if response.status != 200:
            raise ValueError('로컬 AI 요청 실패 (HTTP {}). Ollama와 설치된 모델을 확인하세요.'.format(response.status))
        if len(raw) > 1_000_000:
            raise ValueError('로컬 AI 응답 크기 제한을 초과했습니다.')
        return json.loads(raw)
    except (OSError, http.client.HTTPException):
        raise ValueError('로컬 AI에 연결할 수 없거나 시간이 초과됐습니다. Ollama 실행 상태를 확인하세요. 외부 API는 호출하지 않았습니다.')
    finally:
        conn.close()


def check_model(model):
    value = request('POST', '/api/show', {'model': model})
    if value.get('remote_model') or value.get('remote_host'):
        raise ValueError('클라우드 모델은 내부 AI 모드에서 사용할 수 없습니다.')


def config(model):
    try:
        check_model(model)
        ready = True
    except ValueError:
        ready = False
    return {'provider': 'Ollama (local)', 'configured': ready, 'model': model,
            'source': 'local_ollama', 'private_access': 'loopback_only'}


def analyze(model, bundle, schema, instructions, validator):
    check_model(model)
    value = request('POST', '/api/chat', {'model': model, 'stream': False, 'think': False,
        'messages': [{'role': 'system', 'content': instructions + '\nKeep the review concise: at most 3 facts, 2 hypotheses, and 3 priorities. Mention all major limitations.'},
                     {'role': 'user', 'content': json.dumps(bundle, ensure_ascii=False)}],
        'format': schema, 'options': {'temperature': 0, 'num_ctx': 4096, 'num_predict': 1800}, 'keep_alive': 0}, timeout=300)
    if not value.get('done') or value.get('done_reason') == 'length':
        raise ValueError('로컬 모델 출력이 완료되지 않았습니다. 출력 제한 또는 모델 크기를 조정하세요.')
    try:
        review = validator(json.loads(value['message']['content']), bundle)
    except (ValueError, KeyError, TypeError):
        raise ValueError('로컬 모델의 JSON 구조 또는 근거 인용 검증에 실패했습니다. 자동으로 재시도하지 않았습니다.')
    incoming, outgoing = value.get('prompt_eval_count', 0), value.get('eval_count', 0)
    return {'analysis': review, 'provider': 'Ollama (local)', 'model': model,
            'usage': {'input_tokens': incoming, 'output_tokens': outgoing, 'total_tokens': incoming + outgoing}}

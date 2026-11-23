"""Select an installed local model; never reads or removes OpenAI credentials."""
import argparse
import json
import local_ai


def main():
    parser = argparse.ArgumentParser(description='Hyunode를 로컬 Ollama 모델로 전환합니다.')
    parser.add_argument('--model', default='qwen3.5:0.8b')
    args = parser.parse_args()
    if 'cloud' in args.model.lower() or '/' in args.model:
        parser.error('클라우드 모델은 지원하지 않습니다.')
    try:
        local_ai.check_model(args.model)
        local_ai.SETTINGS.parent.mkdir(exist_ok=True)
        temp = local_ai.SETTINGS.with_suffix('.tmp')
        temp.write_text(json.dumps({'provider': 'ollama', 'model': args.model}), encoding='utf-8')
        temp.replace(local_ai.SETTINGS)
        print('로컬 AI 설정 완료: ' + args.model)
        print('OpenAI API 호출과 자동 폴백은 사용하지 않습니다. 대시보드를 새로고침하세요.')
    except ValueError as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()

"""Run interactively; do not pass API keys on the command line."""
import argparse
import getpass
import sys
import warnings
import credentials


def main():
    parser = argparse.ArgumentParser(description='Hyunode API 설정을 Windows 자격 증명 관리자에 보관합니다.')
    parser.add_argument('--delete', action='store_true', help='Hyunode의 저장된 API 키와 모델 설정 삭제')
    args = parser.parse_args()
    try:
        if args.delete:
            credentials.delete()
            print('저장된 Hyunode API 설정을 삭제했습니다. 환경변수 설정은 별개입니다.')
            return
        if not sys.stdin.isatty():
            raise ValueError('키 노출 방지를 위해 대화형 터미널에서 실행하세요.')
        print('키는 화면에 표시하지 않습니다. Windows 사용자 계정에 저장합니다.')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            key = getpass.getpass('OpenAI API key: ')
        model = input('GPT API 모델 ID: ').strip()
        credentials.save(key, model)
        print('저장했습니다. 이후 같은 Windows 계정에서 python server.py만 실행하면 됩니다.')
        print('OPENAI_API_KEY / OPENAI_MODEL 환경변수가 남아 있으면 환경변수가 우선합니다.')
    except (OSError, ValueError, getpass.GetPassWarning) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print('\n설정을 취소했습니다.', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

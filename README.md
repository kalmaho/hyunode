# Hyunode

내부 실습 환경을 위한 웹 보안 진단 워크스페이스. 대상 등록 → 제한된 포트 검사 → HTTP 보안 설정 관찰 → Nuclei 결과 수집 → 근거 검토 → Markdown 보고서 다운로드를 지원합니다.

## 실행

Python 3.8 이상이 필요합니다. 기본 기능은 외부 패키지 없이 실행됩니다.

```sh
python server.py
```

브라우저에서 http://127.0.0.1:8787 에 접속합니다. 별도 터미널에서 샘플 실습 서버를 실행하세요.

```sh
python lab/server.py
```

대시보드에서 `http://127.0.0.1:8080`을 등록하고 **검사 실행**을 누릅니다. 샘플 서버는 보안 헤더가 의도적으로 빠져 있으며, 합성 데이터만 제공합니다. 로그인·SQLi 등 모의해킹 실습 기능은 아직 포함하지 않습니다.

## 현재 구현

- 대시보드, 진단 대상, 발견 사항 검색·심각도 필터, 결과 근거 모달
- SQLite 기반 대상·검사 이력 저장 (`data/`, Git 제외)
- 허용된 포트 TCP 연결 확인: 열림 / 닫힘 또는 필터링
- HTTP 응답의 CSP, X-Content-Type-Options, HTTPS의 HSTS 존재 여부 관찰
- 로컬 Nuclei 실행 파일과 승인 템플릿이 있는 경우 제한된 검사 실행
- 검사별 Markdown 보고서 다운로드, 실제 엔진 실행 상태 표시
- 반응형 레이아웃, 키보드 포커스, 한국어 UI

GPT 근거 분석을 지원합니다. 외부 ASM, 소유권 인증, 수동 검토 상태 편집, 수정 전후 자동 비교는 아직 구현하지 않았습니다. AI는 추가 검사 요청을 실행하지 않으며 취약점 확정 기능이 아닙니다. 서버가 종료되면 진행 중이던 검사는 다음 실행 시 중단됨으로 표시됩니다. 실행 시간은 UTC로 저장하고 화면에서는 브라우저 시간대로 표시합니다.

## 검사 범위 설정

기본 허용 IP는 `127.0.0.1`, 포트는 `3000,8000,8080,8443`입니다. 실습용 내부 IP만 명시적으로 추가하세요. 도메인, 메타데이터 주소, 공개 IP, URL 경로·인증정보는 허용하지 않으며 리다이렉트를 따라가지 않습니다.

PowerShell:

```powershell
$env:HYUNODE_ALLOWED_IPS = '127.0.0.1,192.168.56.10'
$env:HYUNODE_ALLOWED_PORTS = '3000,8000,8080,8443'
python server.py
```

Linux:

```sh
HYUNODE_ALLOWED_IPS=127.0.0.1,192.168.56.10 HYUNODE_ALLOWED_PORTS=3000,8000,8080,8443 python server.py
```

원격 서버에서는 SSH 로컬 포워딩으로 접속하세요: `ssh -L 8787:127.0.0.1:8787 user@server`. 대시보드는 127.0.0.1에만 바인딩합니다. 단일 사용자용 개발 버전으로 사용자 인증·TLS·다중 사용자 격리가 없으므로 공개 리버스 프록시로 노출하지 마세요. 변경 API는 런타임 토큰을 요구하고 Host를 검증합니다.

## 관리자 전용 GPT 심층 분석

OpenAI Responses API를 서버에서만 호출합니다. 이 채팅의 로그인이나 모델 연결을 재사용하지 않습니다. 본인의 OpenAI API 키와 API 계정에서 사용할 수 있는 Structured Outputs 지원 GPT 모델 ID가 필요합니다. 모델을 임의로 고정하지 않으며 `OPENAI_MODEL`로 명시해야 합니다.

PowerShell에서 키를 화면이나 명령 기록에 직접 적지 않고 입력하려면:

```powershell
$hyunodeKey = Read-Host 'OpenAI API key' -AsSecureString
$env:OPENAI_API_KEY = [System.Net.NetworkCredential]::new('', $hyunodeKey).Password
$env:OPENAI_MODEL = Read-Host '사용할 GPT API 모델 ID'
python server.py
```

Linux:

```bash
read -rsp 'OpenAI API key: ' OPENAI_API_KEY; echo
export OPENAI_API_KEY
read -rp 'GPT API 모델 ID: ' OPENAI_MODEL
export OPENAI_MODEL
python server.py
```

이미 실행 중인 서버는 종료한 뒤 환경변수가 설정된 터미널에서 다시 시작합니다. API 키는 브라우저·SQLite·GitHub에 저장하지 않습니다. SSH 터널을 통해서만 원격 접속하고 서버의 SSH 계정 접근도 본인으로 제한하세요. 루프백 제한은 같은 컴퓨터의 다른 OS 사용자까지 식별하는 로그인 시스템은 아닙니다.

1. 대상을 검사합니다. 새 검사는 루트 응답을 최대 64 KiB만 읽어 구조 정보로 변환합니다.
2. **GPT 심층 분석 → 전송 근거 확인**에서 실제 전송할 JSON을 확인합니다.
3. 전송에 동의하고 분석을 실행합니다. 근거가 바뀌면 다시 확인해야 합니다.
4. 관찰된 사실, 근거 ID, 가설의 전제조건·예상 영향·오탐 가능성·수동 확인 절차·개선안·범위 한계를 확인합니다.
5. 별도의 AI 보고서를 다운로드합니다. 관찰 결과와 AI 추정은 합쳐서 확정하지 않습니다.

전송되는 데이터는 허용 포트의 연결 결과, HTTP 상태, 일부 헤더의 **존재 여부**, 쿠키의 **보안 속성 여부**, 폼·비밀번호 필드·업로드 필드·스크립트·링크의 **개수**, Nuclei 심각도별 매치 개수입니다. 대상 이름·IP·URL, HTML 원문·입력값, 쿠키 값, 응답 헤더 원문, Nuclei 텍스트, 오류 원문은 보내지 않습니다. 기존 검사에는 구조 정보가 없어 재검사하면 더 많은 근거가 생깁니다. 단일 비인증 페이지의 구조만으로 SQLi·XSS·인가 취약점을 확인할 수는 없습니다.

OpenAI 요청은 `store: false`, 출력 최대 6,000토큰, 60초 연결 타임아웃으로 설정합니다. `store: false`는 무보관 전체 보장을 의미하지 않습니다. 별도 API 요금과 제공업체 데이터 정책을 확인하세요. 동시 AI 분석 1개·UTC 기준 하루 최대 20회(실패 시도 포함)로 제한하고 자동 재시도하지 않습니다. 출력이 중단되거나 근거 ID·구조 검증이 실패하면 분석을 완료로 표시하지 않습니다. 모델에 도구 권한은 없으며 출력은 텍스트로만 표시합니다.

공식 문서: [API 시작하기](https://developers.openai.com/api/docs/quickstart), [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create), [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs).

## Nuclei 연결

공식 Nuclei CLI를 서버에 설치해 PATH에 추가합니다. 이 저장소는 자동 다운로드나 전체 템플릿 실행을 하지 않습니다. 지원 CLI 버전의 옵션을 확인한 뒤 검토한 HTTP 템플릿만 연결하세요.

1. 자체 실습 대상에만 요청하고 외부 콜백·코드·파일·헤드리스·다른 호스트 접근을 포함하지 않는 템플릿을 직접 검토합니다.
2. 검토한 `.yaml` 파일을 `nuclei-templates/` 바로 아래에 둡니다.
3. 파일의 SHA-256을 계산합니다 (`Get-FileHash` 또는 `sha256sum`).
4. `nuclei-templates/approved.json`에 아래 형태로 등록합니다.

```json
[{"file": "lab-check.yaml", "sha256": "실제 파일의 SHA-256 소문자 값"}]
```

템플릿은 신뢰된 로컬 관리자만 편집해야 합니다. 해시 검증은 변경 감지용이며 템플릿의 안전성을 보장하는 샌드박스가 아닙니다. Nuclei는 초당 2요청·동시성 1·90초 프로세스 제한으로 실행하고, 리다이렉트·Interactsh·자동 업데이트 확인을 비활성화합니다. 설치·템플릿 미구성 시 HTTP 및 포트 점검만 수행하고 Nuclei 미실행 사유를 기록합니다.

## 결과 해석

포트가 열려 있다는 사실 자체는 취약점이 아닙니다. 보안 헤더 누락은 설정 관찰 결과이며 응용 프로그램의 맥락에 따라 수동 검토해야 합니다. Nuclei 매치도 실제 악용 가능성 확인이 필요합니다. 발견 사항은 모두 **검토 필요**로 기록됩니다. 수정 후 재검사하고 검사별 보고서를 비교할 수 있습니다. HTTP 실패는 부분 완료로 기록됩니다.

## 검증

```sh
python -m unittest discover -s tests -v
node --check web/app.js
node --check web/ai.js
```

테스트는 외부 대상을 접속하지 않습니다. 허용 범위 검증, API 접근 제한, 리다이렉트 차단, 임시 로컬 서버에 대한 실제 검사 및 결과 저장을 확인합니다.

## 구조

```text
server.py             로컬 API · 검사 엔진 · SQLite
ai_analysis.py        OpenAI Responses API · 구조 검증
evidence.py           민감한 원문을 제외한 구조 정보 추출
web/                  대시보드 UI
lab/server.py         루프백 전용 HTTP 실습 서버
nuclei-templates/     관리자 승인 템플릿 목록
tests/                범위·접근 통제·실제 검사 테스트
```

포트폴리오에는 실습 구성도, 발견 근거, 수동 재현 과정, 수정 커밋, 재검증 보고서를 함께 기록하세요. 실제 대상 정보·인증정보·운영 검사 결과는 저장소에 커밋하지 않습니다.

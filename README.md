# BYTE BACK 방어전 · 2단계 저장점

## 현재 동작

- 자료 화면(`/`)은 `/api/notes`에서 가상 메모의 제목과 내용을 읽어 카드로 표시합니다.
- `api/notes.js`는 서버에서 Supabase REST API를 호출합니다. `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`는 Vercel 환경변수에 직접 입력해야 하며, 코드·로그·제출 파일에 넣지 마세요.
- 빌드는 `public/aleph.json`에 Vercel의 저장소·커밋·배포 주소와 단계 정보를 기록합니다. 2단계부터 `data.json`이 남아 있으면 빌드가 실패합니다.
- `stage2-notes.sql`은 메모 테이블과 가상 자료를 준비합니다. Supabase SQL Editor에서 직접 실행해야 합니다.

## 실행과 확인

로컬 정적 빌드 확인: `npm run build -- --local`

실제 화면을 확인하려면 Vercel 프로젝트의 **Settings → Environment Variables**에 두 환경변수를 직접 저장한 뒤 **Deployments → Redeploy**를 누르세요. 값은 채팅이나 코드에 붙여 넣지 마세요. 배포 뒤 사이트의 `/`에서 카드 네 장이 보이고, `/data.json`은 404여야 합니다.

2단계의 의도된 약점: `/api/notes`는 아직 로그인 확인이 없습니다. 로그인하지 않은 요청에도 메모가 반환될 수 있습니다. 이는 현재 확인할 취약점이며, 자료는 모두 실습용 가상 내용입니다. 공개된 기존 Git 커밋이나 이전 배포의 `/data.json`은 이번 변경만으로 지워지지 않습니다.

## 확인된 범위와 다음 단계

- 변경 사항은 로컬 시험으로 검증할 수 있지만, 이 저장소에는 실제 Supabase·Vercel·GitHub 연결이 없습니다. SQL 실행, 배포, 실제 키를 이용한 요청은 수행하지 않았습니다.
- 이 단계의 `npm run bundle`은 깨끗한 Git 커밋, 본인 GitHub `origin`, 실제 `aleph.config.json` 주소와 `bundle-notes.json` 설명, 실제 배포 자기 점검이 필요합니다. 이 값이 준비되지 않아 제출 JSON을 생성하지 않았습니다.
- `npm run decider:test`와 `npm run detect:test`가 실행된다면 이는 가상 연습이며 운영 심판 판정이 아닙니다.
- 다음 실행 명령: `npm test`를 실행하세요. 정상 결과는 시험 11건 모두 통과이며, 빌드는 `data.json`이 남았을 때 거부되어야 합니다.

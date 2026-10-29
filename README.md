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

- **2026-10-28 확인 기록:** Vercel 배포의 `/api/notes`에서 가상 메모 네 건이 반환되고, `/` 화면에도 카드 네 장이 표시됩니다. `/data.json`은 404입니다. `/`, `/index.html`, `/data.json`, `/aleph.json` 응답 본문에서 가상 메모 문구 검색 결과는 모두 0건이었습니다.
- Vercel에 연결된 Supabase 프로젝트에서 `public.notes`의 메모 행 4건, `owner_id` 형식 `uuid`, 외래키 수 `0`, RLS 활성화 `true`를 확인했습니다. 비밀 키 값은 출력하거나 기록하지 않았습니다.
- `/api/notes`는 로그인 없이 메모를 반환하므로 접근 보호가 완성된 것은 아닙니다. 과거 커밋과 옛 배포의 노출도 이번 단계로 해소되지 않았습니다.
- `bundle-notes.json`과 `artifacts/submission.json`은 Git에서 무시되는 로컬 파일이며 커밋하지 않습니다. 번들 실행 결과는 실행 화면의 요약으로 확인합니다.
- `npm run decider:test`와 `npm run detect:test`가 실행된다면 이는 가상 연습이며 운영 심판 판정이 아닙니다.
- 다음 실행 명령: `npm test`를 실행하세요. 정상 결과는 시험 11건 모두 통과이며, 빌드는 `data.json`이 남았을 때 거부되어야 합니다.

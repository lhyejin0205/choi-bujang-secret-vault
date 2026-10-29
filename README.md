# BYTE BACK 방어전 · 3단계 저장점

모든 메모는 실습용 가상 자료입니다. 실제 개인정보, 비밀번호, 토큰, 서버 전용 키를 코드·Git·채팅에 넣지 마세요. 코딩 도구에는 [AGENTS.md](AGENTS.md)를 먼저 읽히세요.

## 단계 기록

| 단계 | 내용 |
|---|---|
| 1 | 공개 `data.json`에서 가상 메모가 로그인 없이 보이던 출발 상태 (첫 커밋 `c0c3653`) |
| 2 | 자료를 Supabase 테이블로 옮기고 화면이 서버 함수 `/api/notes`로 읽음. `data.json` 삭제. 첫 화면 응답에 `X-Content-Type-Options: nosniff` 추가(`vercel.json`) |
| 3 | Supabase Auth 이메일·비밀번호 로그인·로그아웃 화면, 자료 API의 토큰 검사, 로그인한 사용자의 메모 추가·수정·삭제 **(이 저장점)** |

## 현재 동작

- **화면 `/`:** 로그인하지 않으면 로그인 칸만 보이고 자료는 보이지 않습니다. 로그인하면 이메일, 로그아웃 버튼, 메모 목록과 추가·수정·삭제가 나옵니다. 로그인 실패는 이유를 화면에 보여 줍니다. 로그인은 `supabase-js` 공식 SDK(`signInWithPassword`, `signOut`)를 쓰며 비밀번호나 JWT를 직접 만들지 않습니다. 화면 코드에 있는 Project URL과 publishable key는 공개용 값입니다.
- **자료 API `/api/notes`:** 모든 요청에서 `Authorization: Bearer <토큰>`을 먼저 `src/verify-login.mjs`(틀이 준 도우미, 수정하지 않음)로 검사합니다. 토큰이 없거나 검사에 실패하면 자료 없이 401로 거부합니다. 사용자 번호는 검사를 통과한 토큰에서만 얻고, 브라우저가 보낸 `userId`·`role`·`owner_id`는 읽지 않습니다.

| 요청 | 응답 |
|---|---|
| `GET /api/notes` | 로그인 사용자의 메모와 주인 없는 가상 메모 배열 `[{id,title,body}]` |
| `POST /api/notes` | 본문 `{id?,title,body}`(`id`는 UUID, 없으면 서버가 만듦) → 201 `{id}`. `owner_id`는 서버가 확인한 사용자 번호로 저장 |
| `GET /api/notes/:id` | `{id,title,body}`, 없으면 404 |
| `PUT /api/notes/:id` | 본문 `{title,body}` → 200 `{id,title,body}`, 없으면 404 |
| `DELETE /api/notes/:id` | 200 `{id}`, 없으면 404. 지운 뒤 `GET`은 404 |

- **설정 `aleph.config.json`:** `step`은 3, `identityProvider`는 Supabase Auth의 발급자(`…/auth/v1`), 대상(`authenticated`), 공개키 주소(`…/.well-known/jwks.json`)이며 비밀 키는 들어 있지 않습니다. `allowedRoutes`는 위 다섯 경로입니다.
- **라우팅 `vercel.json`:** `/api/notes/:id`를 `/api/notes?id=:id`로 넘겨 함수 파일 하나가 처리합니다. 빌드는 `public/aleph.json`에 저장소·커밋·배포 주소와 단계를 기록하고, `data.json`이 남아 있으면 실패합니다.

## 처음 준비와 다시 실행하는 방법

1. **DB 권한:** Supabase 대시보드 > SQL Editor에서 `supabase/stage3-grants.sql`을 한 번 실행합니다. 서버 함수가 메모를 추가·수정·삭제하려면 필요하고, `anon`·`authenticated`에는 권한을 주지 않습니다. (메모 테이블을 만드는 `stage2-notes.sql`은 메모 본문이 들어 있어 Git에 없습니다. 2단계에서 이미 실행했어야 합니다.)
2. **시험 계정:** Supabase 대시보드 > Authentication > Users에서 A 계정과 B 계정을 만듭니다. 이메일 인증을 켜 두었다면 인증이 끝난 계정이어야 로그인됩니다. 비밀번호는 채팅이나 코드에 적지 마세요.
3. **Vercel 환경변수:** 프로젝트 Settings > Environment Variables에 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`(서버 전용 키)가 있어야 합니다. 값은 직접 입력하고 저장한 뒤 Redeploy 합니다. `SUPABASE_SECRET_KEY`는 DB 읽기·쓰기와 로그인 검사에 서버에서만 쓰입니다.
4. **시험:** `npm test`. 가짜 검사기와 가짜 저장소로 도는 시험이며 실제 로그인이나 배포를 확인하지 않습니다.

## 확인 방법

- 로그인 전: 시크릿 창에서 `/`를 열면 로그인 칸만 보이고 자료가 없어야 합니다. 주소창에서 `/api/notes`를 열면 401이어야 합니다.
- 로그인 후: A 계정으로 로그인하면 가상 메모가 보이고 메모를 추가·수정·삭제할 수 있어야 합니다. 로그아웃하면 화면이 로그인 칸으로 돌아가야 합니다.
- 틀린 비밀번호로 로그인하면 화면에 이유가 나와야 합니다.
- 공개 파일 검색은 아래 한 줄입니다. 결과가 비어 있어야 정상입니다.
  `git grep -n -E "실습용 가상 (과제|포트폴리오|리추얼|행정) 기록" origin/main`

## 알려진 약점 (3단계 기준)

- **소유자 검사가 없습니다.** 로그인만 하면 B가 A 메모의 id를 알 때 `GET`·`PUT`·`DELETE`로 접근해 고치거나 지울 수 있습니다. 4단계에서 고칩니다. (시험 파일에 이 동작을 기록해 두었습니다.)
- 토큰 검사는 서명과 만료를 확인합니다. 로그아웃해도 이미 발급된 토큰은 만료 전까지 검사를 통과할 수 있습니다.
- 목록의 가상 메모(주인 없음)는 로그인한 모든 사용자에게 보입니다.
- 과거 노출은 해소되지 않았습니다. 첫 커밋의 `data.json`과 1단계 옛 배포가 남아 있습니다.

## 확인 기록

직접 확인한 결과만 날짜와 함께 적으세요. 확인하지 않은 항목은 적지 않습니다.

- **2026-10-28 (2단계):** 배포의 `/api/notes`와 `/`에서 가상 메모 네 건이 보였고 `/data.json`은 404였습니다. `public.notes`는 메모 4건, `owner_id`는 `uuid`, 외래키 0개, RLS 켜짐이었습니다. 비밀 키 값은 출력하거나 기록하지 않았습니다.
- **3단계:** (A 로그인·로그아웃, 로그인 없는 요청 거부, 메모 추가·수정·삭제를 확인한 뒤 여기에 적으세요.)

`bundle-notes.json`과 `artifacts/submission.json`은 Git에서 무시되는 로컬 파일이며 커밋하지 않습니다. `npm run decider:test`와 `npm run detect:test`는 가상 연습이며 운영 심판 판정이 아닙니다.

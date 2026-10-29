# BYTE BACK 방어전 · 5단계 저장점

모든 메모는 실습용 가상 자료입니다. 실제 개인정보, 비밀번호, 토큰, 서버 전용 키를 코드·Git·채팅에 넣지 마세요. 코딩 도구에는 [AGENTS.md](AGENTS.md)를 먼저 읽히세요.

## 단계 기록

| 단계 | 내용 |
|---|---|
| 1 | 공개 `data.json`에서 가상 메모가 로그인 없이 보이던 출발 상태 (첫 커밋 `c0c3653`) |
| 2 | 자료를 Supabase 테이블로 옮기고 화면이 서버 함수 `/api/notes`로 읽음. `data.json` 삭제. 이어서 별도 커밋(`39af154`)으로 첫 화면 응답에 `X-Content-Type-Options: nosniff` 추가(`vercel.json`) |
| 3 | Supabase Auth 이메일·비밀번호 로그인·로그아웃 화면, 자료 API의 토큰 검사, 로그인한 사용자의 메모 추가·수정·삭제 (`73b033d`) |
| 4 | 자료 API의 소유자 검사(본인 메모만 읽기·추가·수정·삭제, 주인 바꾸기 거부), 가상 메모 네 건을 A 소유로 연결, `public.notes` RLS·최소 권한 SQL (`6a7345c`) |
| 5 | 자료 요청을 서버 함수 한곳으로 모음: 브라우저의 Supabase 직접 자료 호출은 원래 없음(확인), `public.notes`의 PUBLIC·anon·authenticated 직접 권한 회수 SQL, `originalApiUrl` 기록, 원본 API 자기 점검 (`6141b8a`). 이어서 가점 작업으로 로그인·로그아웃도 서버 함수로 옮겨 화면 코드에서 Supabase 키·SDK 제거 **(이 저장점)** |

## 현재 동작

- **화면 `/`:** 로그인하지 않으면 로그인 칸만 보이고 자료는 보이지 않습니다. 로그인하면 이메일, 로그아웃 버튼, 메모 목록과 추가·수정·삭제가 나옵니다. 로그인 실패는 이유를 화면에 보여 줍니다. 화면 코드에는 Supabase 주소·키·SDK가 없습니다. 로그인은 `POST /api/login`, 로그아웃은 `POST /api/logout`, 메모 자료는 `/api/notes`로, 브라우저는 서버 함수만 부릅니다. 받은 접근 토큰은 그 탭의 `sessionStorage`에만 두고, 만료되거나 401을 받으면 버리고 로그인 화면으로 돌아갑니다.
- **로그인 서버 함수:** `src/session-handler.mjs`가 Supabase Auth의 비밀번호 로그인(`/auth/v1/token?grant_type=password`)을 서버에서 부르고, 브라우저에는 `{accessToken, expiresAt, email}`만 돌려줍니다. refresh token과 서버 전용 키는 돌려주지 않고, 비밀번호는 기록하지 않습니다. 실패 이유는 `INVALID_CREDENTIALS`·`EMAIL_NOT_CONFIRMED`·`RATE_LIMITED` 같은 고정 코드입니다. 로그아웃은 그 토큰의 세션을 `scope=local`로 끝냅니다. JWT를 직접 만들지 않으며, 자료 API의 토큰 검사는 그대로 `src/verify-login.mjs`가 합니다.
- **자료 API `/api/notes`:** 모든 요청에서 `Authorization: Bearer <토큰>`을 먼저 `src/verify-login.mjs`(틀이 준 도우미, 수정하지 않음)로 검사합니다. 토큰이 없거나 검사에 실패하면 자료 없이 401로 거부합니다. 사용자 번호는 검사를 통과한 토큰에서만 얻고, 브라우저가 URL이나 본문으로 보낸 `userId`·`role`·`owner_id`는 믿지 않습니다.
- **소유자 검사(4단계):** 모든 DB 요청에 `owner_id = 검증된 사용자 번호` 조건을 붙이고, DB가 돌려준 행의 주인도 다시 확인합니다. 남의 메모 id는 없는 메모와 똑같이 404입니다. 수정 본문에 다른 주인(`owner_id`·`ownerId`·`userId`·`user_id`)이 있으면 403 `OWNER_CHANGE_FORBIDDEN`이고, 수정할 때 `owner_id`를 본인으로 다시 적습니다.

| 요청 | 응답 |
|---|---|
| `GET /api/notes` | 로그인 사용자 본인의 메모 배열 `[{id,title,body}]` |
| `POST /api/notes` | 본문 `{id?,title,body}`(`id`는 UUID, 없으면 서버가 만듦) → 201 `{id}`. `owner_id`는 서버가 확인한 사용자 번호로 저장 |
| `GET /api/notes/:id` | 본인 메모면 `{id,title,body}`, 없거나 남의 메모면 404 |
| `PUT /api/notes/:id` | 본문 `{title,body}` → 200 `{id,title,body}`, 없거나 남의 메모면 404, 주인 바꾸기는 403 |
| `DELETE /api/notes/:id` | 본인 메모면 200 `{id}`, 없거나 남의 메모면 404. 지운 뒤 `GET`은 404 |
| `POST /api/login` | 본문 `{email,password}` → 200 `{accessToken,expiresAt,email}`, 틀리면 401 `INVALID_CREDENTIALS` |
| `POST /api/logout` | `Authorization: Bearer <토큰>` → 200 `{ok:true}` |

- **원본 자료(5단계):** 원본 자료 API는 `https://fcmjfhjbsaqggxmmjbjo.supabase.co/rest/v1/notes`이며 `originalApiUrl`에 적었습니다. PUBLIC·anon·authenticated에는 이 테이블 권한이 없어 publishable(anon) 키나 로그인 토큰으로 직접 읽거나 고칠 수 없고, 서버 전용 키를 가진 서버 함수만 접근합니다.
- **설정 `aleph.config.json`:** `step`은 5, `identityProvider`는 Supabase Auth의 발급자(`…/auth/v1`), 대상(`authenticated`), 공개키 주소(`…/.well-known/jwks.json`)이며 비밀 키는 들어 있지 않습니다. `allowedRoutes`는 위 일곱 경로, `originalApiUrl`은 쿼리 없는 원본 자료 주소입니다.
- **라우팅 `vercel.json`:** `/api/notes/:id`를 `/api/notes?id=:id`로, `/api/login`·`/api/logout`을 `/api/notes?session=login|logout`으로 넘겨 함수 파일 하나(`api/notes.js`)가 처리합니다. 시작 틀의 서버 함수 기준표(`package/baseline-functions.json`)에 맞춰 함수 파일을 늘리지 않았습니다. 빌드는 `public/aleph.json`에 저장소·커밋·배포 주소와 단계를 기록하고, `data.json`이 남아 있으면 실패합니다.

## 처음 준비와 다시 실행하는 방법

1. **DB 권한:** Supabase 대시보드 > SQL Editor에서 `supabase/stage3-grants.sql`을 한 번 실행합니다. 서버 함수가 메모를 추가·수정·삭제하려면 필요하고, `anon`·`authenticated`에는 권한을 주지 않습니다. (메모 테이블을 만드는 `stage2-notes.sql`은 메모 본문이 들어 있어 Git에 없습니다. 2단계에서 이미 실행했어야 합니다.)
2. **시험 계정:** Supabase 대시보드 > Authentication > Users에서 A 계정과 B 계정을 만듭니다. 이메일 인증을 켜 두었다면 인증이 끝난 계정이어야 로그인됩니다. 비밀번호는 채팅이나 코드에 적지 마세요.
3. **소유자 연결과 RLS(4단계):** 가상 메모 네 건의 `owner_id`를 A 계정으로 연결하고 B 소유 시험 메모 한 건을 넣습니다(이메일이 들어가는 SQL이라 Git에 넣지 않습니다). 그다음 `supabase/stage4-rls.sql`을 ①→②→③ 순서로 실행합니다. `anon`에는 권한이 없고 `authenticated`에는 SELECT·INSERT·UPDATE·DELETE만, 정책은 모두 `auth.uid() = owner_id`입니다. 서버 함수는 서버 전용 키로 접속해 RLS를 거치지 않으므로, 앱 API의 차단은 소유자 검사가 맡습니다.
4. **직접 권한 회수(5단계):** `supabase/stage5-revoke.sql`을 ①→②→③ 순서로 실행합니다. PUBLIC·anon·authenticated의 `public.notes` 권한을 모두 거두고, service_role 권한과 RLS·정책은 그대로 둡니다. 4단계에서 authenticated에 준 권한도 여기서 회수됩니다.
5. **Vercel 환경변수:** 프로젝트 Settings > Environment Variables에 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`(서버 전용 키)가 있어야 합니다. 값은 직접 입력하고 저장한 뒤 Redeploy 합니다. `SUPABASE_SECRET_KEY`는 DB 읽기·쓰기, 로그인·로그아웃, 로그인 검사에 서버에서만 쓰입니다.
6. **시험:** `npm test`.
7. **제출 묶음:** 원본 API 자기 점검에는 공개용 키가 필요합니다. 화면 코드에 키가 없으므로 `SUPABASE_PUBLISHABLE_KEY=sb_publishable_… npm run bundle`처럼 실행할 때만 넘깁니다. 키 없이 실행하면 그 점검은 미실행으로 남습니다. 가짜 검사기와 가짜 저장소로 도는 시험이며 실제 로그인이나 배포를 확인하지 않습니다.

## 확인 방법

- 로그인 전: 시크릿 창에서 `/`를 열면 로그인 칸만 보이고 자료가 없어야 합니다. 주소창에서 `/api/notes`를 열면 401이어야 합니다.
- 로그인 후: A 계정으로 로그인하면 가상 메모가 보이고 메모를 추가·수정·삭제할 수 있어야 합니다. 로그아웃하면 화면이 로그인 칸으로 돌아가야 합니다.
- 틀린 비밀번호로 로그인하면 화면에 이유가 나와야 합니다.
- A로 로그인하면 A의 네 메모만, B로 로그인하면 B 시험 메모만 보여야 합니다. B가 A 메모 id로 `GET`·`PUT`·`DELETE`하면 404, 자기 메모의 주인을 바꾸는 `PUT`은 403이어야 합니다.
- 원본 직접 요청: publishable 키로 `/rest/v1/notes`를 직접 부르면 자료 없이 거부되어야 합니다(심판이 anon 키로 확인). `npm run bundle`의 자기 점검도 같은 요청을 한 번 보내 결과를 기록합니다.
- 화면 원본(Ctrl+U)에서 `sb_publishable`·`supabase`를 찾으면 0건이어야 합니다.
- 공개 파일 검색은 아래 한 줄입니다. 결과가 비어 있어야 정상입니다.
  `git grep -n -E "실습용 가상 (과제|포트폴리오|리추얼|행정) 기록" origin/main`

## 알려진 약점 (5단계 기준)

- 토큰 검사는 서명과 만료를 확인합니다. 로그아웃해도 이미 발급된 토큰은 만료 전까지 검사를 통과할 수 있습니다.
- 브라우저에 refresh token을 주지 않으므로 접근 토큰이 만료되면(보통 1시간) 다시 로그인해야 합니다.
- 로그인 요청이 모두 Vercel 서버에서 Supabase로 가므로, Supabase의 IP별 로그인 횟수 제한을 여러 사용자가 함께 쓸 수 있습니다. 이 서버 함수에는 따로 횟수 제한이 없습니다.
- 접근 토큰은 탭의 `sessionStorage`에 있어, 화면에 스크립트 주입 약점이 생기면 읽힐 수 있습니다.
- 주인이 없는(`owner_id`가 비어 있는) 메모는 이제 아무에게도 보이지 않습니다.
- 서버 함수는 서버 전용 키로 RLS를 거치지 않으므로, 자료 보호는 서버 함수의 로그인·소유자 검사에 달려 있습니다. 이 검사를 바꿀 때 특히 조심해야 합니다.
- 과거 노출은 해소되지 않았습니다. 첫 커밋의 `data.json`과 1단계 옛 배포가 남아 있습니다.

## 확인 기록

직접 확인한 결과만 날짜와 함께 적으세요. 확인하지 않은 항목은 적지 않습니다.

- **2026-10-28 (2단계):** 배포의 `/api/notes`와 `/`에서 가상 메모 네 건이 보였고 `/data.json`은 404였습니다. `public.notes`는 메모 4건, `owner_id`는 `uuid`, 외래키 0개, RLS 켜짐이었습니다. 비밀 키 값은 출력하거나 기록하지 않았습니다.
- **2026-10-29 (3단계):** A 로그인 뒤 메모 네 건과 추가 칸이 보였고 로그아웃하면 로그인 칸만 남았습니다. 시크릿 창에서 로그인 없이 자료가 보이지 않았고 `/api/notes`는 `{"error":"UNAUTHORIZED"}`였습니다. A로 시험 메모를 추가·수정·삭제했습니다. 첫 화면 응답에 `X-Content-Type-Options: nosniff`가 있었고 페이지 원본에 `sb_secret`·`service_role`이 없었습니다.
- **2026-10-29 (4단계 DB):** SQL Editor에서 가상 메모 네 건의 주인이 A, B 시험 메모 한 건의 주인이 B로 확인되었습니다.
- **2026-10-29 (4단계 API·RLS):** 배포(`6a7345c`) 뒤 A는 A 메모 네 건만, B는 B 시험 메모 한 건만 보였고 A·B 모두 자기 메모를 추가·수정·삭제했습니다. B 토큰으로 A 메모 id에 `GET`·`PUT`·`DELETE`는 모두 404, B가 자기 메모의 `owner_id`를 바꾸는 `PUT`은 403이었습니다. RLS 적용 전 화면에서 확인한 anon 일곱 권한과 authenticated DELETE·INSERT는 false, 기존 정책 0개였고, 적용 후 anon은 모두 false, authenticated는 SELECT·INSERT·UPDATE·DELETE만 true, 정책은 `notes_*_own` 네 개였습니다.
- **2026-10-29 (5단계):** 브라우저 코드의 Supabase 직접 자료 호출은 원래 없었습니다. `public.notes` 권한 회수 전 authenticated는 SELECT·INSERT·UPDATE·DELETE가 true였고, 회수 후 public·anon·authenticated 21개 모두 false, service_role의 SELECT·INSERT·UPDATE·DELETE는 true였습니다. 회수 뒤 배포(`6141b8a`)에서 A가 메모를 읽고 추가·수정·삭제했고, `npm run bundle`의 anon 키 직접 요청은 401로 자료가 없었습니다.
- **5단계 가점(로그인 서버 이전):** (배포 뒤 A·B 로그인·로그아웃, 틀린 비밀번호 안내, 화면 원본의 키 0건을 확인한 뒤 여기에 적으세요.)

`bundle-notes.json`과 `artifacts/submission.json`은 Git에서 무시되는 로컬 파일이며 커밋하지 않습니다. `npm run decider:test`와 `npm run detect:test`는 가상 연습이며 운영 심판 판정이 아닙니다.

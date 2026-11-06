# BYTE BACK 방어전 · 12단계 저장점

모든 메모는 실습용 가상 자료입니다. 실제 개인정보, 비밀번호, 토큰, 서버 전용 키를 코드·Git·채팅에 넣지 마세요. 코딩 도구에는 [AGENTS.md](AGENTS.md)를 먼저 읽히세요.

## 단계 기록

| 단계 | 내용 |
|---|---|
| 1 | 공개 `data.json`에서 가상 메모가 로그인 없이 보이던 출발 상태 (첫 커밋 `c0c3653`) |
| 2 | 자료를 Supabase 테이블로 옮기고 화면이 서버 함수 `/api/notes`로 읽음. `data.json` 삭제. 이어서 별도 커밋(`39af154`)으로 첫 화면 응답에 `X-Content-Type-Options: nosniff` 추가(`vercel.json`) |
| 3 | Supabase Auth 이메일·비밀번호 로그인·로그아웃 화면, 자료 API의 토큰 검사, 로그인한 사용자의 메모 추가·수정·삭제 (`73b033d`) |
| 4 | 자료 API의 소유자 검사(본인 메모만 읽기·추가·수정·삭제, 주인 바꾸기 거부), 가상 메모 네 건을 A 소유로 연결, `public.notes` RLS·최소 권한 SQL (`6a7345c`) |
| 5 | 자료 요청을 서버 함수 한곳으로 모음: 브라우저의 Supabase 직접 자료 호출은 원래 없음(확인), `public.notes`의 PUBLIC·anon·authenticated 직접 권한 회수 SQL, `originalApiUrl` 기록, 원본 API 자기 점검 (`6141b8a`). 이어서 가점 작업으로 로그인·로그아웃도 서버 함수로 옮겨 화면 코드에서 Supabase 키·SDK 제거 |
| 6 | 판정 요청의 등록 기기·가명 사용자·확인된 기기 ID와 `notes` 읽기 경로(`GET /notes`, `GET /notes/:id`)를 함께 확인합니다. 미등록·확인값 누락·다른 경로/동작은 `device_not_registered`로 거부 (`19efa2d`) |
| 7 | 출처가 명시된 가상 신호만 검사하고, 야간·처음 보는 네트워크·5분 안의 대량 읽기가 함께 있을 때 `step_up_required`로 추가 확인을 요청하고, 계약의 `stepUp`으로 재확인을 마친 요청은 허용합니다. 지역만으로 차단하지 않습니다. 동일 로그인 재확인 시각 계약이 없어 실제 자료 차단·재로그인은 미실행 (`2c941aa`, 야간 시간대 보정 `cd89d13`, 저장점 `839eebb`, 세 신호 AND 규칙 `ad0968a`, fixture 결과 차이 검사 `1d4002a`, 시작 틀 사건 낱말 `e5e2710`, 재확인 반영 `01867ec`) |
| 8 | 자원을 구역으로 나눔: 메모 `note:<id>`·강사 공지 `notice:<id>` 자원 ID, 판정기의 구역별 정확한 경로 규칙(`resource_zone`), 공지 쓰기의 저장된 강사 권한 대조와 짧은 거부 사유 기록. `allowedRoutes`는 판정기 허용 경로 세 개 (`005f714`) |
| 9 | 탐지기 `src/detect.mjs`: 사건의 `at`·`method`·`identity.sub`만 읽고, 같은 가명 사용자의 GET이 10분 안에 120건을 넘으면 `burst_read`로 회수를 제안(`propose_revocation`)합니다. 운영 반 엔진의 사건 전달·회수 집행은 미연결 (`57b2c50`) |
| 10 | 백업에서 되살리기: 안전 정책(판정기 규칙·`allowedRoutes`·DB 접근 정책) 사본과 SHA-256 해시, 시험 정책과의 차이 보기·확인 후 복원·감사 기록(`npm run policy:*`), 시험 계정 B 메모 한 건의 비공개 사본(`stage10-restore-backup.sql`)과 ID·소유자·내용 해시를 대조해 그 한 건만 되돌리는 `POST /api/restore`, 복구 뒤 재확인 순서 (`9075192`) |
| 11 | 나만의 접속 앱: 설치형 웹앱 설정(`manifest.webmanifest`·아이콘)·오프라인 안내·기기 승인 상태 표시, 메모리에만 있는 기기 서명 키로 `POST /api/devices` 승인 대기 등록, DB(`stage11-devices.sql`)에서 사람이 승인한 기기의 요청 서명(동작·경로·본문 해시·시각)이 있어야 메모·공지 API가 응답 (`4352d66`, 재제출에서 로그인 세션도 메모리에만 두도록 고침 `1ae7fd6`) |
| 12 | 탈환 작전실: 승인된 기기에서 `GET /api/ops`로 판정기 규칙(코드 기준)·탐지 사건(미실행)·기기 승인·회수 상태와 복구 버전·복원 감사 기록(실측)을 출처와 함께 표시, 1~11단계 정상·금지 요청 재확인 표(`npm run ops:recheck`·작전실 「재확인 표 만들기」), 출처와 설치·실행·중지·복구 안내 (`1776206`, 재제출에서 제출 묶음 자기 점검이 배포 앱에 요청을 보내지 않고 `not_run`으로 기록하도록 고침 `84a2ff4`·`93bbbf0`·`183823e`) |

## 현재 동작

- **화면 `/`:** 로그인하지 않으면 로그인 칸만 보이고 자료는 보이지 않습니다. 로그인하면 이메일, 로그아웃 버튼, 메모 목록과 추가·수정·삭제가 나옵니다. 로그인 실패는 이유를 화면에 보여 줍니다. 화면 코드에는 Supabase 주소·키·SDK가 없습니다. 로그인은 `POST /api/login`, 로그아웃은 `POST /api/logout`, 메모 자료는 `/api/notes`로, 브라우저는 서버 함수만 부릅니다. 받은 접근 토큰은 페이지의 메모리 변수에만 두고 브라우저 저장소에는 쓰지도 읽지도 않습니다(11단계 재제출에서 `sessionStorage` 저장을 없애고, 이전 버전이 남긴 값은 열 때 지움). 만료되거나 401을 받으면 버리고 로그인 화면으로 돌아가며, 새로 고치거나 탭을 닫으면 다시 로그인해야 합니다.
- **설치형 앱·기기 승인(11단계):** `public/manifest.webmanifest`(앱 이름 「BYTE BACK 자료실」, `standalone`)와 `icon.svg`로 설치형 웹앱으로 열 수 있고, 연결이 끊기면 오프라인 안내가 뜹니다(서비스 워커·자료 캐시 없음). 화면 위쪽에 앱 실행 방식과 기기 승인 상태를 보여 주며, 설치 여부는 승인 판단에 쓰지 않습니다. 로그인 뒤 화면은 내보낼 수 없는 ECDSA P-256 서명 키를 **메모리 변수에만** 만들고(브라우저 저장소에 넣지 않음) 공개키를 `POST /api/devices`로 보내 "승인 대기"로 등록합니다. 승인 전에는 기기 지문 앞 12자리와 「승인 다시 확인」만 보이고 메모·공지를 불러오지 않습니다. 승인은 SQL Editor에서 `supabase/stage11-devices.sql` ③으로 사람이 하며, 서버 함수에는 UPDATE 권한이 없습니다. 승인 뒤 화면은 모든 자료 요청에 `aleph-device-v1·동작·경로·시각·정렬한 JSON 본문의 SHA-256`에 대한 서명을 `x-device-key`·`x-device-time`·`x-device-signature`로 붙이고, 서버(`src/device-handler.mjs`)는 라우팅으로 아는 실제 경로와 받은 본문으로 다시 검증합니다. 서명 없음·승인 전·다른 사람 기기·5분 넘은 서명·서명 뒤 경로나 본문 변경은 403입니다. 새로 고치면 키가 사라져 다시 승인받아야 합니다.
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
- **기기 등록 판정(6단계):** `src/decider.mjs`는 계약에 있는 `deviceRegistered`, `subjectId`, `deviceId`, `service`, `method`, `path`, `route`만 확인합니다. 등록된 확인 기기의 자료 읽기 경로만 `allow`하고, 미등록·확인값 누락·쓰기/다른 경로는 `deny`와 `device_not_registered`를 반환합니다. `npm run decider:test`는 가상 요청 연습이며 실제 기기 접속이나 심판 판정이 아닙니다.
- **접속 정보 판정(7단계):** 판정기는 계약의 `signals`와 `recentEvents`를 그대로 검사하며, 누락·형식 오류·`judge_fixture`가 아닌 출처는 정상값으로 채우지 않고 `step_up_required`로 보냅니다. `judge_fixture`는 가상 연습에만 쓰입니다. 0–5시 또는 22–23시(6시~21시는 정상)·처음 보는 네트워크(`first_seen` 또는 시작 틀의 `unusual`)·최근 5분 다량 읽기 사건(`bulk_read` 또는 시작 틀의 `risk_signal`) 20건 이상이 모두 있을 때만 `unusual_access_pattern`과 `step_up_required`로 추가 확인하고, 지역만으로 차단하지 않습니다. 같은 복합 이상 요청이라도 계약의 `stepUp`이 `verified: true`이고 `authAgeSeconds`가 0~900초이면 재확인을 마친 것으로 보고 `allow`합니다. 재확인이 없거나 범위를 벗어나면 그대로 `step_up_required`입니다. 계약에는 동일 로그인 재로그인 시각이 없어 실제 자료 차단은 시험하지 않았습니다.
- **XDR known-CVE 보너스:** `xdr/known-cve/decide.mjs`는 파일 입출력 없이 CVE-2021-44228 형태 JNDI 요청과 점검 도구 흔적을 `block`·`alert`·`record`로 나눕니다. `npm run xdr:run -- known-cve`가 결과를 만들고 XDR의 `deny-rules.json`·`alerts.log` 연결을 시험합니다. 현재 가상 경보 24건은 block 8·alert 1·record 15이며, 시간순 재생에서 정상 이벤트 차단은 0건이었습니다. 오래된 fixture의 규칙은 만료 처리됩니다. 이는 운영 ZTNA 접속 경로의 실시간 차단 증거가 아닙니다.
- **자원 구역(8단계):** `src/resources.mjs`가 메모는 `note:<UUID>`(목록 `note:list`), 강사 공지는 `notice:<공지 ID>`(목록 `notice:list`)로 자원 ID를 정하고, 자료 API가 요청마다 응답 머리글 `x-resource-kind`·`x-resource-id`에 남깁니다. 응답 본문 모양은 그대로입니다. 강사 공지 `/api/notices`, `/api/notices/:id`(`src/notices-handler.mjs`)는 로그인한 사용자가 읽기만 하며, 공지 두 건은 코드 안의 실습용 가상 문구입니다.
- **구역 판정(8단계):** 판정기는 등록 기기 확인 뒤 `ZONE_ROUTES`의 정확한 경로만 허용합니다. 메모는 `GET /notes/:id`(ID 형식은 좁히지 않음), 반 공지는 `GET /notices`·`GET /notices/:id`뿐입니다. 메모 전체 목록, 메모·공지 쓰기, 강사 자료 등 다른 서비스, 알 수 없는 경로, 쿼리가 붙은 요청, `:id` 아래 기능 경로는 `deny`(`resource_zone`, 이유 코드는 등록된 `device_not_registered`)입니다. 메모 주인 비교는 판정기가 아니라 자료 API가 합니다.
- **API 권한 재대조(8단계):** 공지 쓰기는 검증된 Supabase 로그인 사용자를 서버 환경변수 `INSTRUCTOR_USER_IDS`(쉼표로 구분한 사용자 UUID)와 대조해, 목록에 없으면 403 `NOT_INSTRUCTOR`입니다. 화면 메뉴나 본문의 `role`은 보지 않습니다. 강사라도 공지 저장소가 없어 수정은 501로 받지 않습니다. 메모·공지 API는 거부할 때 `{event:'api_denied', zone, method, reason}`만 Vercel 함수 기록에 남기며 사용자 번호·토큰·본문은 넣지 않습니다.
- **도플갱어 탐지(9단계):** `src/detect.mjs`의 `detect(events)`는 `docs/DETECT_EVENTS.md`의 사건 모양 그대로 각 사건에서 `at`·`method`·`identity.sub` 세 값만 읽고, 형식이 틀린 사건은 세지 않습니다. 네트워크·기기·지역 값은 쓰지 않고 토큰·본문은 복사하지 않습니다. 같은 `sub`의 GET이 `at` 기준 어느 10분 구간(시작 시각부터 10분 미만)에서든 121건 이상이면 정확히 `{action:'propose_revocation', reasonCode:'burst_read', subject}`를, 아니면 `{action:'observe'}`를 돌려줍니다. 정확히 120건, 10분 밖으로 흩어진 조회, 다른 사용자의 합산은 정상입니다. 회수는 제안만 하며 회수 API를 부르거나 기기 권한을 바꾸지 않습니다. `npm run detect:test`는 가상 사건 연습이며, 운영 반 엔진의 사건 전달과 접속 회수는 연결·시험하지 않았습니다.
- **안전 정책 사본(10단계):** 판정기 규칙(`src/decider.mjs`), `allowedRoutes`, DB 접근 정책(`supabase/stage4-rls.sql`·`stage5-revoke.sql`)을 안전 정책으로 정해 `policy-backup/safe-policy.json`과 SHA-256 해시(`safe-policy.sha256`, 버전 `safe-2026-11-06-57b2c50`)로 남겼습니다. `npm run policy:diff`는 사본과 해시를 다시 읽어 검증한 뒤 시험 정책(`trial-policy.json`)과의 차이만 보여 주고, 사본이 없거나 해시가 다르면 중단합니다. `npm run policy:restore`는 바뀔 항목을 먼저 보여 주고, `-- --confirm=<해시 앞 12자>`를 붙였을 때만 시험 정책을 검증 버전으로 되돌린 뒤 `policy-backup/audit-log.jsonl`에 덧붙입니다. 운영 정책 파일은 바꾸지 않습니다.
- **메모 한 건 복원(10단계):** 복원 대상은 시험 계정 B의 가상 메모 **`7cd005ec-cbad-47d4-9100-3a48e0f04269`** 한 건입니다. 서비스는 자료 API 서버 함수(`api/notes.js`, `notes`), 경로는 **`POST /api/restore`**(`vercel.json`이 `/api/notes?zone=restore`로 넘김, `aleph.config.json`의 `restoreRoute`)입니다. `src/restore-handler.mjs`가 비공개 사본 테이블 `public.notes_restore_backup`을 다시 읽어 ID·소유자(B)·내용 해시(SHA-256 of `title\ncontent`)를 대조하고, 맞을 때만 그 한 건을 id 조건으로 되돌립니다(삭제됐으면 같은 id로 다시 넣고, 변조됐으면 고침). 되돌린 뒤 다시 읽어 세 값이 사본과 같은지 확인해 `idMatches`·`ownerMatches`·`contentHashMatches`로 답합니다. 호출은 로그인한 B 본인이나 심판 토큰만 할 수 있고, 대상은 본문·쿼리로 바꿀 수 없습니다. 다른 메모는 건드리지 않고, 시도마다 `public.restore_audit`에 한 줄씩 덧붙이기만 합니다. 응답·기록에 메모 본문과 사용자 번호는 넣지 않습니다.
- **설정 `aleph.config.json`:** `step`은 11, `restoreRoute`는 `POST /api/restore`, `identityProvider`는 Supabase Auth의 발급자(`…/auth/v1`), 대상(`authenticated`), 공개키 주소(`…/.well-known/jwks.json`)이며 비밀 키는 들어 있지 않습니다. `allowedRoutes`는 판정기가 허용하는 `GET /api/notes/:id`, `GET /api/notices`, `GET /api/notices/:id` 세 경로, `originalApiUrl`은 쿼리 없는 원본 자료 주소입니다. 화면의 메모 목록·추가·수정·삭제와 로그인·로그아웃 API는 서버 함수에 그대로 있지만 판정기 허용 경로에는 넣지 않았습니다.
- **라우팅 `vercel.json`:** `/api/notes/:id`를 `/api/notes?id=:id`로, `/api/notices(/:id)`를 `/api/notes?zone=notices(&id=:id)`로, `/api/login`·`/api/logout`을 `/api/notes?session=login|logout`으로 넘겨 함수 파일 하나(`api/notes.js`)가 처리합니다. 시작 틀의 서버 함수 기준표(`package/baseline-functions.json`)에 맞춰 함수 파일을 늘리지 않았습니다. 빌드는 `public/aleph.json`에 저장소·커밋·배포 주소와 단계를 기록하고, `data.json`이 남아 있으면 실패합니다.

## 처음 준비와 다시 실행하는 방법

1. **DB 권한:** Supabase 대시보드 > SQL Editor에서 `supabase/stage3-grants.sql`을 한 번 실행합니다. 서버 함수가 메모를 추가·수정·삭제하려면 필요하고, `anon`·`authenticated`에는 권한을 주지 않습니다. (메모 테이블을 만드는 `stage2-notes.sql`은 메모 본문이 들어 있어 Git에 없습니다. 2단계에서 이미 실행했어야 합니다.)
2. **시험 계정:** Supabase 대시보드 > Authentication > Users에서 A 계정과 B 계정을 만듭니다. 이메일 인증을 켜 두었다면 인증이 끝난 계정이어야 로그인됩니다. 비밀번호는 채팅이나 코드에 적지 마세요.
3. **소유자 연결과 RLS(4단계):** 가상 메모 네 건의 `owner_id`를 A 계정으로 연결하고 B 소유 시험 메모 한 건을 넣습니다(이메일이 들어가는 SQL이라 Git에 넣지 않습니다). 그다음 `supabase/stage4-rls.sql`을 ①→②→③ 순서로 실행합니다. `anon`에는 권한이 없고 `authenticated`에는 SELECT·INSERT·UPDATE·DELETE만, 정책은 모두 `auth.uid() = owner_id`입니다. 서버 함수는 서버 전용 키로 접속해 RLS를 거치지 않으므로, 앱 API의 차단은 소유자 검사가 맡습니다.
4. **직접 권한 회수(5단계):** `supabase/stage5-revoke.sql`을 ①→②→③ 순서로 실행합니다. PUBLIC·anon·authenticated의 `public.notes` 권한을 모두 거두고, service_role 권한과 RLS·정책은 그대로 둡니다. 4단계에서 authenticated에 준 권한도 여기서 회수됩니다.
4-1. **복원 사본(10단계):** `supabase/stage10-restore-backup.sql`을 ①→②→③ 순서로 실행합니다. B 메모 한 건을 `public.notes_restore_backup`에 복사하고 내용 해시를 함께 저장하며, 감사 기록 테이블 `public.restore_audit`을 만듭니다. 두 테이블 모두 RLS를 켜고 anon·authenticated 권한이 없으며, service_role은 사본 SELECT와 감사 SELECT·INSERT만 가집니다. 사본이 이미 있으면 덮어쓰지 않으므로 **메모가 바뀌기 전에** 실행해야 합니다. ③에서 `sha_ok`가 true여야 합니다.
4-2. **기기 승인(11단계):** `supabase/stage11-devices.sql`의 ①(테이블)·②(권한 확인)를 한 번 실행합니다. ②에서 anon·authenticated는 모두 false, service_role은 SELECT·INSERT만 true여야 합니다. 배포 화면에 로그인해 기기 지문이 보이면 ③의 목록 질의로 같은 지문을 찾아 `update … set status = 'approved'`를 실행하고 「승인 다시 확인」을 누릅니다.
5. **Vercel 환경변수:** 프로젝트 Settings > Environment Variables에 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`(서버 전용 키)가 있어야 합니다. 값은 직접 입력하고 저장한 뒤 Redeploy 합니다. `SUPABASE_SECRET_KEY`는 DB 읽기·쓰기, 로그인·로그아웃, 로그인 검사에 서버에서만 쓰입니다.
6. **시험:** `npm test`.
7. **판정기 연습(7·8단계):** `npm run fixture:7`과 `npm run decider:test`를 실행합니다. 정상·지역만 다른 사건은 `allow`, 복합 이상 사건은 `step_up`, 누락·위조 출처 신호도 정상 접속 정보로 승격되지 않는지, 메모 한 건·공지 읽기만 허용되고 메모 목록·쓰기·강사 자료·쿼리 요청은 `deny`인지 확인합니다. 둘 다 가상 요청 연습이며 실제 심판 판정은 아닙니다.
   - **탐지 연습(9단계):** `npm run detect:test`에서 10분 안 121건·200건 폭주는 `propose_revocation`, 정상 30건·120건·두 사용자 각 100건·흩어진 200건은 `observe`여야 합니다.
   - **강사 권한(선택):** 강사 계정이 있으면 Vercel 환경변수 `INSTRUCTOR_USER_IDS`에 그 사용자 UUID를 넣고 Redeploy 합니다. 넣지 않으면 모든 공지 쓰기가 403입니다.
8. **제출 묶음:** `npm run bundle`의 자기 점검(`src/attack-check.mjs`)은 12단계부터 **배포 앱에 요청을 보내지 않습니다.** 심판이 묶음을 격리 환경(공개 HTTPS로 GET·HEAD만 허용)에서 다시 실행하고 실제로 나간 요청을 따로 기록하기 때문에, 로그인 없는·가짜 토큰·지어낸 서명 읽기 5건과 쓰기 4건(메모 추가·공지 수정·복원·기기 등록)은 `observed: "not_run"`, 계정·엔진이 필요한 나머지는 "미실행"으로 적습니다. 보내지 않은 요청에 결과를 적지 않습니다. 같은 정상·금지 요청의 실측은 `npm run ops:recheck`와 작전실 재확인 표에 남깁니다. 원본 API 점검만은 `SUPABASE_PUBLISHABLE_KEY=sb_publishable_… npm run bundle`처럼 공개용 키를 넘길 때 요청을 보내며, 키 없이 실행하면 미실행입니다.

## 출처와 설치·실행·중지·복구 안내 (12단계)

기준은 이 안내를 담은 **12단계 저장점 커밋**입니다(`npm run bundle`이 만든 `artifacts/submission.json`의 `commit` 값, 배포의 `/aleph.json` `commit` 값과 같아야 함). 아래 명령과 화면 이름은 그 커밋의 파일을 대조해 적었습니다. 비밀값(서버 전용 키, 비밀번호, 토큰, 기기 개인키)은 저장소·안내·제출 묶음 어디에도 넣지 않으며, 필요한 곳에는 **이름만** 적습니다.

### 누가 만든 것인가

| 출처 | 무엇 | 이 저장소에서의 위치 |
|---|---|---|
| **ALEPH SDP 엔진 사용** (운영 측 제공, 학생이 만들지 않음) | 로그인한 신원·확인된 기기·경로를 검증하고 판정 요청(`aleph.decision.v1`)을 학생 판정기에 전달, 미등록 기기 선차단, 탐지 사건 전달과 회수 집행, 심판 접수(`judgeIssuer`) | 저장소에 엔진 코드는 없습니다. 계약 문서 `docs/DECIDER_REQUEST.md`·`docs/DETECT_EVENTS.md`와 `aleph.config.json`의 `judgeIssuer`만 있습니다. 탐지 사건 전달·회수 집행은 이 자료실과 **연결·시험하지 않았습니다.** |
| **시작 틀 제공** (`ChoiTimo/aleph-defense-starter`, 첫 커밋 `c0c3653`) | 로그인 토큰 검사 `src/verify-login.mjs`(고치지 않음), 제출 묶음 `scripts/bundle.mjs`, 빌드 `scripts/build-public.mjs`·`deployment-identity.mjs`, 연습 틀 `scripts/decider-test.mjs`·`fixture-7.mjs`·`detect-test.mjs`(학생이 사례를 더함), `package/` 양식, 미구현 뼈대 `api/ai.js`·`api/threat-intel.js`(501), XDR 틀 `scripts/xdr-run.mjs`·`xdr/README.md` | 위 파일들. 판정기 `src/decider.mjs`·탐지기 `src/detect.mjs`·자기 점검 `src/attack-check.mjs`·화면 `public/index.html`은 시작 틀의 빈 틀을 학생이 채운 것입니다. |
| **학생 작업** | 자료 API·로그인 서버 함수 `api/notes.js`, `src/notes-handler.mjs`·`session-handler.mjs`·`notices-handler.mjs`·`resources.mjs`·`restore-handler.mjs`·`device-handler.mjs`·`ops-handler.mjs`·`policy-backup.mjs`, 판정기 규칙(`src/decider.mjs`), 탐지 규칙(`src/detect.mjs`), 접속 앱 화면(`public/index.html`·`manifest.webmanifest`·`icon.svg`·`recheck-cases.js`), DB SQL `supabase/*.sql`, 정책 사본 `policy-backup/`, 도구 `scripts/policy.mjs`·`recheck.mjs`, 시험 `test/*`, XDR 보너스 `xdr/*/` | 2단계부터 12단계까지의 커밋 |
| **외부 서비스** | Supabase(로그인·DB), Vercel(배포·서버 함수) | 계정과 설정은 학생이 직접 만들고, 값은 각 서비스의 비밀 입력란에만 넣습니다. |

### 1. 자료실 (서버 함수 + DB)

- **설치:** ① Supabase 프로젝트와 `notes` 테이블(2단계), A·B 시험 계정을 만듭니다. ② SQL Editor에서 `supabase/stage3-grants.sql` → `stage4-rls.sql` → `stage5-revoke.sql` → `stage10-restore-backup.sql` → `stage11-devices.sql`을 각 파일의 ①②③ 순서로 실행합니다. ③ Vercel 프로젝트에 이 저장소를 연결하고 환경변수 **이름** `SUPABASE_URL`, `SUPABASE_SECRET_KEY`(서버 전용), 선택 `INSTRUCTOR_USER_IDS`를 비밀 입력란에 넣은 뒤 배포합니다. ④ 로컬에서는 `npm install` 뒤 `npm test`가 통과해야 합니다.
- **실행:** 배포 주소(`aleph.config.json`의 `publicAppUrl`)를 엽니다. 로그인 → 화면의 기기 지문 확인 → SQL Editor에서 `stage11-devices.sql` ③으로 그 지문을 승인 → 「승인 다시 확인」 순서입니다.
- **중지:** 자료 제공을 바로 멈추려면 Vercel 환경변수에서 `SUPABASE_SECRET_KEY`를 지우고 다시 배포합니다. 자료 API는 503(`NOTES_NOT_CONFIGURED`)을 돌려주고 자료를 내주지 않습니다. 특정 기기만 막으려면 `stage11-devices.sql` ③의 `revoked` 문을 실행합니다.
- **복구:** 배포가 깨졌으면 Vercel의 이전 정상 배포로 되돌리거나, Git에서 문제 커밋을 `git revert`로 되돌린 뒤 다시 배포합니다(`reset --hard`는 쓰지 않음). 시험 계정 B의 메모 한 건은 `POST /api/restore`로 사본에서 되살립니다(위 「복구 뒤 다시 확인하는 순서」).

### 2. 학생 판정기 (`src/decider.mjs`)

- **설치:** 따로 설치하지 않습니다. 운영 측 ALEPH SDP 엔진이 이 저장소의 `decide(request)`를 불러 씁니다.
- **실행(연습):** `npm run decider:test`, `npm run fixture:7`. 둘 다 가상 요청이며 엔진의 실제 판정 기록이 아닙니다.
- **중지:** 학생 저장소에는 판정기를 끄는 스위치가 없습니다. 엔진 쪽 연결은 운영 측 몫입니다.
- **복구:** 판정기 규칙은 안전 정책 사본에 들어 있습니다. `npm run policy:diff`로 사본 해시를 검증한 뒤 Git 기록과 대조해 되돌립니다.

### 3. 탐지 규칙 (`src/detect.mjs`)

- **실행(연습):** `npm run detect:test`. 가상 사건만 넣습니다.
- **운영 연결:** 엔진의 사건 전달과 회수 집행은 연결되지 않았습니다. 탈환 작전실도 탐지 사건을 「미실행」으로 표시합니다.
- **중지·복구:** Git으로 이전 커밋의 파일을 되돌리고 `npm run detect:test`로 다시 확인합니다.

### 4. 접속 앱 (설치형 웹앱 + 기기 승인)

- **설치:** 배포 주소를 Chrome 등으로 열어 「앱 설치」를 고릅니다. 설치는 기기 승인이 아닙니다.
- **실행:** 앱 창에서 로그인하고 기기 승인을 받습니다. 토큰과 서명 키는 메모리에만 있어 새로 고치면 다시 로그인·승인합니다.
- **중지:** 로그아웃하거나 앱 창을 닫습니다. 기기를 더 믿지 않으려면 `revoked`로 바꿉니다.
- **복구:** 새로 로그인해 새 지문을 승인받습니다.

### 5. 탈환 작전실과 재확인 표

- **작전실:** 승인된 기기의 자료실 아래 「작전실 불러오기」를 누릅니다. `GET /api/ops` 응답을 그대로 보여 주며, 항목마다 실측·코드 기준·미실행이 표시됩니다.
- **재확인 표:** 계정 없이 보낼 수 있는 줄은 `npm run ops:recheck`로 보냅니다(결과는 `artifacts/recheck.json`, Git 제외). 로그인·승인 기기가 필요한 줄은 작전실의 「재확인 표 만들기」로 보냅니다. 엔진·계정 비밀값이 필요한 줄은 미실행으로 남습니다. 어느 쪽도 심판의 41종 판정이 아닙니다.
- **복원 감사 기록 0건의 뜻:** 작전실의 「복원 감사 기록」이 0건이면 실제 운영 DB에서 `POST /api/restore` 복원이 한 번도 실행되지 않았다는 뜻입니다. 2026-11-06 확인에서 서버 역할(`service_role`)로 기록 추가가 되고(되돌린 시험의 첫 번호가 1), B 메모가 사본과 같았으므로, 10단계 심판의 복원 시험은 심판 쪽 시험 환경에서 이루어지고 이 DB에는 닿지 않은 것으로 판단했습니다.

## 확인 방법

- 로그인 전: 시크릿 창에서 `/`를 열면 로그인 칸만 보이고 자료가 없어야 합니다. 주소창에서 `/api/notes`를 열면 401이어야 합니다.
- 로그인 후: A 계정으로 로그인하면 가상 메모가 보이고 메모를 추가·수정·삭제할 수 있어야 합니다. 로그아웃하면 화면이 로그인 칸으로 돌아가야 합니다.
- 틀린 비밀번호로 로그인하면 화면에 이유가 나와야 합니다.
- A로 로그인하면 A의 네 메모만, B로 로그인하면 B 시험 메모만 보여야 합니다. B가 A 메모 id로 `GET`·`PUT`·`DELETE`하면 404, 자기 메모의 주인을 바꾸는 `PUT`은 403이어야 합니다.
- 원본 직접 요청: publishable 키로 `/rest/v1/notes`를 직접 부르면 자료 없이 거부되어야 합니다(심판이 anon 키로 확인). `npm run bundle`의 자기 점검은 공개용 키를 넘겨 실행할 때만 같은 요청을 한 번 보내 결과를 기록합니다.
- 판정기 연습: `npm run fixture:7` 또는 `npm run decider:test`를 실행합니다. 정상 및 지역만 다른 사건은 허용되고, 야간·새 네트워크·대량 읽기의 복합 사건과 위조·누락 출처는 추가 확인으로 가야 합니다. 가상 연습 결과는 실제 접속 또는 심판 판정 증거가 아닙니다.
- 구역(8단계): 로그인 뒤 `/api/notices`와 본인 메모 `/api/notes/:id`는 200이고 응답 머리글 `x-resource-id`가 각각 `notice:list`, `note:<id>`여야 합니다. 로그인 없이 `/api/notices`는 401, 학생 계정으로 `PUT /api/notices/n-001`은 403 `NOT_INSTRUCTOR`, 남의 메모 id는 404여야 합니다.
- 화면 원본(Ctrl+U)에서 `sb_publishable`·`supabase`를 찾으면 0건이어야 합니다.
- 공개 파일 검색은 아래 한 줄입니다. 결과가 비어 있어야 정상입니다.
  `git grep -n -E "실습용 가상 (과제|포트폴리오|리추얼|행정) 기록" origin/main`

## 복구 뒤 다시 확인하는 순서 (10단계)

자료나 안전 정책을 되돌린 뒤 아래 순서대로 다시 실행합니다. "상태"에는 실제로 실행한 결과만 적고, 실행하지 않은 것은 **미실행**으로 둡니다. 토큰·비밀번호·키는 터미널이나 화면에 직접 입력하고 여기에 적지 않습니다.

**가. 사본부터 다시 읽어 검증합니다.** 사본이 없거나 해시가 다르면 복원하지 않고 멈춥니다.

| # | 할 일 | 정상 결과 | 상태 |
|---|---|---|---|
| 1 | `npm run policy:diff` | "사본 해시 검증: 통과 68fa0f04884e…", 복원할 버전 `safe-2026-11-06-57b2c50` | 2026-11-06 실행: 통과 |
| 2 | SQL Editor에서 `supabase/stage10-restore-backup.sql` ③ | 사본 한 건(`7cd005ec-…`, 주인 B), `sha_ok = true` | 2026-11-06 실행: `sha_ok = true` |

**나. 정책과 자료를 되돌립니다.**

| # | 할 일 | 정상 결과 | 상태 |
|---|---|---|---|
| 3 | `npm run policy:restore` (미리 보기) → 바뀔 항목 확인 → `npm run policy:restore -- --confirm=68fa0f04884e` | 시험 정책만 되돌리고 감사 기록에 한 줄 덧붙임, 복원 뒤 확인 네 줄 모두 통과 | 2026-11-06 실행: 시험 정책 `src/decider.mjs` 18행 복원, 재확인 4/4 통과 |
| 4 | B로 로그인한 화면의 개발자 도구에서 `POST /api/restore` (본문 없음, `Authorization: Bearer <B 토큰>`) | 200, `idMatches`·`ownerMatches`·`contentHashMatches` 모두 `true`, `beforeState`는 `tampered`·`deleted`·`unchanged` 중 하나 | 미실행 (배포 전) |
| 5 | 같은 요청을 A 토큰으로, 또 로그인 없이 | A는 403 `NOT_RESTORE_OWNER`, 로그인 없음은 401. 메모는 바뀌지 않음 | 미실행 (배포 전) |
| 6 | SQL Editor에서 `select count(*) from public.restore_audit;` | 4·5번 시도마다 한 줄씩 늘고, 이전 줄은 그대로 | 미실행 |

**다. 1~9단계의 정상·금지 요청을 다시 보냅니다.**

| # | 단계 | 정상 요청 (유지되어야 함) | 금지 요청 (다시 거부되어야 함) | 상태 |
|---|---|---|---|---|
| 7 | 1·2 | 배포 `/` 화면이 열림 | `/data.json` 404, 로그인 없이 `/api/notes` 401 | 미실행 (복구 뒤) |
| 8 | 3 | A 로그인 뒤 A 메모 목록이 보이고 추가·수정·삭제됨 | 가짜 토큰으로 `/api/notes` 401, 로그인 없이 `POST /api/notes` 401 | 미실행 (복구 뒤) |
| 9 | 4 | A가 자기 메모 `GET /api/notes/:id` 200 | B가 A 메모 id로 `GET`·`PUT`·`DELETE` 404, B가 자기 메모 주인을 바꾸는 `PUT` 403 | 미실행 (복구 뒤) |
| 10 | 5 | 서버 함수로 A 메모 읽기 200 | publishable 키로 `/rest/v1/notes` 직접 요청 시 자료 없음 | 미실행 (복구 뒤) |
| 11 | 6·7 | `npm run decider:test`, `npm run fixture:7`에서 등록 기기 정상 요청 `allow` | 미등록 기기 `deny`, 복합 이상 `step_up`, 불명확한 출처 `step_up` | 2026-11-06 실행: 25개 통과, fixture 7건 기대대로 |
| 12 | 8 | 로그인 뒤 `/api/notices` 200, 본인 메모 한 건 200 (`x-resource-id` 머리글) | 메모 전체 목록·공지 쓰기·강사 자료는 판정기 `deny`, 학생 계정 `PUT /api/notices/n-001` 403, 로그인 없이 `/api/notices` 401 | 판정기 부분 2026-11-06 실행: 통과(위 11번). 배포 API는 미실행 (복구 뒤) |
| 13 | 9 | `npm run detect:test`에서 정상 묶음 `observe` | 10분 안 121건·200건 폭주는 `propose_revocation` | 2026-11-06 실행: 6건 통과 |
| 14 | 전체 | `npm test` | (단위 시험 안의 거부 사례 포함) | 2026-11-06 실행: 66개 통과 |
| 15 | 전체 | `npm run bundle` 자기 점검의 실제 요청 | 로그인 없는 메모·공지·복원 요청과 가짜 토큰 요청이 모두 401 | 2026-11-06 실행(`9075192` 배포 뒤): 실제 요청 6건 모두 401. 12단계 재제출(`183823e`)부터 자기 점검은 요청을 보내지 않고 `not_run`으로 기록하므로, 같은 확인은 아래 `npm run ops:recheck`·작전실 재확인 표로 합니다. |

2026-11-06 12단계 작전실 재확인 표(`1776206` 배포, A 계정·승인 기기)로 위 표의 7·8·9(A 쪽)·11·12번 요청을 다시 보냈습니다: 첫 화면 200, `/data.json` 404, 로그인 없는 요청 401, 내 메모 목록 200, A가 B 메모 읽기 404, 공지 읽기 200, 학생 공지 수정 403, 서명 없음·다른 경로 서명 403(일치 17·불일치 0·미실행 5). 실제 메모를 변조·삭제한 뒤 복원하는 시험과 B 계정 토큰이 필요한 요청은 아직 보내지 않았습니다. 실제 메모를 변조·삭제한 뒤 복원하는 시험도 하지 않았습니다. 실행하면 위 표의 "상태"를 날짜와 실제 결과로 바꿉니다.

## 알려진 약점 (12단계 기준)

- 탈환 작전실의 탐지 사건은 운영 엔진과 연결되지 않아 항상 「미실행」입니다. 판정기 규칙도 코드 기준이며, 엔진이 실제로 내린 판정 기록은 이 서버에 없습니다.
- 작전실의 기기·복원 기록은 최근 50건만 셉니다. 그보다 오래된 기록은 SQL Editor에서 직접 확인해야 합니다.
- 재확인 표에서 B 계정 토큰이 필요한 공격, 공개용 키가 필요한 원본 API 점검, 엔진이 필요한 6·7·9단계, B 본인 복원은 미실행으로 남습니다.
- 제출 묶음의 자기 점검은 배포 앱에 요청을 보내지 않으므로, 묶음만 봐서는 실제 거부 결과를 알 수 없습니다. 실측은 `npm run ops:recheck`의 `artifacts/recheck.json`(Git 제외)과 작전실 재확인 표에만 있습니다.
- 12단계 통과는 41종 공격 전량 방어를 뜻하지 않습니다(상황실의 「잡은 괴물」 수는 따로 있음).

- 기기 서명 키는 탭 메모리에만 있어, 새로 고치거나 탭을 닫으면 새 기기로 다시 승인받아야 합니다. 승인 대기 줄이 계속 쌓이므로 오래된 줄은 SQL로 정리해야 합니다.
- 승인은 SQL Editor에서 지문을 눈으로 대조해 하는 수작업입니다. 다른 사람의 승인 대기 기기를 잘못 승인하지 않도록 `owner_id`도 함께 확인해야 합니다.
- 서명에 일회용 값(nonce)이 없어, 5분 안에 같은 요청을 그대로 다시 보내는 재전송은 막지 않습니다. 경로·본문·동작을 바꾼 요청은 막습니다.
- 복원 경로 `POST /api/restore`는 기기 서명 대상이 아니며, B 본인·심판 토큰 검사만 합니다.

- 메모 복원은 시험 계정 B의 한 건(`7cd005ec-…`)만 대상입니다. 다른 메모는 사본이 없어 되살릴 수 없습니다.
- 사본은 SQL을 실행한 시점의 상태입니다. 그 뒤 B가 정상적으로 고친 내용도 복원하면 사본 내용으로 돌아갑니다.
- 안전 정책 복원 도구는 시험 정책 사본만 되돌립니다. 운영 정책 파일이 바뀌면 Git 기록과 `policy:diff`로 확인하고 사람이 고쳐야 합니다.

- 탐지기는 회수를 제안만 합니다. 운영 반 엔진이 사건을 전달하고 제안을 집행하는 경로가 연결되지 않아, 실제로 회수된 신원·남은 세션의 재접속을 막는지는 시험하지 않았습니다.
- 탐지 규칙은 GET 폭주 하나뿐입니다. 느리게 오래 긁어 가는 조회(10분에 120건 이하)는 잡지 않습니다.

- 강사 공지는 코드 안의 가상 문구라 강사도 고칠 수 없습니다. 공지 저장소와 강사 관리 경로는 아직 없습니다.
- 강사 권한은 서버 환경변수의 사용자 UUID 목록에 달려 있어, 바꾸려면 Vercel 설정을 고치고 다시 배포해야 합니다.
- `/api/notices`는 내부적으로 `/api/notes?zone=notices`로 넘어가므로 그 쿼리 주소로도 같은 공지 API(로그인·권한 검사 포함)에 닿습니다. 판정기는 쿼리가 붙은 요청을 거부합니다.

- 토큰 검사는 서명과 만료를 확인합니다. 로그아웃해도 이미 발급된 토큰은 만료 전까지 검사를 통과할 수 있습니다.
- 브라우저에 refresh token을 주지 않으므로 접근 토큰이 만료되면(보통 1시간) 다시 로그인해야 합니다.
- 로그인 요청이 모두 Vercel 서버에서 Supabase로 가므로, Supabase의 IP별 로그인 횟수 제한을 여러 사용자가 함께 쓸 수 있습니다. 이 서버 함수에는 따로 횟수 제한이 없습니다.
- 접근 토큰은 페이지 메모리에만 있어 저장소에서 읽히지는 않지만, 화면에 스크립트 주입 약점이 생기면 같은 페이지 안에서는 여전히 쓰일 수 있습니다. 새로 고치면 로그인과 기기 승인을 다시 거쳐야 합니다.
- 주인이 없는(`owner_id`가 비어 있는) 메모는 이제 아무에게도 보이지 않습니다.
- 서버 함수는 서버 전용 키로 RLS를 거치지 않으므로, 자료 보호는 서버 함수의 로그인·소유자 검사에 달려 있습니다. 이 검사를 바꿀 때 특히 조심해야 합니다.
- 판정 계약의 `stepUp`에는 확인 여부와 인증 경과 시간만 있고 같은 로그인 세션의 재로그인 시각·요청 연결 정보가 없습니다. 따라서 확인 전 자료 차단과 새 로그인 뒤 재판정은 구현·실측하지 않았고, 이 단계에서는 가상 사건 규칙만 시험합니다.
- 과거 노출은 해소되지 않았습니다. 첫 커밋의 `data.json`과 1단계 옛 배포가 남아 있습니다.

## 확인 기록

직접 확인한 결과만 날짜와 함께 적으세요. 확인하지 않은 항목은 적지 않습니다.

- **2026-10-28 (2단계):** 배포의 `/api/notes`와 `/`에서 가상 메모 네 건이 보였고 `/data.json`은 404였습니다. `public.notes`는 메모 4건, `owner_id`는 `uuid`, 외래키 0개, RLS 켜짐이었습니다. 비밀 키 값은 출력하거나 기록하지 않았습니다.
- **2026-10-29 (3단계):** A 로그인 뒤 메모 네 건과 추가 칸이 보였고 로그아웃하면 로그인 칸만 남았습니다. 시크릿 창에서 로그인 없이 자료가 보이지 않았고 `/api/notes`는 `{"error":"UNAUTHORIZED"}`였습니다. A로 시험 메모를 추가·수정·삭제했습니다. 첫 화면 응답에 `X-Content-Type-Options: nosniff`가 있었고 페이지 원본에 `sb_secret`·`service_role`이 없었습니다.
- **2026-10-29 (4단계 DB):** SQL Editor에서 가상 메모 네 건의 주인이 A, B 시험 메모 한 건의 주인이 B로 확인되었습니다.
- **2026-10-29 (4단계 API·RLS):** 배포(`6a7345c`) 뒤 A는 A 메모 네 건만, B는 B 시험 메모 한 건만 보였고 A·B 모두 자기 메모를 추가·수정·삭제했습니다. B 토큰으로 A 메모 id에 `GET`·`PUT`·`DELETE`는 모두 404, B가 자기 메모의 `owner_id`를 바꾸는 `PUT`은 403이었습니다. RLS 적용 전 화면에서 확인한 anon 일곱 권한과 authenticated DELETE·INSERT는 false, 기존 정책 0개였고, 적용 후 anon은 모두 false, authenticated는 SELECT·INSERT·UPDATE·DELETE만 true, 정책은 `notes_*_own` 네 개였습니다.
- **2026-10-29 (5단계):** 브라우저 코드의 Supabase 직접 자료 호출은 원래 없었습니다. `public.notes` 권한 회수 전 authenticated는 SELECT·INSERT·UPDATE·DELETE가 true였고, 회수 후 public·anon·authenticated 21개 모두 false, service_role의 SELECT·INSERT·UPDATE·DELETE는 true였습니다. 회수 뒤 배포(`6141b8a`)에서 A가 메모를 읽고 추가·수정·삭제했고, `npm run bundle`의 anon 키 직접 요청은 401로 자료가 없었습니다.
- **5단계 가점(로그인 서버 이전):** (배포 뒤 A·B 로그인·로그아웃, 틀린 비밀번호 안내, 화면 원본의 키 0건을 확인한 뒤 여기에 적으세요.)
- **2026-11-03 (7단계 가상 판정기 연습):** `npm run fixture:7`에서 정상·지역 단독은 `allow`, 복합 이상·불명확한 출처·위조 헤더는 `step_up`이었습니다. `npm run decider:test`의 10개 가상 확인과 `npm test`의 41개 테스트, `npm run build -- --local`이 통과했습니다(야간 시간대 보정 `cd89d13` 뒤에도 다시 실행). 접속 정보의 출처가 `judge_fixture`가 아니거나 `headers` 같은 계약 밖 항목, 누락·형식 오류 신호가 있으면 모두 `step_up`이었습니다. 같은 로그인 재확인 계약이 없어 실제 자료 차단은 미실행입니다.
- **2026-11-06 (7단계 심판 재제출):** `62fe220` 제출은 심판 기록 코드 `S07_SAME_VERDICT`(지역 급변 사건에서 정상·복합 이상 판정이 같음)로 51점이었습니다. 연습 사건을 판정기 낱말로 바꿔 둔 탓에, 시작 틀의 `unusual`·`risk_signal` 사건이 `allow`로 빠진 것이 원인이었습니다. `e5e2710`에서 두 낱말을 받게 하자 정상과 복합 이상은 구분됐지만, 재확인한 복합 이상 요청이 `step_up`으로 남아 다시 불통과였습니다. `01867ec`에서 계약의 `stepUp` 재확인(0~900초)을 반영한 뒤 심판 판정은 「방어에 성공했습니다」, 100/100점(조건 7개, 완결성 가점 3개)이었습니다. 제출 전 `npm run fixture:7`, `npm run decider:test`(11개), `npm test`(41개)가 통과했습니다. 실제 자료 차단·재로그인은 여전히 미실행입니다.
- **2026-11-06 (8단계):** `005f714` 배포 뒤 `npm run bundle` 자기 점검에서 로그인 없는 메모 목록·추가, 가짜 토큰 목록, 로그인 없는 공지 목록·공지 수정이 모두 401이었습니다. 심판 판정은 「방어에 성공했습니다」, 100/100점(조건 5개, 완결성 가점 3개)으로 다른 구역 메모 조회·수정·목록 조회와 학생 계정의 강사 공지 수정이 모두 막혔습니다. 제출 전 `npm run decider:test`(25개), `npm test`(47개)가 통과했습니다.
- **2026-11-06 (9단계 가상 탐지 연습):** `npm run detect:test` 6건이 모두 통과했습니다(121건·200건 폭주는 `propose_revocation`, 나머지는 `observe`). `npm test` 54개와 `npm run decider:test` 25개도 통과했습니다. 운영 반 엔진의 사건 전달·회수 집행은 연결되지 않아 미실행입니다.
- **2026-11-06 (9단계):** `57b2c50` 배포 뒤 심판 판정은 「방어에 성공했습니다」, 100/100점(조건 4개, 완결성 가점 3개)이었습니다.
- **2026-11-06 (10단계 사본·복원 준비):** `npm run policy:snapshot`으로 안전 정책 사본(`safe-2026-11-06-57b2c50`, 해시 `68fa0f04884e…`)을 만들었습니다. 사본을 한 글자 바꾸면 `policy:diff`가 해시 불일치로 중단했고, 원래대로 두면 통과했습니다. 시험 정책(판정기 18행을 메모 전체 목록 허용으로 바꿈)을 `policy:restore`로 되돌린 뒤 재확인 4건(A 한 건 `allow`, 목록 `deny`, B의 A 메모 404, A 본인 200)이 통과하고 감사 기록에 한 줄이 남았습니다. SQL Editor에서 `stage10-restore-backup.sql` ①~③을 실행해 B 메모 한 건의 사본이 생겼고 `sha_ok = true`, anon·authenticated 권한은 모두 false였습니다. 실제 `POST /api/restore` 호출과 복구 뒤 배포 앱 재시험은 미실행입니다.
- **2026-11-06 (10단계):** `9075192` 배포 뒤 `npm run bundle` 자기 점검의 실제 요청 6건(로그인 없는 메모 목록·추가, 가짜 토큰, 로그인 없는 공지 목록·수정, 로그인 없는 `POST /api/restore`)이 모두 401이었습니다. 심판 판정은 「방어에 성공했습니다」, 100/100점(조건 5개, 완결성 가점 3개)으로 B 메모 변조·삭제 뒤 복구와 복구 직후 1~9단계 공격이 모두 막혔습니다.
- **2026-11-06 (11단계 기기 승인 준비):** `npm test` 71개가 통과했습니다(승인 기기 서명만 통과, 서명 없음·서명 뒤 경로·본문·동작 변경·승인 전·다른 사람 기기·만료 서명은 거부). HTTPS 브라우저에서 화면과 같은 방식으로 만든 서명을 서버 검증 코드에 넣어 원래 요청은 통과, 본문·경로를 바꾼 요청은 `DEVICE_SIGNATURE_INVALID`임을 확인했습니다. SQL Editor에서 `stage11-devices.sql` ①·②를 실행해 anon·authenticated 권한은 모두 false, service_role은 SELECT·INSERT만 true였습니다. 배포 화면에서 실제 기기를 승인해 자료실을 여는 확인은 미실행입니다.
- **2026-11-06 (11단계 배포 확인·심판):** `4352d66` 배포에서 A 계정으로 로그인하자 「승인 대기」와 기기 지문이 나오고 메모 0건, 나간 요청은 `/api/login`·`/api/devices`(201)뿐이었습니다. 탭을 새로 고치자 지문이 바뀌어 다시 승인 대기가 되었고, SQL로 새 지문을 승인한 뒤 「승인 다시 확인」에서 자료실이 열려 A 메모 4건이 보였습니다. 같은 로그인으로 서명 없이 보낸 `/api/notes`·`/api/notices`는 403 `DEVICE_SIGNATURE_REQUIRED`, 승인 지문에 지어낸 서명은 403 `DEVICE_SIGNATURE_INVALID`였습니다. 첫 제출(`4352d66`)은 로그인 토큰이 `sessionStorage`에 있어 `S11_KEY_EXPOSED`로 50점이었고, 세션을 메모리에만 두도록 고친 `1ae7fd6` 재제출은 「방어에 성공했습니다」, 100/100점(조건 6개, 완결성 가점 3개)이었습니다. 고친 뒤 배포 화면의 sessionStorage·localStorage·IndexedDB는 모두 비어 있었습니다.
- **2026-11-06 (12단계 재확인 명령):** `1ae7fd6` 배포에 `npm run ops:recheck`를 실행해 계정 없이 보낸 10줄이 모두 기대와 일치(첫 화면 200, `/data.json` 404, 나머지 금지 요청 401)했고 불일치 0, 미실행 12였습니다. 작전실 화면의 「재확인 표 만들기」와 `/api/ops` 실측은 12단계 저장점 배포 뒤 확인합니다.
- **2026-11-06 (12단계 작전실 실측):** `1776206` 배포에서 A 계정 로그인 뒤 승인 대기(메모 0건, 브라우저 저장소 비어 있음) → SQL 승인 → 자료실 열림(메모 4건)을 다시 확인했습니다. 「작전실 불러오기」(요청 ID `2837d278-…`, 05:53:20Z)는 판정기 규칙 5개·허용 경로 3개(코드 기준), 탐지 사건 없음(미실행), 기기 3건(승인 1·회수 1·대기 1, 실측), 안전 정책 `safe-2026-11-06-57b2c50`·`68fa0f04884e…`(코드 기준), B 메모 사본 해시 `35f71b938901…`(실측), 복원 감사 기록 0건(실측)을 보여 줬고, 기기 수치는 SQL로 한 승인·회수와 맞았습니다. 「재확인 표 만들기」는 22줄 중 일치 17·불일치 0·미실행 5였고 줄마다 Vercel 요청 ID와 확인 시각이 남았습니다. 감사 기록 0건은 SQL로 진단해 기록 권한 문제가 아니라 실제 DB에서 복원이 실행되지 않은 것으로 확인했습니다(위 「복원 감사 기록 0건의 뜻」).
- **2026-11-06 (12단계 심판):** `1776206` 첫 제출은 0점(`S12_BUNDLE_UNSUPPORTED`, 자기 점검의 POST·PUT 요청이 격리 환경에서 막힘), 쓰기 점검 4건을 `not_run`으로 바꾼 `84a2ff4`는 53점(`evidence_rejected`, 보낸 GET 5건의 결과를 문장으로 적음), 상태 코드로 바꾼 `93bbbf0`도 53점(`undecided`, 심판 기록에 그 5건의 요청이 없음), 그 5건도 보내지 않고 `not_run`으로 적은 `183823e`가 「방어에 성공했습니다」, 100/100점이었습니다. 심판은 이 통과가 41종 공격 전량 방어를 뜻하지는 않으며, 보완할 때 1~2단계 `anonymous_note_read`의 기대·실제 결과를 따로 기록하고 미실행을 막음 수에 넣지 말라고 안내했습니다.

`bundle-notes.json`과 `artifacts/submission.json`은 Git에서 무시되는 로컬 파일이며 커밋하지 않습니다. `npm run decider:test`와 `npm run detect:test`는 가상 연습이며 운영 심판 판정이 아닙니다.

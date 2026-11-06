-- 11단계: 기기 승인 상태를 서버 DB에 둡니다. 브라우저는 공개키만 보내고 "승인 대기"로 등록할 수 있을 뿐,
-- 승인(status = 'approved')은 이 SQL Editor처럼 서버 쪽에서만 바꿉니다. 서버 함수에는 UPDATE 권한을 주지 않습니다.
-- 이 파일에는 개인키·토큰·메모 본문·이메일이 없습니다. 공개키는 비밀값이 아닙니다.
-- 실행 방법: Supabase 대시보드 > SQL Editor에서 ①, ②를 한 번 실행하고, 기기를 승인할 때마다 ③을 실행합니다.

-- ① 기기 승인 테이블 만들기 (한 번) ---------------------------------------------
begin;

create table if not exists public.device_approvals (
  key_thumbprint text primary key check (key_thumbprint ~ '^[0-9a-f]{64}$'),
  owner_id uuid not null,
  public_key_jwk jsonb not null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  requested_at timestamptz not null default now(),
  decided_at timestamptz
);

alter table public.device_approvals enable row level security;
revoke all on table public.device_approvals from public, anon, authenticated;
revoke all on table public.device_approvals from service_role;
-- 서버 함수(service_role)는 읽기와 "승인 대기" 등록만 합니다. 승인·회수는 여기서 사람이 합니다.
grant select, insert on table public.device_approvals to service_role;

commit;

-- ② 권한 확인 -------------------------------------------------------------------
-- 정상: anon·authenticated는 모두 false, service_role은 SELECT·INSERT만 true.
select r.role, p.privilege,
       has_table_privilege(r.role, 'public.device_approvals', p.privilege) as allowed
from (values ('anon'), ('authenticated'), ('service_role')) as r(role)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) as p(privilege)
order by r.role, p.privilege;

-- ③ 기기 승인 (기기마다) ------------------------------------------------------------
-- 먼저 승인 대기 목록을 봅니다. 화면에 보이는 "기기 지문" 앞 12자리와 같은 줄인지 확인하세요.
select key_thumbprint, owner_id, status, requested_at
from public.device_approvals
order by requested_at desc
limit 20;

-- 확인한 기기만 승인합니다. '<기기 지문 64자>'를 위 목록의 key_thumbprint 값으로 바꿉니다.
-- update public.device_approvals
--    set status = 'approved', decided_at = now()
--  where key_thumbprint = '<기기 지문 64자>' and status = 'pending';

-- 기기를 더 믿을 수 없으면 회수합니다.
-- update public.device_approvals
--    set status = 'revoked', decided_at = now()
--  where key_thumbprint = '<기기 지문 64자>';

-- 10단계: 시험 계정 B의 가상 메모 한 건(7cd005ec-cbad-47d4-9100-3a48e0f04269)을 비공개 사본으로 남깁니다.
-- 복원 경로 POST /api/restore 는 이 사본에서 그 한 건만 되돌리고, 시도마다 restore_audit 에 한 줄씩 남깁니다.
-- 사본과 감사 기록 테이블은 RLS를 켜고 PUBLIC·anon·authenticated 권한을 주지 않아, 서버 전용 키(서버 함수)만 읽고 씁니다.
-- 이 파일에는 메모 본문·이메일·비밀 키가 없습니다. 본문은 DB 안의 사본 테이블에만 복사됩니다.
-- 실행 방법: Supabase 대시보드 > SQL Editor에서 ①, ②, ③을 하나씩 붙여 넣고 Run 합니다.
-- 내용 해시: SHA-256( title || 줄바꿈 || content ), 16진수. 서버 함수도 같은 방식으로 계산해 대조합니다.

-- ① 적용 전 확인 (아무것도 바꾸지 않음) ---------------------------------------
-- 대상 메모가 정확히 한 건, 주인이 B(a6a7947a-…)여야 합니다. 본문 대신 해시만 봅니다.
select id, owner_id,
       encode(sha256(convert_to(title || E'\n' || content, 'UTF8')), 'hex') as content_sha256
from public.notes
where id = '7cd005ec-cbad-47d4-9100-3a48e0f04269';

-- ② 적용 (한 묶음. 사본이 이미 있으면 덮어쓰지 않습니다) ------------------------
begin;

create table if not exists public.notes_restore_backup (
  id uuid primary key,
  owner_id uuid not null,
  title text not null,
  content text not null,
  content_sha256 text not null,
  captured_at timestamptz not null default now()
);

create table if not exists public.restore_audit (
  seq bigint generated always as identity primary key,
  at timestamptz not null default now(),
  note_id uuid not null,
  actor_kind text not null,
  before_state text not null,
  result text not null
);

alter table public.notes_restore_backup enable row level security;
alter table public.restore_audit enable row level security;
revoke all on table public.notes_restore_backup from public, anon, authenticated;
revoke all on table public.restore_audit from public, anon, authenticated;
-- 서버 함수는 사본을 읽기만 하고, 감사 기록은 덧붙이기(INSERT)와 읽기만 합니다.
revoke all on table public.notes_restore_backup from service_role;
revoke all on table public.restore_audit from service_role;
grant select on table public.notes_restore_backup to service_role;
grant select, insert on table public.restore_audit to service_role;

-- 침해 전 상태를 사본으로 남깁니다. 이미 사본이 있으면 그대로 둡니다(on conflict do nothing).
insert into public.notes_restore_backup (id, owner_id, title, content, content_sha256)
select id, owner_id, title, content,
       encode(sha256(convert_to(title || E'\n' || content, 'UTF8')), 'hex')
from public.notes
where id = '7cd005ec-cbad-47d4-9100-3a48e0f04269'
  and owner_id = 'a6a7947a-0843-4aa2-801f-0c0a9e15b616'
on conflict (id) do nothing;

commit;

-- ③ 적용 후 확인 (본문은 보지 않음) ----------------------------------------------
-- 정상: 사본 한 건, id·owner_id가 위와 같고 sha_ok가 true.
select id, owner_id, content_sha256, captured_at,
       content_sha256 = encode(sha256(convert_to(title || E'\n' || content, 'UTF8')), 'hex') as sha_ok
from public.notes_restore_backup;

-- 정상: anon·authenticated는 두 테이블 모두 false, service_role은 사본 SELECT와 감사 SELECT·INSERT만 true.
select t.tbl, r.role, p.privilege,
       has_table_privilege(r.role, t.tbl, p.privilege) as allowed
from (values ('public.notes_restore_backup'), ('public.restore_audit')) as t(tbl)
cross join (values ('anon'), ('authenticated'), ('service_role')) as r(role)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) as p(privilege)
order by t.tbl, r.role, p.privilege;

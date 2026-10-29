-- 4단계: public.notes 한 테이블에만 RLS와 최소 권한을 겁니다. 다른 테이블은 건드리지 않습니다.
-- 실행 방법: Supabase 대시보드 > SQL Editor에서 ①, ②, ③을 하나씩 붙여 넣고 Run 합니다.
-- 메모 본문, 이메일, 비밀 키는 들어 있지 않습니다.
-- 참고: 서버 함수는 서버 전용 키(service_role)로 접속하므로 RLS를 거치지 않습니다.
--       앱 API의 A/B 차단은 src/notes-handler.mjs의 소유자 검사가 맡고,
--       이 SQL은 publishable key로 DB에 직접 오는 요청을 막는 두 번째 벽입니다.

-- ① 적용 전 확인 (아무것도 바꾸지 않음) ---------------------------------------
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('anon', 'authenticated', 'PUBLIC')
order by grantee, privilege_type;

select r.role, p.privilege,
       has_table_privilege(r.role, 'public.notes', p.privilege) as allowed
from (values ('anon'), ('authenticated')) as r(role)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                   ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) as p(privilege)
order by r.role, p.privilege;

-- 이미 있는 정책 목록. 아래에서 만드는 네 정책 말고 다른 정책이 보이면 실행 전에 알려 주세요.
-- (허용 정책은 OR로 합쳐지므로, 넓은 정책이 하나 남아 있으면 아래 정책이 소용없어집니다.)
select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public' and tablename = 'notes';

-- ② 적용 (한 덩어리로 실행. 중간 오류가 나면 아무것도 바뀌지 않음) ----------------
begin;

alter table public.notes enable row level security;

revoke all on table public.notes from public, anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

-- 읽기·삭제: 기존 행의 주인이 본인일 때만 (USING)
create policy notes_select_own on public.notes
  for select to authenticated
  using ((select auth.uid()) = owner_id);

create policy notes_delete_own on public.notes
  for delete to authenticated
  using ((select auth.uid()) = owner_id);

-- 추가: 새 행의 주인이 본인일 때만 (WITH CHECK)
create policy notes_insert_own on public.notes
  for insert to authenticated
  with check ((select auth.uid()) = owner_id);

-- 수정: 기존 행도 본인 것(USING), 바뀐 새 행도 본인 것(WITH CHECK)
create policy notes_update_own on public.notes
  for update to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);

commit;

-- ③ 적용 후 확인 (①과 같은 질의) -------------------------------------------------
-- 정상: role_table_grants에 anon 행이 없고, authenticated는 DELETE·INSERT·SELECT·UPDATE 네 줄만.
--       has_table_privilege는 anon 전부 false, authenticated는 위 네 개만 true.
--       pg_policies에는 notes_*_own 네 정책만.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('anon', 'authenticated', 'PUBLIC')
order by grantee, privilege_type;

select r.role, p.privilege,
       has_table_privilege(r.role, 'public.notes', p.privilege) as allowed
from (values ('anon'), ('authenticated')) as r(role)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                   ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) as p(privilege)
order by r.role, p.privilege;

select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public' and tablename = 'notes';

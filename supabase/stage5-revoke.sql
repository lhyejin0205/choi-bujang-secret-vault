-- 5단계: public.notes 한 테이블에서 PUBLIC·anon·authenticated의 직접 권한을 모두 거둡니다.
-- 자료는 이제 서버 함수(/api/notes) 한곳으로만 오가며, 서버 함수는 서버 전용 키(service_role)로 접속합니다.
-- 다른 테이블, service_role 권한, RLS와 4단계 정책은 건드리지 않습니다.
-- 실행 방법: Supabase 대시보드 > SQL Editor에서 ①, ②, ③을 하나씩 붙여 넣고 Run 합니다.
-- 메모 본문, 이메일, 비밀 키는 들어 있지 않습니다.

-- ① 적용 전 확인 (아무것도 바꾸지 않음) ---------------------------------------
-- 4단계 상태라면 authenticated에 DELETE·INSERT·SELECT·UPDATE, service_role에 네 권한이 보입니다.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
order by grantee, privilege_type;

select r.role, p.privilege,
       has_table_privilege(r.role, 'public.notes', p.privilege) as allowed
from (values ('public'), ('anon'), ('authenticated'), ('service_role')) as r(role)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                   ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) as p(privilege)
order by r.role, p.privilege;

-- ② 적용 (한 묶음) -------------------------------------------------------------
begin;
revoke all on table public.notes from public, anon, authenticated;
commit;

-- ③ 적용 후 확인 (①과 같은 질의) -------------------------------------------------
-- 정상: role_table_grants에 PUBLIC·anon·authenticated 행이 없고 service_role 네 줄(또는 그 이상)만 남습니다.
--       has_table_privilege는 public·anon·authenticated 21줄 모두 false,
--       service_role은 SELECT·INSERT·UPDATE·DELETE가 true여야 서버 함수가 계속 작동합니다.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
order by grantee, privilege_type;

select r.role, p.privilege,
       has_table_privilege(r.role, 'public.notes', p.privilege) as allowed
from (values ('public'), ('anon'), ('authenticated'), ('service_role')) as r(role)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                   ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) as p(privilege)
order by r.role, p.privilege;

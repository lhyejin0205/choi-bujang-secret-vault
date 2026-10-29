-- 3단계: 서버 함수(service_role)가 메모를 추가·수정·삭제할 수 있게 권한을 줍니다.
-- 실행 방법: Supabase 대시보드 > SQL Editor에 붙여 넣고 Run을 한 번 누릅니다.
-- 메모 본문은 들어 있지 않습니다. 비밀 키도 들어 있지 않습니다.

grant select, insert, update, delete on table public.notes to service_role;

-- anon·authenticated에는 여전히 권한을 주지 않습니다. (이미 회수되어 있어도 다시 실행해도 됩니다.)
revoke all on table public.notes from anon, authenticated;

-- 확인: service_role에 네 권한이 보이고, anon·authenticated 행은 없어야 합니다.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'notes'
order by grantee, privilege_type;

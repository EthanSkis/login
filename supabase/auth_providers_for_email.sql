-- Returns the set of auth providers linked to an email address.
-- Called from the login page to tailor the "invalid credentials" message
-- (e.g. suggest GitHub when the account has no password).
--
-- Run once in the Supabase SQL editor for project qunobrixpnerocdntkio.
--
-- Trade-off: exposes "account exists" to anon callers. If enumeration is
-- a concern, move this behind an Edge Function with rate limiting/CAPTCHA.

create or replace function public.auth_providers_for_email(p_email text)
returns text[]
language sql
security definer
set search_path = public
as $$
  select coalesce(array_agg(distinct i.provider), '{}')
  from auth.users u
  join auth.identities i on i.user_id = u.id
  where lower(u.email) = lower(p_email);
$$;

revoke all on function public.auth_providers_for_email(text) from public;
grant execute on function public.auth_providers_for_email(text) to anon, authenticated;

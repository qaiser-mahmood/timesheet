-- ==============================================================================
-- Supabase Row-Level Security (RLS) Lockdown
-- Project: Anatolya Kebabs Staff & Sales Portal
-- 
-- PURPOSE:
-- Blocks all public anonymous reads and writes to sensitive business tables
-- (staff wages, roster hours, hourly sales, expenses, and transactions).
-- 
-- HOW TO RUN:
-- 1. Open your Supabase Dashboard: https://supabase.com/dashboard/project/ckyutsdgpdamnhsqoail
-- 2. In the left sidebar, click "SQL Editor".
-- 3. Click "+ New Query", paste all of the SQL below, and click "Run".
-- 4. In Render Dashboard (epos-sync-worker -> Environment):
--    Add an environment variable:
--    Key:   SUPABASE_SERVICE_ROLE_KEY
--    Value: <Paste your service_role secret key from Supabase Settings -> API>
-- ==============================================================================

-- 1. Enable Row Level Security on all sensitive business tables
ALTER TABLE IF EXISTS staff ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS roster ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS hourly_sales ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS expenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS raw_transactions ENABLE ROW LEVEL SECURITY;

-- 2. Revoke all public / anonymous direct permissions from tables
-- (The Supabase 'service_role' key automatically bypasses RLS and maintains full access)
REVOKE ALL ON staff FROM anon;
REVOKE ALL ON roster FROM anon;
REVOKE ALL ON hourly_sales FROM anon;
REVOKE ALL ON expenses FROM anon;
REVOKE ALL ON raw_transactions FROM anon;

-- ==============================================================================
-- VERIFICATION:
-- Check that RLS is now enabled (rowsecurity = true)
-- ==============================================================================
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public' 
  AND tablename IN ('staff', 'roster', 'hourly_sales', 'expenses', 'raw_transactions');

-- ==============================================================================
-- (OPTIONAL) ROLLBACK SCRIPT:
-- If you ever need to disable RLS and return to public access, run:
--
-- ALTER TABLE staff DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE roster DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE hourly_sales DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE expenses DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE raw_transactions DISABLE ROW LEVEL SECURITY;
-- ==============================================================================

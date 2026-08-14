-- Stage 3-only identity adjustment for the CSV import boundary.
-- The existing exact-commit image seeds Field Reports and Partner Signups.
UPDATE roles
SET permissions = ARRAY['subscribers:import']
WHERE id = (
    SELECT user_role_id FROM users WHERE username = 'ops-analyst'
);

UPDATE roles
SET permissions = ARRAY['list:get', 'list:manage']
WHERE parent_id = (
    SELECT list_role_id FROM users WHERE username = 'ops-analyst'
);

UPDATE users
SET password = 'ops-analyst-token-a7f3e9c15b4d', password_login = FALSE
WHERE username = 'ops-analyst';

SELECT l.id, l.name,
       CASE WHEN r.permissions @> ARRAY['list:manage']::text[]
            THEN 'attacker-managed' ELSE 'protected' END AS boundary
FROM lists l
LEFT JOIN roles r
  ON r.list_id = l.id
 AND r.parent_id = (
     SELECT list_role_id FROM users WHERE username = 'ops-analyst'
 )
WHERE l.name IN ('Field Reports', 'Partner Signups')
ORDER BY l.name;

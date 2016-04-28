WITH
CTE AS (
SELECT DISTINCT ON (ip_address)    
     da.ip_address, da.host_name, dos.description AS operating_system,     
     fa.scan_finished AS last_scanned, aos.certainty,aos.fingerprint_source_id,
CASE
WHEN (aos.certainty = 1) then sum(2-1)
ELSE sum(1-1)
END AS authenticated,

CASE
WHEN (aos.certainty >=0) then sum(2-1)
ELSE sum(1-1)
END AS total,
CASE
WHEN (asset_group_id = '2') then 'Group 1'
WHEN (asset_group_id = '29') then 'Group 2'
WHEN (asset_group_id = '25') then 'Group 3'
WHEN (asset_group_id = '56') then 'Group 4'
WHEN (asset_group_id = '55') then 'Group 5'
WHEN (asset_group_id = '40') then 'Group 6'
WHEN (asset_group_id = '4') then 'Group 7'
WHEN (asset_group_id = '66') then 'Group 8'
WHEN (asset_group_id = '28') then 'Group 9'
WHEN (asset_group_id = '26') then 'Group 10'
WHEN (asset_group_id = '8') then 'Group 11'
WHEN (asset_group_id = '27') then 'Group 12'
END AS asset_group
   
FROM fact_asset AS fa    
   JOIN dim_asset da USING (asset_id)    
   JOIN dim_operating_system dos USING (operating_system_id)    
   JOIN dim_asset_operating_system aos USING (asset_id)   
   JOIN dim_asset_group_asset daga USING (asset_id)

WHERE daga.asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66)

GROUP BY daga.asset_group_id, da.ip_address, da.host_name, dos.description, fa.scan_finished, aos.certainty, aos.fingerprint_source_id
ORDER BY da.ip_address ASC
)
SELECT asset_group, sum(authenticated) as authenticated, sum(total) as total, round(sum(authenticated)/sum(total),2) AS percentage_authenticated
FROM CTE
Group by asset_group

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
END AS total

   
FROM fact_asset AS fa    
   JOIN dim_asset da USING (asset_id)    
   JOIN dim_operating_system dos USING (operating_system_id)    
   JOIN dim_asset_operating_system aos USING (asset_id)    
GROUP BY da.ip_address, da.host_name, dos.description, fa.scan_finished, aos.certainty, aos.fingerprint_source_id
ORDER BY da.ip_address ASC
)
SELECT sum(authenticated) as authenticated, sum(total) as total, round(sum(authenticated)/sum(total),2) AS percentage_authenticated
FROM CTE

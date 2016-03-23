SELECT DISTINCT ON (ip_address)    
     da.ip_address, da.host_name, dos.description AS operating_system,     
     fa.scan_finished AS last_scanned, aos.certainty, fa.vulnerabilities, fa.riskscore    
FROM fact_asset AS fa    
   JOIN dim_asset da USING (asset_id)    
   JOIN dim_operating_system dos USING (operating_system_id)    
   JOIN dim_asset_operating_system aos USING (asset_id)    
ORDER BY da.ip_address, certainty DESC

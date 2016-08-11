WITH  
  open_ports AS (  
      SELECT asset_id, array_to_string(array_agg(dp.name || ':' || port ORDER BY port), ' , ') AS open_ports  
      FROM dim_asset_service  
        JOIN dim_protocol dp USING (protocol_id)  
      GROUP BY asset_id  
  )  

SELECT ip_address, mac_address, host_name , dos.description AS "operating_system",  open_ports,
  to_char(first_discovered, 'YYYY-mm-dd') as first_discovered, to_char(last_discovered, 'YYYY-mm-dd') as last_discovered, sites  
FROM fact_asset_discovery  
  JOIN dim_asset USING (asset_id)  
  JOIN dim_operating_system dos USING (operating_system_id)  
  JOIN open_ports USING (asset_id)
WHERE now() - first_discovered <= INTERVAL '1 days'
ORDER BY ip_address ASC

WITH
vuln_urls AS (
      SELECT vulnerability_id, array_to_string(array_agg(reference), ' , ') AS references
      FROM dim_vulnerability_reference 
      GROUP BY vulnerability_id
)


select da.ip_address, da.host_name, dos.description as operating_system, dv.title as vuln_title, round(dv.riskscore::numeric,0) as vuln_riskscore, 
CASE
WHEN (dv.riskscore >= 800) then 'Very High'
WHEN (dv.riskscore >= 600 AND dv.riskscore <= 799) then 'High'
WHEN (dv.riskscore >= 400 AND dv.riskscore <= 599) then 'Medium'
WHEN (dv.riskscore >= 200 AND dv.riskscore <= 399) then 'Low'
WHEN (dv.riskscore <= 199) then 'Very Low'
END AS vuln_severity,
proofastext(dv.description) as vuln_description, 
proofastext(favi.proof) as vuln_proof, vu.references, favi.port as "port# (-1 = n/a)", dv.date_added as vuln_date_into_nexpose, 
to_char(favi.date, 'YYYY-mm-dd') as asset_last_scan

FROM fact_asset_vulnerability_instance favi
JOIN dim_vulnerability dv USING (vulnerability_id)
JOIN dim_asset da USING (asset_id)
JOIN dim_operating_system dos USING (operating_system_id)
JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
JOIN vuln_urls vu USING (vulnerability_id)

ORDER BY dv.riskscore DESC

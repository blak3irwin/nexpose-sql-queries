SELECT da.ip_address, da.host_name, da.mac_address, 
CASE
WHEN (dta.tag_id = 1) THEN 'VH'
WHEN (dta.tag_id = 2) THEN 'H'
WHEN (dta.tag_id = 3) THEN 'M'
WHEN (dta.tag_id = 4) THEN 'L'
WHEN (dta.tag_id = 5) THEN 'VL'
WHEN (dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90) THEN 'NO RATING'
END AS asset_rating,

to_char(favf.date, 'YYYY-mm-dd') AS asset_last_scan,

dv.title AS vulnerability_title, dv.date_added AS vuln_first_scan, 
CASE
WHEN (dta.tag_id = 1) then round(2*dv.riskscore::numeric, 0)
WHEN (dta.tag_id = 2) then round(1.2*dv.riskscore::numeric, 0)
WHEN (dta.tag_id = 3) then round(1.1*dv.riskscore::numeric, 0)
WHEN (dta.tag_id = 4) then round(dv.riskscore::numeric, 0)
WHEN (dta.tag_id = 5) then round(.75*dv.riskscore::numeric, 0)
WHEN (dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90) then round(dv.riskscore::numeric, 0)
END AS weighted_riskscore,

   CASE
WHEN (now() - dv.date_added > INTERVAL '1 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 1201 ) OR
(dta.tag_id = 4 AND dv.riskscore >= 1201) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 1201 ) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 1201 )
)
) then 'URGENT'
WHEN (now() - dv.date_added > INTERVAL '7 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 900 AND 2*dv.riskscore <= 1200) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 900 AND 1.2*dv.riskscore <= 1200) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 900 AND 1.1*dv.riskscore <= 1200) OR
(dta.tag_id = 4 AND dv.riskscore >= 900 AND dv.riskscore <= 1200) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 900 AND .75*dv.riskscore <= 1200) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 900 AND dv.riskscore <= 1200)
)
) then 'CRITICAL'
WHEN (now() - dv.date_added > INTERVAL '14 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 600 AND 2*dv.riskscore <= 899) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 600 AND 1.2*dv.riskscore <= 899) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 600 AND 1.1*dv.riskscore <= 899) OR
(dta.tag_id = 4 AND dv.riskscore >= 600 AND dv.riskscore <= 899) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 600 AND .75*dv.riskscore <= 899) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 600 AND dv.riskscore <= 899)   
) 
) then 'HIGH'
WHEN (now() - dv.date_added > INTERVAL '30 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 300 AND 2*dv.riskscore <= 599) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 300 AND 1.2*dv.riskscore <= 599) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 300 AND 1.1*dv.riskscore <= 599) OR
(dta.tag_id = 4 AND dv.riskscore >= 300 AND dv.riskscore <= 599) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 300 AND .75*dv.riskscore <= 599) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 300 AND dv.riskscore <= 599)   
) 
) then 'MEDIUM'
WHEN (now() - dv.date_added > INTERVAL '90 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore <= 299) OR
(dta.tag_id = 2 AND  1.2*dv.riskscore <= 299) OR
(dta.tag_id = 3 AND  1.1*dv.riskscore <= 299) OR
(dta.tag_id = 4 AND  dv.riskscore <= 299) OR
(dta.tag_id = 5 AND  .75*dv.riskscore <= 299) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90  AND dv.riskscore <= 299)   
) 
) then 'LOW'
END AS vuln_severity   

FROM fact_asset_vulnerability_finding favf 
   JOIN dim_asset da USING (asset_id) 
   JOIN dim_operating_system dos USING (operating_system_id) 
   JOIN dim_vulnerability dv USING (vulnerability_id)
   JOIN dim_asset_group_asset daga USING (asset_id)
   JOIN dim_tag_asset dta USING (asset_id) 

WHERE daga.asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66) AND 

(

(
now() - dv.date_added > INTERVAL '1 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 1201 ) OR
(dta.tag_id = 4 AND dv.riskscore >= 1201) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 1201 ) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 1201 )
)
)

OR

(

now() - dv.date_added > INTERVAL '7 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 900 AND 2*dv.riskscore <= 1200) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 900 AND 1.2*dv.riskscore <= 1200) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 900 AND 1.1*dv.riskscore <= 1200) OR
(dta.tag_id = 4 AND dv.riskscore >= 900 AND dv.riskscore <= 1200) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 900 AND .75*dv.riskscore <= 1200) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 900 AND dv.riskscore <= 1200)
)

)

OR

(

now() - dv.date_added > INTERVAL '14 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 600 AND 2*dv.riskscore <= 899) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 600 AND 1.2*dv.riskscore <= 899) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 600 AND 1.1*dv.riskscore <= 899) OR
(dta.tag_id = 4 AND dv.riskscore >= 600 AND dv.riskscore <= 899) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 600 AND .75*dv.riskscore <= 899) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 600 AND dv.riskscore <= 899)   
) 


)

OR

(
now() - dv.date_added > INTERVAL '30 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 300 AND 2*dv.riskscore <= 599) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 300 AND 1.2*dv.riskscore <= 599) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 300 AND 1.1*dv.riskscore <= 599) OR
(dta.tag_id = 4 AND dv.riskscore >= 300 AND dv.riskscore <= 599) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 300 AND .75*dv.riskscore <= 599) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 300 AND dv.riskscore <= 599)   
)  

)

OR

(

now() - dv.date_added > INTERVAL '90 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore <= 299) OR
(dta.tag_id = 2 AND  1.2*dv.riskscore <= 299) OR
(dta.tag_id = 3 AND  1.1*dv.riskscore <= 299) OR
(dta.tag_id = 4 AND  dv.riskscore <= 299) OR
(dta.tag_id = 5 AND  .75*dv.riskscore <= 299) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90  AND dv.riskscore <= 299)   
)  
)


)

ORDER BY dv.riskscore DESC, da.ip_address ASC, dv.date_added DESC

WITH
CTE AS (

SELECT 
CASE
WHEN (daga.asset_group_id = '2') then 'Group 1'  
WHEN (daga.asset_group_id = '29') then 'Group 2'  
WHEN (daga.asset_group_id = '25') then 'Group 3'  
WHEN (daga.asset_group_id = '56') then 'Group 4'  
WHEN (daga.asset_group_id = '55') then 'Group 5'  
WHEN (daga.asset_group_id = '40') then 'Group 6'  
WHEN (daga.asset_group_id = '4') then 'Group 7'  
WHEN (daga.asset_group_id = '66') then 'Group 8'  
WHEN (daga.asset_group_id = '28') then 'Group 9'  
WHEN (daga.asset_group_id = '26') then 'Group 10'  
WHEN (daga.asset_group_id = '8') then 'Group 11'  
WHEN (daga.asset_group_id = '27') then 'Group 12' 
END AS asset_group, 
da.asset_id, da.ip_address, da.host_name, da.mac_address, 
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
WHEN 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 1201 ) OR
(dta.tag_id = 4 AND dv.riskscore >= 1201) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 1201 ) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 1201 )
)
then 'URGENT'
WHEN 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 900 AND 2*dv.riskscore <= 1200) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 900 AND 1.2*dv.riskscore <= 1200) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 900 AND 1.1*dv.riskscore <= 1200) OR
(dta.tag_id = 4 AND dv.riskscore >= 900 AND dv.riskscore <= 1200) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 900 AND .75*dv.riskscore <= 1200) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 900 AND dv.riskscore <= 1200)
)
then 'CRITICAL'
WHEN
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 600 AND 2*dv.riskscore <= 899) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 600 AND 1.2*dv.riskscore <= 899) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 600 AND 1.1*dv.riskscore <= 899) OR
(dta.tag_id = 4 AND dv.riskscore >= 600 AND dv.riskscore <= 899) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 600 AND .75*dv.riskscore <= 899) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 600 AND dv.riskscore <= 899)   
) 
then 'HIGH'
WHEN
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 300 AND 2*dv.riskscore <= 599) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 300 AND 1.2*dv.riskscore <= 599) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 300 AND 1.1*dv.riskscore <= 599) OR
(dta.tag_id = 4 AND dv.riskscore >= 300 AND dv.riskscore <= 599) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 300 AND .75*dv.riskscore <= 599) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 300 AND dv.riskscore <= 599)   
) 
then 'MEDIUM'

WHEN
(
(dta.tag_id = 1 AND 2*dv.riskscore <= 299) OR
(dta.tag_id = 2 AND  1.2*dv.riskscore <= 299) OR
(dta.tag_id = 3 AND  1.1*dv.riskscore <= 299) OR
(dta.tag_id = 4 AND  dv.riskscore <= 299) OR
(dta.tag_id = 5 AND  .75*dv.riskscore <= 299) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90  AND dv.riskscore <= 299)   
) 
then 'LOW'
END AS vuln_severity,

CASE
WHEN (dv.riskscore >=0) then sum(2-1)
END AS total_count,

CASE
WHEN (dv.riskscore >=0) then sum(1-1)
END AS high_to_urgent_count

FROM fact_asset_vulnerability_finding favf 
   JOIN dim_asset da USING (asset_id) 
   JOIN dim_operating_system dos USING (operating_system_id) 
   JOIN dim_vulnerability dv USING (vulnerability_id)
   JOIN dim_asset_group_asset daga USING (asset_id)
   JOIN dim_tag_asset dta USING (asset_id) 

WHERE daga.asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66) AND 

(

(
(dta.tag_id = 1 AND 2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 1201 ) OR
(dta.tag_id = 4 AND dv.riskscore >= 1201) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 1201 ) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 1201 )
)


OR


(
(dta.tag_id = 1 AND 2*dv.riskscore >= 900 AND 2*dv.riskscore <= 1200) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 900 AND 1.2*dv.riskscore <= 1200) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 900 AND 1.1*dv.riskscore <= 1200) OR
(dta.tag_id = 4 AND dv.riskscore >= 900 AND dv.riskscore <= 1200) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 900 AND .75*dv.riskscore <= 1200) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 900 AND dv.riskscore <= 1200)
)



OR


(
(dta.tag_id = 1 AND 2*dv.riskscore >= 600 AND 2*dv.riskscore <= 899) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 600 AND 1.2*dv.riskscore <= 899) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 600 AND 1.1*dv.riskscore <= 899) OR
(dta.tag_id = 4 AND dv.riskscore >= 600 AND dv.riskscore <= 899) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 600 AND .75*dv.riskscore <= 899) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 600 AND dv.riskscore <= 899)   
) 




OR

(
(dta.tag_id = 1 AND 2*dv.riskscore >= 300 AND 2*dv.riskscore <= 599) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 300 AND 1.2*dv.riskscore <= 599) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 300 AND 1.1*dv.riskscore <= 599) OR
(dta.tag_id = 4 AND dv.riskscore >= 300 AND dv.riskscore <= 599) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 300 AND .75*dv.riskscore <= 599) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 300 AND dv.riskscore <= 599)   
)  


OR


(
(dta.tag_id = 1 AND 2*dv.riskscore <= 299) OR
(dta.tag_id = 2 AND  1.2*dv.riskscore <= 299) OR
(dta.tag_id = 3 AND  1.1*dv.riskscore <= 299) OR
(dta.tag_id = 4 AND  dv.riskscore <= 299) OR
(dta.tag_id = 5 AND  .75*dv.riskscore <= 299) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90  AND dv.riskscore <= 299)   
)


)

GROUP BY da.asset_id, da.ip_address, da.host_name, da.mac_address, dv.title, dv.date_added, favf.date, dta.tag_id, dv.riskscore,asset_group_id






union all





SELECT 
CASE
WHEN (daga.asset_group_id = '2') then 'Group 1'  
WHEN (daga.asset_group_id = '29') then 'Group 2'  
WHEN (daga.asset_group_id = '25') then 'Group 3'  
WHEN (daga.asset_group_id = '56') then 'Group 4'  
WHEN (daga.asset_group_id = '55') then 'Group 5'  
WHEN (daga.asset_group_id = '40') then 'Group 6'  
WHEN (daga.asset_group_id = '4') then 'Group 7'  
WHEN (daga.asset_group_id = '66') then 'Group 8'  
WHEN (daga.asset_group_id = '28') then 'Group 9'  
WHEN (daga.asset_group_id = '26') then 'Group 10'  
WHEN (daga.asset_group_id = '8') then 'Group 11'  
WHEN (daga.asset_group_id = '27') then 'Group 12' 
END AS asset_group, 
da.asset_id, da.ip_address, da.host_name, da.mac_address, 
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

WHEN 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 1201 ) OR
(dta.tag_id = 4 AND dv.riskscore >= 1201) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 1201 ) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 1201 )
)
then 'URGENT'
WHEN 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 900 AND 2*dv.riskscore <= 1200) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 900 AND 1.2*dv.riskscore <= 1200) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 900 AND 1.1*dv.riskscore <= 1200) OR
(dta.tag_id = 4 AND dv.riskscore >= 900 AND dv.riskscore <= 1200) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 900 AND .75*dv.riskscore <= 1200) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 900 AND dv.riskscore <= 1200)
)
then 'CRITICAL'
WHEN
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 600 AND 2*dv.riskscore <= 899) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 600 AND 1.2*dv.riskscore <= 899) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 600 AND 1.1*dv.riskscore <= 899) OR
(dta.tag_id = 4 AND dv.riskscore >= 600 AND dv.riskscore <= 899) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 600 AND .75*dv.riskscore <= 899) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 600 AND dv.riskscore <= 899)   
) 
then 'HIGH'
END AS vuln_severity,

CASE
WHEN (dv.riskscore >=0) then sum(1-1)
END AS total_count,

CASE
WHEN (dv.riskscore >=0) then sum(2-1)
END AS med_low_count



FROM fact_asset_vulnerability_finding favf 
   JOIN dim_asset da USING (asset_id) 
   JOIN dim_operating_system dos USING (operating_system_id) 
   JOIN dim_vulnerability dv USING (vulnerability_id)
   JOIN dim_asset_group_asset daga USING (asset_id)
   JOIN dim_tag_asset dta USING (asset_id) 

WHERE daga.asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66) AND 

(

(
(dta.tag_id = 1 AND 2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 1201 ) OR
(dta.tag_id = 4 AND dv.riskscore >= 1201) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 1201 ) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 1201 )
)


OR


(
(dta.tag_id = 1 AND 2*dv.riskscore >= 900 AND 2*dv.riskscore <= 1200) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 900 AND 1.2*dv.riskscore <= 1200) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 900 AND 1.1*dv.riskscore <= 1200) OR
(dta.tag_id = 4 AND dv.riskscore >= 900 AND dv.riskscore <= 1200) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 900 AND .75*dv.riskscore <= 1200) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 900 AND dv.riskscore <= 1200)
)



OR


(
(dta.tag_id = 1 AND 2*dv.riskscore >= 600 AND 2*dv.riskscore <= 899) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 600 AND 1.2*dv.riskscore <= 899) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 600 AND 1.1*dv.riskscore <= 899) OR
(dta.tag_id = 4 AND dv.riskscore >= 600 AND dv.riskscore <= 899) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 600 AND .75*dv.riskscore <= 899) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 600 AND dv.riskscore <= 899)   
) 


)

GROUP BY da.asset_id, da.ip_address, da.host_name, da.mac_address, dv.title, dv.date_added, favf.date, dta.tag_id, dv.riskscore,asset_group_id

),

STEP_2 AS (
SELECT DISTINCT ON (asset_id, total_count,  high_to_urgent_count)
*
FROM CTE
)

SELECT asset_group, SUM(total_count)as TOTAL_COUNT, SUM(total_count) - SUM(high_to_urgent_count) AS LOW_MED_ONLY_COUNT, round((SUM(total_count) - SUM(high_to_urgent_count)) / SUM(total_count),4) AS PERCENTAGE_ONLY_LOW_MED
FROM STEP_2
GROUP BY asset_group

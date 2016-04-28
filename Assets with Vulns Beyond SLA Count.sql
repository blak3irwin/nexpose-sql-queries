WITH
CTE AS (

SELECT
favf.asset_id, 
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
END AS asset_group, 

count (favf.vulnerability_instances) AS Urgent_beyond_SLA, 

CASE
WHEN (1=1) then sum(1-1)
END AS Critical_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS High_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS Medium_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS Low_beyond_SLA


FROM fact_asset_vulnerability_finding favf 
   JOIN dim_vulnerability dv USING (vulnerability_id) 
   JOIN dim_asset_group_asset daga USING (asset_id)
   JOIN dim_tag_asset dta USING (asset_id)
WHERE daga.asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66) AND now() - dv.date_added > INTERVAL '1 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 1201 ) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 1201 ) OR
(dta.tag_id = 4 AND dv.riskscore >= 1201) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 1201 ) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 1201 )
)
GROUP BY daga.asset_group_id, favf.asset_id




union all




SELECT
favf.asset_id, 
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
END AS asset_group, 

CASE
WHEN (1=1) then sum(1-1)
END AS Urgent_beyond_SLA,

count (favf.vulnerability_instances) AS Critical_beyond_SLA, 

CASE
WHEN (1=1) then sum(1-1)
END AS High_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS Medium_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS Low_beyond_SLA


FROM fact_asset_vulnerability_finding favf 
   JOIN dim_vulnerability dv USING (vulnerability_id) 
   JOIN dim_asset_group_asset daga USING (asset_id)
   JOIN dim_tag_asset dta USING (asset_id)
   
WHERE daga.asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66) AND now() - dv.date_added > INTERVAL '7 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 900 AND 2*dv.riskscore <= 1200) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 900 AND 1.2*dv.riskscore <= 1200) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 900 AND 1.1*dv.riskscore <= 1200) OR
(dta.tag_id = 4 AND dv.riskscore >= 900 AND dv.riskscore <= 1200) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 900 AND .75*dv.riskscore <= 1200) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 900 AND dv.riskscore <= 1200)
)

GROUP BY daga.asset_group_id, favf.asset_id





union all




SELECT 
favf.asset_id,
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
END AS asset_group, 

CASE
WHEN (1=1) then sum(1-1)
END AS Urgent_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS Critical_beyond_SLA,

count (favf.vulnerability_instances) AS High_beyond_SLA, 

CASE
WHEN (1=1) then sum(1-1)
END AS Medium_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS Low_beyond_SLA


FROM fact_asset_vulnerability_finding favf 
   JOIN dim_vulnerability dv USING (vulnerability_id) 
   JOIN dim_asset_group_asset daga USING (asset_id)
   JOIN dim_tag_asset dta USING (asset_id)

WHERE daga.asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66) AND now() - dv.date_added > INTERVAL '14 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 600 AND 2*dv.riskscore <= 899) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 600 AND 1.2*dv.riskscore <= 899) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 600 AND 1.1*dv.riskscore <= 899) OR
(dta.tag_id = 4 AND dv.riskscore >= 600 AND dv.riskscore <= 899) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 600 AND .75*dv.riskscore <= 899) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 600 AND dv.riskscore <= 899)   
) 
GROUP BY daga.asset_group_id, favf.asset_id






union all





SELECT 
favf.asset_id,
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
END AS asset_group, 

CASE
WHEN (1=1) then sum(1-1)
END AS Urgent_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS Critical_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS High_beyond_SLA,

count (favf.vulnerability_instances) AS Medium_beyond_SLA, 

CASE
WHEN (1=1) then sum(1-1)
END AS Low_beyond_SLA


FROM fact_asset_vulnerability_finding favf 
   JOIN dim_vulnerability dv USING (vulnerability_id) 
   JOIN dim_asset_group_asset daga USING (asset_id)
   JOIN dim_tag_asset dta USING (asset_id)
   
WHERE daga.asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66) AND now() - dv.date_added > INTERVAL '30 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore >= 300 AND 2*dv.riskscore <= 599) OR
(dta.tag_id = 2 AND 1.2*dv.riskscore >= 300 AND 1.2*dv.riskscore <= 599) OR
(dta.tag_id = 3 AND 1.1*dv.riskscore >= 300 AND 1.1*dv.riskscore <= 599) OR
(dta.tag_id = 4 AND dv.riskscore >= 300 AND dv.riskscore <= 599) OR
(dta.tag_id = 5 AND .75*dv.riskscore >= 300 AND .75*dv.riskscore <= 599) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90 AND dv.riskscore >= 300 AND dv.riskscore <= 599)   
)  

GROUP BY daga.asset_group_id, favf.asset_id





union all




SELECT 
favf.asset_id,
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
END AS asset_group, 

CASE
WHEN (1=1) then sum(1-1)
END AS Urgent_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS Critical_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS High_beyond_SLA,

CASE
WHEN (1=1) then sum(1-1)
END AS Medium_beyond_SLA,

count (favf.vulnerability_instances) AS Low_beyond_SLA


FROM fact_asset_vulnerability_finding favf 
   JOIN dim_vulnerability dv USING (vulnerability_id) 
   JOIN dim_asset_group_asset daga USING (asset_id)
   JOIN dim_tag_asset dta USING (asset_id)

WHERE daga.asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66) AND now() - dv.date_added > INTERVAL '90 days' AND 
(
(dta.tag_id = 1 AND 2*dv.riskscore <= 299) OR
(dta.tag_id = 2 AND  1.2*dv.riskscore <= 299) OR
(dta.tag_id = 3 AND  1.1*dv.riskscore <= 299) OR
(dta.tag_id = 4 AND  dv.riskscore <= 299) OR
(dta.tag_id = 5 AND  .75*dv.riskscore <= 299) OR
(dta.tag_id NOT IN (1,2,3,4,5)  AND dta.tag_id = 90  AND dv.riskscore <= 299)   
)  

GROUP BY daga.asset_group_id, favf.asset_id

),

STEP_2 AS (
SELECT DISTINCT ON (asset_group, asset_id)
asset_group, asset_id
FROM CTE
GROUP BY asset_group, asset_id
ORDER BY asset_group ASC, asset_id
),
STEP_3 AS (
SELECT
asset_group, asset_id, sum(2-1)
FROM STEP_2
GROUP BY asset_group, asset_id
ORDER BY asset_group ASC, asset_id
)

SELECT
asset_group, sum(sum)
FROM STEP_3
GROUP BY asset_group
ORDER BY asset_group DESC

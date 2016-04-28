WITH CTE AS (
SELECT 
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
END AS asset_group, assets, vulnerabilities, round(riskscore::numeric,0) as riskscore
FROM fact_asset_group

WHERE asset_group_id IN (2,4,8,25,26,27,28,29,40,55,56,66)

)
SELECT *
FROM CTE
Order by asset_group DESC

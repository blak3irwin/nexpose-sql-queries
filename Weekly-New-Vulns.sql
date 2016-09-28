WITH
   today_date AS (
      SELECT now() AS date
   ),
   asset_scans AS (
      SELECT asset_id, scanAsOfDate(asset_id, now()::date) AS scan_today, scanAsOfDate(asset_id, ((SELECT date FROM today_date) - INTERVAL '1 week')::date) AS scan_week_ago
      FROM dim_asset
   ),
   asset_scan_results AS (
      -- results from the scan on each asset for today's results
      SELECT fasvf.asset_id, fasvf.vulnerability_id, fasvf.scan_id, 2 AS state
      FROM fact_asset_scan_vulnerability_finding fasvf
         JOIN asset_scans a ON a.asset_id = fasvf.asset_id AND fasvf.scan_id = a.scan_today
      UNION ALL
      -- results from the scan on each asset for the results one week ago
      SELECT fasvf.asset_id, fasvf.vulnerability_id, fasvf.scan_id, 1 AS state
      FROM fact_asset_scan_vulnerability_finding fasvf
         JOIN asset_scans a ON a.asset_id = fasvf.asset_id AND fasvf.scan_id = a.scan_week_ago
   ),
   asset_scan_results_diff AS (
      SELECT asset_id, vulnerability_id, baselineComparison(state, 2) AS diff
      FROM asset_scan_results
      GROUP BY asset_id, vulnerability_id
   )
SELECT da.ip_address, da.host_name, da.mac_address, asrd.diff, dv.title AS vulnerability_title, to_char(now(), 'YYYY-mm-dd') AS current_date
FROM asset_scan_results_diff asrd
   JOIN dim_asset da USING (asset_id)
   JOIN dim_vulnerability dv USING (vulnerability_id)
WHERE asrd.diff = 'New'
ORDER BY da.ip_address, asrd.diff, dv.title

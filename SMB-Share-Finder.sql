select da.ip_address, da.host_name, dos.description, daf.type, daf.name, da.sites
from dim_asset da
   JOIN dim_asset_file daf using (asset_id)
   JOIN dim_operating_system dos USING (operating_system_id)  
order by da.ip_address asc

# Snap Collector plugin - Nginx
This Collector fetches nginx metrics for SNAP telemtry framework.

Forked from (Also documentation for running this plugin):
https://github.com/Staples-Inc/snap-plugin-collector-nginx

Checking whether nginx status module is working properly:
https://mathias-kettner.de/checkmk_check_nginx_status.html

# Troubleshoot
If you got error for not having some libraries, run following command in the repo folder:

``` 
  go get ./...
```

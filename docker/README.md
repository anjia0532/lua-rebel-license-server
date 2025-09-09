# Run with docker

```bash
docker run -d -p80:80 --name openresty  --rm -v $(pwd)/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf  openresty/openresty:alpine-fat
docker exec openresty opm get anjia0532/lua-rebel-license-server
docker exec openresty openresty -s reload
```

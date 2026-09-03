# nginx TLS certs

`cert.pem` / `key.pem` здесь — **самоподписанная заглушка**, только чтобы
nginx стартовал. Реальный трафик она не обслуживает: до перехода на прямой
proxied (Obsidian `23_План_переход_на_статический_IP`) порт 443 снаружи не
используется — DNS `animemory.ru` ещё на Cloudflare Tunnel (cloudflared -> nginx:80).

На проде подменяется настоящим **Cloudflare Origin Certificate**:
1. Cloudflare -> SSL/TLS -> Origin Server -> Create Certificate
   (hostnames: `animemory.ru`, `*.animemory.ru`).
2. Положить `cert.pem` + `key.pem` в
   `C:\Users\mishg\Desktop\Ancen\deploy\nginx\certs\` (персистентная папка).
3. В серверном `.env`: `NGINX_CERTS_DIR=C:/Users/mishg/Desktop/Ancen/deploy/nginx/certs`
4. Cloudflare -> SSL/TLS -> Overview -> режим **Full (strict)**.
5. Cloudflare -> DNS: заменить CNAME на туннель A-записью -> статический IP, Proxied.
6. Cloudflare -> Rules -> Origin Rules: destination port -> `8443`.

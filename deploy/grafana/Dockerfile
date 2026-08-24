FROM grafana/grafana:13.1.4

# MAX (мессенджер) API использует TLS-сертификат, выпущенный российским
# национальным УЦ (Минцифры), которого нет в базовом доверенном хранилище
# образа — без него Grafana Alerting не может отправить webhook в MAX
# ("x509: certificate signed by unknown authority").
USER root
COPY ca-certs/*.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
USER grafana

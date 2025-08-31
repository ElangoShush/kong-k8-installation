Kong Gateway (Enterprise) + Postgres on Kubernetes (K3s/Rancher HelmController)

This repo installs Kong Gateway Enterprise backed by Postgres and exposes:

Proxy: 32080 (HTTP), 32443 (HTTPS)

Admin API: 32081 (HTTP), 32441 (HTTPS)

Manager UI: 30516 (HTTP), 30952 (HTTPS)

It also includes an overlay to set environment-specific admin_gui_api_url and admin_gui_url without hard-coding IPs in the base config.

Prerequisites

kubectl configured for your cluster (K3s recommended).

Rancher Helm Controller CRDs available (helm.cattle.io/v1).

Namespace:

kubectl create ns kong


Kong Enterprise license.json file (do not commit it to git).

1) Install Postgres (Bitnami)
# From repo root
kubectl apply -n kong -k apps/postgres/on-perm

# Wait for Postgres
kubectl -n kong rollout status statefulset/kong-pg-postgresql --timeout=5m

# Inspect
kubectl -n kong get pods,svc -l app.kubernetes.io/name=postgresql

Quick DB test
kubectl -n kong run psql-client --rm -it --image=postgres:15 --restart=Never \
  --env=PGPASSWORD=supersecret-kong -- \
  psql "host=kong-pg-postgresql.kong.svc.cluster.local port=5432 dbname=kong user=kong" \
  -c "select now(), current_user, current_database();"

# Add the Enterprise License

From the folder containing license.json:

kubectl -n kong create secret generic kong-enterprise-license \
  --from-file=license=./license.json

# Install Kong Gateway Enterprise

In the folder containing apps/kong/on-perm/deployment-patch.yaml (HelmChart) configures:
  1. Enterprise image kong/kong-gateway
  2. External Postgres connection
  3. NodePorts for Proxy/Admin/Manager
  4. Migrations enabled

Apply:

kubectl apply -n kong -k apps/kong/on-perm
kubectl -n kong rollout status deploy/kong-kong --timeout=5m

# First-time DB bootstrap (if you see “Database needs bootstrapping”)
kubectl -n kong apply -f - <<'EOF'
apiVersion: batch/v1
kind: Job
metadata:
  name: kong-ee-bootstrap-once
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: bootstrap
        image: kong/kong-gateway:3.9
        env:
        - { name: KONG_DATABASE, value: "postgres" }
        - { name: KONG_PG_HOST, value: "kong-pg-postgresql.kong.svc.cluster.local" }
        - { name: KONG_PG_DATABASE, value: "kong" }
        - { name: KONG_PG_USER, value: "kong" }
        - { name: KONG_PG_PASSWORD, value: "supersecret-kong" }
        command: ["sh","-lc","kong migrations bootstrap -v || (echo already bootstrapped; exit 0)"]
        volumeMounts: [{ name: license, mountPath: /etc/kong }]
      volumes:
      - name: license
        secret:
          secretName: kong-enterprise-license
          items: [{ key: license, path: license.json }]
EOF

# Health Check 
kubectl -n kong logs -f job/kong-ee-bootstrap-once
kubectl -n kong delete job kong-ee-bootstrap-once
kubectl -n kong rollout restart deploy/kong-kong
kubectl -n kong rollout status deploy/kong-kong --timeout=5m

# Manager Ednpoint
curl -I http://<NODE_PUBLIC_IP>:30516/workspaces

# Proxy Endpoint
curl -I https://<NODE_PUBLIC_IP>:32080/



# Deploy Redis
kubectl apply -k ts43-redis/k8s/on-perm
kubectl -n kong get pods,svc | grep ts43-redis


# docker build and push TS43 Authe code Image to sherlock-004:
cd kong-k8-installation/ts43-auth/app

sudo docker buildx build \
  --platform linux/amd64 \
  -t us-central1-docker.pkg.dev/sherlock-004/ts43/ts43-authcode:v2 \
  --push .

# Deploy TS43 AUth Code  Image
cd kong-k8-installation/
kubectl apply -k ts43-auth/k8s/on-perm
kubectl -n kong get deploy,po,svc | grep ts43-auth


# check the Kong Ingress 
kubectl -n kong get ingress ts43-auth

you should get like this:
    NAME        CLASS   HOSTS   ADDRESS        PORTS   AGE
    ts43-auth   kong    *       10.43.239.88   80      50s


Deploy TS 43 Endpoint to KONG:
# dry-run
helm upgrade --install ts43-config ./charts/ts43-config -n kong --debug --dry-run

# apply & wait
helm upgrade --install ts43-config ./charts/ts43-config -n kong


# Check the Service type 
kubectl -n kong get svc ts43-auth-backend

NAME                TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE
ts43-auth-backend   ClusterIP   10.43.95.105   <none>        80/TCP    5h8m

10.43.95.105  -> this is ip for the service ( which is via this can reach the authcode microservice)






# TOOLS:
1. Kong runtime log:
    kubectl logs kong-kong-666dc66497-xdjpt --follow -n kong
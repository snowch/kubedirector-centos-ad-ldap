# kubedirector-centos-ad-ldap

```
kubectl -n non-mlops apply -f https://raw.githubusercontent.com/snowch/kubedirector-centos-ad-ldap/main/cr-app-centos.json
```

- In the UI provision a centos 7 cluster with `hpecp-ext-auth-secret`

```
...
spec: 
  ...
  connections: 
    secrets: [
      hpecp-ext-auth-secret
    ]
```

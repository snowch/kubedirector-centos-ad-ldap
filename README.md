# kubedirector-centos-ad-ldap

```
kubectl -n your-ns apply -f https://raw.githubusercontent.com/snowch/kubedirector-centos-ad-ldap/main/cr-app-centos.json
```

- Ensure your tenant has external authentication configured with an AD/LDAP group
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

# kubedirector-centos-ad-ldap

Note that this application is currently hard-coded to the controller IP address for my environment.  This will be rectified within a few days.

https://github.com/snowch/kubedirector-centos-ad-ldap/blob/main/appconfig/startscript#L19-L20

Setup notes:

- SSH to controller then

```
sudo cat > /var/www/html/thirdparty/auth.py 
[[paste auth.py]]
^C
```

```
sudo cat > /var/www/html/thirdparty/auth.props
[[paste auth.props]]
^C
```

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

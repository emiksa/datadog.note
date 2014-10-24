##準備

####配置

```
cd /etc/dd-agent/checks.d
wget https://raw.githubusercontent.com/mar3/datadog.note/master/code.example/checks/usertraffic/usertraffic.py
chown dd-agent:dd-agent usertraffic.py

cd /etc/dd-agent/conf.d
wget https://raw.githubusercontent.com/mar3/datadog.note/master/code.example/checks/usertraffic/usertraffic.yaml
chown dd-agent usertraffic.yaml
```

テストを必ず実施

```
# /etc/init.d/datadog-agent configtest
```

####sudoers の編集

```
# visudo
```

↓追記

```
dd-agent ALL=(ALL) NOPASSWD: /sbin/iptables*
```

requiretty は off

```
#Defaults    requiretty
```


##実行

必ず(再)起動

```
# service datadog-agent restart
```

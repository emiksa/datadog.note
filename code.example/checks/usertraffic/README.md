##setting

placing.

```
cd /etc/dd-agent/checks.d
wget https://raw.githubusercontent.com/mar3/datadog.note/master/code.example/checks/usertraffic/usertraffic.py
chown dd-agent:dd-agent usertraffic.py

cd /etc/dd-agent/conf.d
wget https://raw.githubusercontent.com/mar3/datadog.note/master/code.example/checks/usertraffic/usertraffic.yaml
chown dd-agent usertraffic.yaml
```

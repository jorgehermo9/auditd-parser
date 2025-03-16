
# Bugs

This is wrongly parsed
`type=SYSTEM_SHUTDOWN msg=audit(1724505854.498:44): pid=446051 uid=0 auid=4294967295 ses=4294967295 msg=' comm="systemd-update-utmp" exe="/usr/lib/systemd/systemd-update-utmp" hostname=? addr=? terminal=? res=success'UID="root" AUID="unset"`

It seems that the msg field contains a preceded space. Should we allow to parse that?

Or should we submit an issue to auditd because SYSTEM_SHUTDOWN is not well formatted?

```
{
    "record_type": "SYSTEM_SHUTDOWN",
    "timestamp": 1725041662447,
    "id": 172,
    "fields": {
        "ses": 4294967295,
        "auid": 4294967295,
        "pid": 834299,
        "uid": 0,
        "msg": " comm=\"systemd-update-utmp\" exe=\"/usr/lib/systemd/systemd-update-utmp\" hostname=? addr=? terminal=? res=success"
    },
    "enrichment": {
        "AUID": "unset",
        "UID": "root"
    }
},
```

#NCompass-Cloudtrax

#Description

1. Receives HTTP POST requests from the [CloudTrax Presence Reporting API](https://help.cloudtrax.com/hc/en-us/articles/207985916-CloudTrax-Presence-Reporting-API
) containing JSON

2. Parses JSON and stores each item in probe_requests as a row in example.db (SQLite)

3. Displays all ProbeRequests from example.db

CloudTrax usually sends a request every 30 seconds, but there is an option to change the rate.

Python, Flask, SQLAlchemy, and Marshmallow

## Sample JSON
```
{
  "network_id": 179283,
  "node_mac": "AC:86:74:61:4F:C0",
  "version": 1,
  "probe_requests": [
    {
      "mac": "14:2d:27:29:16:f7",
      "count": 26,
      "min_signal": -74,
      "max_signal": -64,
      "avg_signal": -68,
      "first_seen": 1455845796,
      "last_seen": 1455845819,
      "associated": false
    },
    {
      "mac": "48:5a:3f:37:de:f7",
      "count": 10,
      "min_signal": -37,
      "max_signal": -26,
      "avg_signal": -30,
      "first_seen": 1455845791,
      "last_seen": 1455845811,
      "associated": true
    },
    {
      "mac": "4e:20:5d:18:d0:ab",
      "count": 1,
      "min_signal": -90,
      "max_signal": -90,
      "avg_signal": -90,
      "first_seen": 1455845809,
      "last_seen": 1455845809,
      "associated": false
    },
    {
      "mac": "68:96:7b:c8:8b:e9",
      "count": 4,
      "min_signal": -54,
      "max_signal": -5,
      "avg_signal": -27,
      "first_seen": 1455845817,
      "last_seen": 1455845817,
      "associated": false
    },
    {
      "mac": "80:19:34:b8:bc:1c",
      "count": 2,
      "min_signal": -65,
      "max_signal": -61,
      "avg_signal": -63,
      "first_seen": 1455845819,
      "last_seen": 1455845820,
      "associated": false
    }
  ]
}
```

#Install
```
  git clone https://github.com/f00-/ncompass-cloudtrax.git
  cd ncompass-cloudtrax
  virtualenv env
  source env/bin/activate
  pip install -r requirements.txt
  python app.py
```

  Go to http://127.0.0.1:5000/test to add sample ProbeRequests and go to http://127.0.0.1:5000/ to view them
  
#Usage

Shows table of ProbeRequests

```
  /
  /?limit=100
```

Filters table of ProbeRequests by node or client's mac address

```
  /filter?mac=
  /filter?node_mac=
  /filter?mac=&node_mac=
```

Receives HTTP Post request from Cloudtrax

```
  /receive
```


Adds test ProbeRequests to the database


```
  /test
```

#Note about iPhones/iOS
iOS sends a random mac address to wifi networks while scanning, so you can only track iOS devices after they have connected to wifi (when associated = 1 in probe request)

#Dependency Documentation

[CloudTrax Presence Reporting API Documentation](https://help.cloudtrax.com/hc/en-us/articles/207985916-CloudTrax-Presence-Reporting-API
)

[Flask Documentation](http://flask.pocoo.org/)

[Flask-SQLAlchemy Documentation](http://flask-sqlalchemy.pocoo.org/2.1/)

[Marshmallow-SQLAlchemy Documentation](https://marshmallow-sqlalchemy.readthedocs.io/en/latest/)

[Heroku Procfile](https://devcenter.heroku.com/articles/procfile)

[Virtualenv Documentation](https://virtualenv.pypa.io/en/stable/)

[pip and requirements.txt](https://pip.readthedocs.io/en/1.1/requirements.html)

from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import json
import arrow

# initialize flask as app, sqlalchemy as db & marshmallow as ma
# also set database URI
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
db = SQLAlchemy(app)
ma = Marshmallow(app)

# https://help.cloudtrax.com/hc/en-us/articles/207985916-CloudTrax-Presence-Reporting-API
# sqlalchemy model
class ProbeRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.String(120))
    node_mac = db.Column(db.String(120))
    mac = db.Column(db.String(120))
    count = db.Column(db.String(120))
    min_signal = db.Column(db.String(120))
    max_signal = db.Column(db.String(120))
    avg_signal = db.Column(db.String(120))
    first_seen = db.Column(db.String(120))
    last_seen = db.Column(db.String(120))
    associated = db.Column(db.String(120))

    def __init__(self, network_id, node_mac, mac, count, min_signal, max_signal,
                    avg_signal, first_seen, last_seen, associated):
        self.network_id = network_id
        self.node_mac = node_mac
        self.mac = mac
        self.count = count
        self.min_signal = min_signal
        self.max_signal = max_signal
        self.avg_signal = avg_signal
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.associated = associated

    def __repr__(self):
        return '<Mac %r>' % self.mac

# marshmallow schema
class ProbeRequestSchema(ma.ModelSchema):
    class Meta:
        model = ProbeRequest

# flask routes

# show stored ProbeRequests
@app.route("/")
def show():

    # retrieve ProbeRequests
    if 'limit' in request.args:
        probes = ProbeRequest.query.order_by(ProbeRequest.last_seen.desc()).limit(request.args.get('limit')).all()
    else:
        probes = ProbeRequest.query.order_by(ProbeRequest.last_seen.desc()).all()

    for probe in probes:
        probe.first_seen = arrow.get(probe.first_seen).format('YYYY-MM-DD HH:mm:ss ZZ')
        probe.last_seen = arrow.get(probe.last_seen).format('YYYY-MM-DD HH:mm:ss ZZ')

    return render_template('show.html', probes=probes)

# store ProbeRequests from Cloudtrax
@app.route('/recieve', methods=['POST'])
def recieve():
    # get json that cloudtrax HTTP POST'd to this URL
    json_string = request.data
    parsed_json = json.loads(json_string.decode())

    # loop through probe_requests
    for probe in parsed_json['probe_requests']:
        # create new ProbeRequest row
        probe = ProbeRequest(parsed_json['network_id'], parsed_json['node_mac'], probe['mac'], probe['count'], probe['min_signal'], probe['max_signal'], probe['avg_signal'], probe['first_seen'], probe['last_seen'], probe['associated'])
        db.session.add(probe)

    # commit db changes
    db.session.commit()

    return render_template('recieve.html', data="success!")

# store sample ProbeRequests
@app.route('/test')
def test():
    # sample json string
    json_string = '{"network_id":179283,"node_mac":"AC:86:74:61:4F:C0","version":1,"probe_requests": [{"mac":"14:2d:27:29:16:f7","count":26,"min_signal":-74,"max_signal":-64,"avg_signal":-68,"first_seen":1455845796,"last_seen":1455845819,"associated":false},{"mac":"48:5a:3f:37:de:f7","count":10,"min_signal":-37,"max_signal":-26,"avg_signal":-30,"first_seen":1455845791,"last_seen":1455845811,"associated":true},{"mac":"4e:20:5d:18:d0:ab","count":1,"min_signal":-90,"max_signal":-90,"avg_signal":-90,"first_seen":1455845809,"last_seen":1455845809,"associated":false},{"mac":"68:96:7b:c8:8b:e9","count":4,"min_signal":-54,"max_signal":-5,"avg_signal":-27,"first_seen":1455845817,"last_seen":1455845817,"associated":false},{"mac":"80:19:34:b8:bc:1c","count":2,"min_signal":-65,"max_signal":-61,"avg_signal":-63,"first_seen":1455845819,"last_seen":1455845820,"associated":false}]}'
    parsed_json = json.loads(json_string)

    # loop through probe_requests
    for probe in parsed_json['probe_requests']:
        # create new ProbeRequest row
        probe = ProbeRequest(parsed_json['network_id'], parsed_json['node_mac'], probe['mac'], probe['count'], probe['min_signal'], probe['max_signal'], probe['avg_signal'], probe['first_seen'], probe['last_seen'], probe['associated'])
        db.session.add(probe)

    # commit db changes
    db.session.commit()

    #return success
    return render_template('recieve.html', data="success!")

@app.route('/filter')
def filter():
    mac = request.args.get('mac')
    node_mac = request.args.get('node_mac')

    if 'mac' in request.args and 'node_mac' in request.args:
        probes = ProbeRequest.query.filter_by(mac=mac).filter_by(node_mac=node_mac).all()
    elif 'node_mac' in request.args:
        probes = ProbeRequest.query.filter_by(node_mac=node_mac).all()
    elif 'mac' in request.args:
        probes = ProbeRequest.query.filter_by(mac=mac).all()
    else:
        probes = None

    for probe in probes:
        probe.first_seen = arrow.get(probe.first_seen).format('YYYY-MM-DD HH:mm:ss ZZ')
        probe.last_seen = arrow.get(probe.last_seen).format('YYYY-MM-DD HH:mm:ss ZZ')

    return render_template('show.html', probes=probes)

@app.route('/nodes_seen/<mac>')
def nodes_seen(mac):
    probes = ProbeRequest.query.filter_by(mac=mac).all()
    nodes_seen = []
    for probe in probes:
        nodes_seen.append(probe.node_mac)

    return nodes_seen

@app.route('/last_seen')
def last_seen(mac):
    probes = ProbeRequest.query.filter_by(mac=mac).all()
    #sort by last seen in ascending order
    #return first value

# this code only executes if file is run directly
if __name__ == "__main__":
    # creates database with models
    db.create_all()
    # start flask server
    app.run()

import geocoder
import requests
import pprint
import re
import random
import geohash
import logging
import os
import elasticsearch
import datetime
import elasticsearch.helpers
import json
import argparse
import yaml

from geopy.geocoders import Nominatim
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class es():
    def __init__(self, es_config):
        _es_config = es_config

        try:
            if _es_config['use_ssl']:
                self.es_eng = elasticsearch.Elasticsearch(
                    _es_config['nodes'],
                    port=_es_config['port'],
                    http_auth=(_es_config['user'] + ':' + _es_config['password']),
                    verify_certs=_es_config['verify_certs'],
                    use_ssl=_es_config['use_ssl'],
                    ca_certs=_es_config['ca_cert']
                )
            else:
                self.es_eng = elasticsearch.Elasticsearch(
                    _es_config['nodes'],
                    port=_es_config['port'],
                    #http_auth=(_es_config['user'] + ':' + _es_config['password'])
                )
        except Exception as _exc:
            print('ERR: [es:__init__]: Error with establishing connection with elastic cluster:', _exc)
            self.es_eng = False

    def bulk_insert(self, es_config, js_arr):
        _es_config = es_config
        _js_arr = js_arr
        _shards = _es_config['shards']
        _replicas = _es_config['replicas']
        _date_pattern = '{0:%Y}'.format(datetime.datetime.today())
        _index = _es_config['pattern'] + _date_pattern

        _map = {
            "mappings": {
                "properties": {
                    "prefix": {"type": "ip_range"},
                    "siteIpRanges": {"type": "keyword"},
                    "ipAddresses": {"type": "ip"},
                    "targetForTests": {"type": "ip"},
                    "publicIpAddresses": {"type": "ip"},
                    "timestamp": {"type": "date", "format": "yyyy-MM-dd' 'HH:mm:ss"},
                    "dateEnd": {"type": "date", "format": "yyyy-MM-dd' 'HH:mm:ss"},
                    "dateStart": {"type": "date", "format": "yyyy-MM-dd' 'HH:mm:ss"},
                    "agent_dateEnd": {"type": "date", "format": "yyyy-MM-dd' 'HH:mm:ss"},
                    "agent_dateStart": {"type": "date", "format": "yyyy-MM-dd' 'HH:mm:ss"},
                    "dateCreated": {"type": "date", "format": "yyyy-MM-dd' 'HH:mm:ss"},
                    "dateOfLastAlertStateChange": {"type": "date", "format": "yyyy-MM-dd' 'HH:mm:ss"},
                    "agentName": {"type": "keyword"},
                    "agentState": {"type": "keyword"},
                    "agentType": {"type": "keyword"},
                    "countryId": {"type": "keyword"},
                    "enabled": {"type": "keyword"},
                    "location": {"type": "keyword"},
                    "agentId": {"type": "keyword"},
                    "active": {"type": "keyword"},
                    "metric": {"type": "integer"},
                    "alertId": {"type": "keyword"},
                    "ruleName": {"type": "keyword"},
                    "siteId": {"type": "keyword"},
                    "siteName": {"type": "keyword"},
                    "applicationName": {"type": "keyword"},
                    "ruleId": {"type": "keyword"},
                    "instance": {"type": "keyword"},
                    "alertState": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "apm": {"type": "keyword"},
                    "violationCount": {"type": "keyword"},
                    "agent_active": {"type": "keyword"},
                    "agent_agentId": {"type": "keyword"},
                    "agent_agentName": {"type": "keyword"},
                    "deviceName": {"type": "keyword"},
                    "deviceSerial": {"type": "keyword"},
                    "geohash": {"type": "geo_point"},
                    "lat": {"type": "float"},
                    "lng": {"type": "float"},
                }
            }
        }

        _body = {
            "settings": {
                "number_of_shards": _shards,
                "number_of_replicas": _replicas
            },
            "mappings": _map["mappings"]
        }

        _actions = [
            {
                "_index": _index,
                "_source": json.dumps(_js)
            }
            for _js in _js_arr
        ]

        if self.es_eng:
            if not self.es_eng.indices.exists(index=_index):
                try:
                    self.es_eng.indices.create(index=_index, body=_body)
                except Exception as _err:
                    print('ERR: [es:bulk_insert]', _err)
                    return False
            try:
                elasticsearch.helpers.bulk(self.es_eng, _actions, chunk_size=50, request_timeout=30, yield_ok=False)
            except Exception as _err:
                print('ERR: [es:bulk_insert]', _err)
                return False
            else:
                return True


class Livenx():
    def __init__(self, base_url, token):
        self.pp = pprint.PrettyPrinter(indent=2, width=80)
        self.token = str(token)
        self.base_url = str(base_url)
        self.timestamp = '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.utcnow())

        # LogLevels: DEBUG, INFO, WARNING, ERROR, CRITICAL
        self.logger = logging.getLogger('livenx')
        self.logger.setLevel(logging.DEBUG)
        _root_dir = os.path.dirname(os.path.abspath(__file__))
        _log_path = os.path.join(_root_dir, 'projectx.log')
        _fh = logging.FileHandler(_log_path)
        _fh.setLevel(logging.DEBUG)
        _formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        _fh.setFormatter(_formatter)
        self.logger.addHandler(_fh)

    def _date_transformation(self, ts):
        _ts = ts
        _dateStart = ''

        # 2020-05-13T07:17:19.313Z
        _pattern = re.compile(r'(?P<year>\d+)-'
                              r'(?P<month>\d+)-'
                              r'(?P<day>\d+)T'
                              r'(?P<hour>\d+):'
                              r'(?P<minute>\d+):'
                              r'(?P<second>\d+)\.')
        try:
            _match = _pattern.match(_ts)
        except:
            self.logger.error('WRN: [livenx:_date_transformation]: There was an error occurred with dateCreated re.match')
            self.logger.error(_ts)
        else:
            if _match:
                _dict = _match.groupdict()
                _dateStart = str(_dict['year']) + "-"\
                                    + str(_dict['month']) + "-"\
                                    + str(_dict['day']) + " "\
                                    + str(_dict['hour']) + ":"\
                                    + str(_dict['minute']) + ":"\
                                    + str(_dict['second'])

        return _dateStart

    def alerts(self, sites):
        _alerts = []
        _sites = sites
        _bearer_token = 'Bearer ' + self.token
        _headers = {"Authorization": _bearer_token,
                    "accept": "application/json"}

        _url = self.base_url + 'alerting/alerts'
        _payload = {
            'allActiveOnly': 'false'
        }

        try:
            _response = requests.get(_url,
                                     params=_payload,
                                     verify=False,
                                     headers=_headers
                                     )
        except Exception as _ex:
            _msg = 'ERR: [livenx:alerts]:' + str(_ex)
            self.logger.error(_msg)
        else:
            _js = json.loads(_response.text)

            for _alert in _js:
                _dict = {'alertId': _alert['alertId'],
                         'alertCategory': _alert['alertCategory'],
                         'apm': 'livenx',
                         'instance': 'alert',
                         'timestamp': self.timestamp,
                         'alertState': _alert['alertState'],
                         'metric': random.randint(0, 5),
                         }

                if 'dateCreated' in _alert:
                    _dict['dateCreated'] = self._date_transformation(ts=_alert['dateCreated'])
                if 'dateOfLastAlertStateChange' in _alert:
                    _dict['dateOfLastAlertStateChange'] = self._date_transformation(ts=_alert['dateOfLastAlertStateChange'])

                if 'description' in _alert:
                    if 'details' in _alert['description']:
                        try:
                            _dict['tags'] = _alert['description']['details'][2]['value']
                        except Exception as _ex:
                            print('EXC: [livenx:alerts]:', _ex)
                            pass

                    if 'details' in _alert['description']:
                        try:
                            _dict['applicationName'] = _alert['description']['details'][2]['value']
                        except Exception as _ex:
                            print('EXC: [livenx:alerts]:', _ex)
                            pass

                    if 'sourceInfo' in _alert['description']:
                        try:
                            _deviceSerial = _alert['description']['sourceInfo'][0]['rawValue']['deviceSerial']
                            _deviceName = _alert['description']['sourceInfo'][0]['rawValue']['deviceName']
                        except Exception as _ex:
                            print('EXC: [livenx:alerts]:', _ex)
                            pass
                        else:
                            _dict['deviceName'] = _deviceName
                            _dict['deviceSerial'] = _deviceSerial
                            if _deviceSerial in _sites:
                                if ('lat' in _sites[_deviceSerial]) and ('lng' in _sites[_deviceSerial]):
                                    _lat = _sites[_deviceSerial]['lat']
                                    _lng = _sites[_deviceSerial]['lng']
                                    _dict['geohash'] = _sites[_deviceSerial]['geohash']

                                    _geolocator = Nominatim()
                                    _latlng = str(_lat) + ', ' + str(_lng)
                                    _location = _geolocator.reverse(_latlng)

                                    if _location:
                                        _location = _location.raw
                                        if 'address' in _location:
                                            _country = str(_location['address']['country'])
                                            if 'city' in _location['address']:
                                                _city = str(_location['address']['city'])
                                                _dict['location'] = _country + ', ' + _city
                                            elif 'state' in _location['address']:
                                                _state = str(_location['address']['state'])
                                                _dict['location'] = _country + ', ' + _state

                    if 'summary' in _alert['description']:
                        _dict['summary'] = _alert['description']['summary']

                    if 'title' in _alert['description']:
                        _dict['title'] = _alert['description']['title']

                _alerts.append(_dict)

        # self.pp.pprint(_alerts)

        return _alerts

    def sites(self):
        _sites = {}
        _bearer_token = 'Bearer ' + self.token
        _headers = {"Authorization": _bearer_token,
                    "accept": "application/json"}

        _url = self.base_url + 'sites'

        try:
            _response = requests.get(_url,
                                     verify=False,
                                     headers=_headers
                                     )
        except Exception as _ex:
            _msg = 'ERR: [livenx:sites]:' + str(_ex)
            self.logger.error(_msg)
        else:
            _js = json.loads(_response.text)

            for _site in _js['sites']:
                if _site['id'] not in 'Unspecified':
                    _dict = {'siteId': _site['id'],
                             'timestamp': self.timestamp,
                             'siteName': _site['siteName'],
                             'instance': 'site',
                             'apm': 'livenx',
                             'tags': _site['tags']
                             }

                    if 'siteIpRanges' in _site:
                        _site['siteIpRanges'] = _site['siteIpRanges']

                    if 'position' in _site:
                        _dict['geohash'] = geohash.encode(_site['position']['latitude'], _site['position']['longitude'])
                        _dict['lat'] = _site['position']['latitude']
                        _dict['lng'] = _site['position']['longitude']

                    if 'mailingAddress' in _site:
                        if ('city' in _site['mailingAddress']) and ('country' in _site['mailingAddress']):
                            _city = str(_site['mailingAddress']['city'])
                            _country = str(_site['mailingAddress']['country'])

                            if (len(_country) > 1) and (_country not in 'None') and (len(_city) > 1) and (_city not in 'None'):
                                _dict['location'] = _city + ',' + _country
                            elif (_country in 'None') and (_city not in 'None'):
                                _dict['location'] = _city
                            elif (_country not in 'None') and (_city in 'None'):
                                _dict['location'] = _country
                            elif (len(_country) > 1) and (len(_city) < 1):
                                _dict['location'] = _country
                            elif (len(_country) < 1) and (len(_city) > 1):
                                _dict['location'] = _city
                            else:
                                _dict['location'] = 'Null, Null'
                        else:
                            _dict['location'] = 'Null, Null'

                    if 'devices' in _site:
                        for _device in _site['devices']['devices']:
                            _dict['deviceName'] = _device['deviceName']
                            _dict['deviceSerial'] = _device['deviceSerial']

                            _sites[_device['deviceSerial']] = _dict

        # self.pp.pprint(_sites)

        return _sites


class Thousandeyes():
    def __init__(self, base_url, user, password, window):
        self.pp = pprint.PrettyPrinter(indent=2, width=80)
        self.password = str(password)
        self.user = str(user)
        self.base_url = str(base_url)
        self.window = str(window)
        self.timestamp = '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.utcnow())

        # LogLevels: DEBUG, INFO, WARNING, ERROR, CRITICAL
        self.logger = logging.getLogger('Thousandeyes')
        self.logger.setLevel(logging.DEBUG)
        _root_dir = os.path.dirname(os.path.abspath(__file__))
        _log_path = os.path.join(_root_dir, 'projectx.log')
        _fh = logging.FileHandler(_log_path)
        _fh.setLevel(logging.DEBUG)
        _formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        _fh.setFormatter(_formatter)
        self.logger.addHandler(_fh)

    def _geo(self, location):
        _location = location
        _dict = {}

        try:
            _g = geocoder.komoot(location)
            _g_json = _g.json
        except Exception as _ex:
            _msg = 'ERR: [thousandeyes:_geo]:' + str(_ex)
            self.logger.error(_msg)
            return False
        else:
            if _g_json:
                if ('status' in _g_json) and (_g_json['status'] in 'OK'):
                    _dict['lat'] = _g_json['lat']
                    _dict['lng'] = _g_json['lng']
                    _dict['geohash'] = geohash.encode(_g_json['lat'], _g_json['lng'])

                    return _dict
            else:
                self.logger.error('ERR: [thousandeyes:_geo]: There is an error occurred while getting geo info.')
                self.logger.error('ERR: [thousandeyes:_geo]: Failed object looks like:')
                self.logger.error(_g_json)

                return False

    def agents(self):
        _agents = {}
        _url = self.base_url + 'agents.json'
        _payload = {
            'format': 'json',
            'window': self.window
        }

        try:
            _response = requests.get(_url,
                                     auth=HTTPBasicAuth(self.user, self.password),
                                     params=_payload,
                                     verify=False)
        except Exception as _ex:
            _msg = 'ERR: [thousandeyes:agents]:' + str(_ex)
            self.logger.error(_msg)
        else:
            _js = json.loads(_response.text)

            if _js:
                _g_dict = {}
                for _agent in _js['agents']:
                    if 'agentType' in _agent:
                        _dict = {'agentId': _agent['agentId'],
                                 'agentName': _agent['agentName'],
                                 'agentType': _agent['agentType'],
                                 'countryId': _agent['countryId'],
                                 'location': _agent['location'],
                                 'timestamp': self.timestamp,
                                 'instance': 'agent',
                                 'apm': 'thousandeyes',
                                 }

                        _g = self._geo(location=_agent['location'])
                        if _g:
                            _dict['lat'] = _g['lat']
                            _dict['lng'] = _g['lng']
                            _dict['geohash'] = _g['geohash']

                        if 'agentState' in _agent:
                            _dict['agentState'] = _agent['agentState']

                        if 'targetForTests' in _agent:
                            _dict['targetForTests'] = _agent['targetForTests']

                        if 'ipAddresses' in _agent:
                            _dict['ipAddresses'] = _agent['ipAddresses']

                        if 'publicIpAddresses' in _agent:
                            _dict['publicIpAddresses'] = _agent['publicIpAddresses']

                        if 'clusterMembers' in _agent:
                            for _member in _agent['clusterMembers']:
                                if 'memberId' in _member:
                                    _dict['cluster_memberId'] = _member['memberId']

                                if 'publicIpAddresses' not in _dict:
                                    _dict['publicIpAddresses'] = []
                                if 'targetForTests' not in _dict:
                                    _dict['targetForTests'] = []
                                if 'ipAddresses' not in _dict:
                                    _dict['ipAddresses'] = []

                                if 'publicIpAddresses' in _member:
                                    if isinstance(_member['publicIpAddresses'], list):
                                        _dict['publicIpAddresses'].extend(_member['publicIpAddresses'])
                                    else:
                                        _dict['publicIpAddresses'].append(_member['publicIpAddresses'])
                                if 'targetForTests' in _member:
                                    if isinstance(_member['targetForTests'], list):
                                        _dict['targetForTests'].extend(_member['targetForTests'])
                                    else:
                                        _dict['targetForTests'].append(_member['targetForTests'])
                                if 'ipAddresses' in _member:
                                    if isinstance(_member['ipAddresses'], list):
                                        _dict['ipAddresses'].extend(_member['ipAddresses'])
                                    else:
                                        _dict['targetForTests'].append(_member['targetForTests'])

                                _agents[_agent['agentId']] = _dict
                        else:
                            _agents[_agent['agentId']] = _dict

        # self.pp.pprint(_agents)

        return _agents

    def alerts(self, agents):
        _alerts = []
        _agents = agents
        _url = self.base_url + 'alerts.json'
        _payload = {
            'format': 'json',
            'window': self.window
        }

        try:
            _response = requests.get(_url,
                                     auth=HTTPBasicAuth(self.user, self.password),
                                     params=_payload,
                                     verify=False)
        except Exception as _ex:
            _msg = 'ERR: [thousandeyes:alerts]:' + str(_ex)
            self.logger.error(_msg)
        else:
            _js = json.loads(_response.text)

            if _js:
                for _alert in _js['alert']:
                    _dict = {'alertId': _alert['alertId'],
                             'ruleId': _alert['ruleId'],
                             'metric': _alert['violationCount'],
                             'ruleName': _alert['ruleName'],
                             'testId': _alert['testId'],
                             'testName': _alert['testName'],
                             'type': _alert['type'],
                             'violationCount': _alert['violationCount'],
                             'active': _alert['active'],
                             'timestamp': self.timestamp,
                             'instance': 'alert',
                             'apm': 'thousandeyes',
                             'tags': _alert['testName']
                             }

                    if 'dateStart' in _alert:
                        _dict['dateStart'] = _alert['dateStart']
                    else:
                        _dict['dateStart'] = self.timestamp

                    if 'dateEnd' in _alert:
                        _dict['dateEnd'] = _alert['dateEnd']
                    else:
                        _dict['dateEnd'] = self.timestamp

                    if 'agents' in _alert:
                        for _agent in _alert['agents']:
                            _dict['agent_active'] = _agent['active']
                            _dict['agent_agentId'] = _agent['agentId']
                            _dict['agent_agentName'] = _agent['agentName']

                            if _agent['agentId'] in _agents:
                                _dict['geohash'] = _agents[_agent['agentId']]['geohash']

                            if 'dateEnd' in _agent:
                                _dict['agent_dateEnd'] = _agent['dateEnd']

                            if 'dateStart' in _agent:
                                _dict['agent_dateStart'] = _agent['dateStart']

                            if 'metricsAtStart' in _agent:
                                _dict['metricsAtStart'] = _agent['metricsAtStart']

                            if 'metricsAtEnd' in _agent:
                                _dict['metricsAtEnd'] = _agent['metricsAtEnd']

                            _alerts.append(_dict)

        # self.pp.pprint(_alerts)

        return _alerts

import es
import thousandeyes
import livenx

if __name__=="__main__":
    startTime = datetime.datetime.now()
    pp = pprint.PrettyPrinter(indent=4)

    argparser = argparse.ArgumentParser(usage='%(prog)s [options]')
    argparser.add_argument('-c', '--conf',
                           help='Set full path to the configuration file.',
                           default='conf.yml')
    argparser.add_argument('-v', '--verbose',
                           help='Set verbose run to true.',
                           action='store_true')
    argparser.add_argument('-a', '--apm',
                           help='Set the APM we want to run for: thousandeyes or livenx.',
                           default='thousandeyes')

    args = argparser.parse_args()

    verbose = args.verbose
    apm = args.apm

    if (apm in 'thousandeyes') or (apm in 'livenx'):
        root_dir = os.path.dirname(os.path.realpath(__file__))
        conf_path_full = str(root_dir) + os.sep + str(args.conf)

        with open(conf_path_full, 'r') as reader:
            try:
                cf = yaml.safe_load(reader)
            except yaml.YAMLError as ex:
                print('ERR: [main]', ex)
                exit(1)
            else:
                if verbose:
                    pp.pprint(cf)

                js_arr = []

                if apm in 'livenx':
                    session = livenx.Livenx(base_url=cf['livenx']['base_url'], token=cf['livenx']['token'])

                    sites = session.sites()
                    js_arr.extend(sites.values())
                    alerts = session.alerts(sites=sites)
                    js_arr.extend(alerts)

                elif apm in 'thousandeyes':
                    session = thousandeyes.Thousandeyes(base_url=cf['thousandeyes']['base_url'],
                                                        user=cf['thousandeyes']['user'],
                                                        password=cf['thousandeyes']['password'],
                                                        window=cf['thousandeyes']['window'])

                    agents = session.agents()
                    js_arr.extend(agents.values())
                    alerts = session.alerts(agents=agents)
                    js_arr.extend(alerts)

                if js_arr:
                    es_eng = es.es(es_config=cf['es_config'])
                    es_eng.bulk_insert(es_config=cf['es_config'], js_arr=js_arr)

    else:
        print('ERR: [main]: Please specify the right mode for script running: thousandeyes or livenx')

    print(datetime.datetime.now() - startTime)

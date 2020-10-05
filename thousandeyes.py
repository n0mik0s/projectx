import requests
import json
import pprint
import datetime
import geocoder
import geohash
import logging
import os

from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


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

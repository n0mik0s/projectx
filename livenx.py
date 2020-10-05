import requests
import json
import pprint
import datetime
import re
import random
import geohash
import logging
import os

from geopy.geocoders import Nominatim
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


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

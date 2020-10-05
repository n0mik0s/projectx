import elasticsearch
import datetime
import elasticsearch.helpers
import json

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

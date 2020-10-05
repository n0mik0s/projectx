import argparse
import os
import pprint
import yaml
import datetime
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

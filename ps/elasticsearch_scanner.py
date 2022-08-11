from loguru import logger
from elasticsearch import Elasticsearch
from urllib.parse import quote_plus as urlquote
from psex import ScannerEngine
from psex.funcs.assetio import AssetIO
from psex.weaks import weak_passwords


class ElasticsearchScanner(ScannerEngine):
    def __init__(self):
        super(ElasticsearchScanner, self).__init__()

    @logger.catch(level='ERROR')
    def is_connected(self, connection):
        try:
            r = connection.info()
            if 'You Know, for Search' in str(r):
                logger.success(f'[+] {r}')
                return True
            return False
        except Exception as e:
            logger.error(f'[-] {e}')
            return False

    @logger.catch(level='ERROR')
    def create_connect(self, *args):
        connection = Elasticsearch([f'{args[0]}:{args[1]}'], http_auth=(args[2], urlquote(args[3])), timeout=self.timeout)
        return connection

    @logger.catch(level='ERROR')
    def dia(self, target_file: str = 'targets.csv'):
        asset_io = AssetIO()
        ips = asset_io.get_file_assets(target_file)
        passwords = weak_passwords('elasticsearch')
        for user_pwd in passwords:
            username = list(user_pwd.keys())[0]
            password = list(user_pwd.values())[0]
            for ip_port in ips:
                ip_port = ip_port.strip()
                ip = ip_port.split(':')[0]
                port = int(ip_port.split(':')[1])
                logger.debug(f'Connecting to {ip} ......')
                logger.warning(f'Testing {ip_port} with: {username}/{password} !')
                result = self.poc(ip, port, username, password)
                if result:
                    asset_io.save2file('elasticsearch_success', ip, port, username, password)


if __name__ == '__main__':
    es = ElasticsearchScanner()
    es.dia()

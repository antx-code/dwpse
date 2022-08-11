from loguru import logger
from pymongo import MongoClient
from urllib.parse import quote_plus as urlquote
from psex import ScannerEngine
from psex.funcs.assetio import AssetIO
from psex.weaks import weak_passwords


class MongodbScanner(ScannerEngine):
    def __init__(self):
        super(MongodbScanner, self).__init__()

    @logger.catch(level='ERROR')
    def is_connected(self, connection):
        try:
            connection.list_database_names()
            connection.close()
            return True
        except Exception as e:
            connection.close()
            return False

    @logger.catch(level='ERROR')
    def create_connect(self, *args):
        connection = MongoClient(host=args[0], port=args[1], username=args[2], password=urlquote(args[3]), socketTimeoutMS=self.timeout_ms, connectTimeoutMS=self.timeout_ms, serverSelectionTimeoutMS=self.timeout_ms)
        return connection

    @logger.catch(level='ERROR')
    def dia(self, target_file: str = 'targets.csv'):
        asset_io = AssetIO()
        ips = asset_io.get_file_assets(target_file)
        passwords = weak_passwords('mongodb')
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
                    asset_io.save2file('mongodb_success', ip, port, username, password)


if __name__ == '__main__':
    ms = MongodbScanner()
    ms.dia()

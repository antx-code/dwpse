from loguru import logger
from sqlalchemy import create_engine
from urllib.parse import quote_plus as urlquote
from psex import ScannerEngine
from psex.funcs.assetio import AssetIO
from psex.weaks import weak_passwords


class ClickhouseScanner(ScannerEngine):
    def __init__(self):
        super(ClickhouseScanner, self).__init__()

    @logger.catch(level='ERROR')
    def is_connected(self, connection):
        try:
            con = connection.connect()
            con.connection.close()
            return True
        except Exception as e:
            return False

    @logger.catch(level='ERROR')
    def create_connect(self, *args):
        connection = create_engine(f"clickhouse://{args[2]}:{urlquote(args[3])}@{args[0]}:{args[1]}/default?timeout=2", connect_args={'connect_timeout': self.timeout})
        return connection

    @logger.catch(level='ERROR')
    def dia(self, target_file: str = 'targets.csv'):
        asset_io = AssetIO()
        ips = asset_io.get_file_assets(target_file)
        passwords = weak_passwords('clickhouse')
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
                    asset_io.save2file('clickhouse_success', ip, port, username, password)


if __name__ == '__main__':
    cs = ClickhouseScanner()
    cs.dia()

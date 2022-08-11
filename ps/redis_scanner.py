from loguru import logger
from redis import Redis
from psex import ScannerEngine
from psex.funcs.assetio import AssetIO
from psex.weaks import weak_passwords


class RedisScanner(ScannerEngine):
    def __init__(self):
        super(RedisScanner, self).__init__()

    @logger.catch(level='ERROR')
    def is_connected(self, connection):
        try:
            connection.ping()
            return True
        except Exception as e:
            return False

    @logger.catch(level='ERROR')
    def create_connect(self, *args):
        connection = Redis(host=args[0], password=args[3], port=args[1], db=0, socket_connect_timeout=self.timeout, socket_timeout=self.timeout)
        return connection

    @logger.catch(level='ERROR')
    def dia(self, target_file: str = 'targets.csv'):
        asset_io = AssetIO()
        ips = asset_io.get_file_assets(target_file)
        passwords = weak_passwords('redis')
        for password in passwords:
            for ip_port in ips:
                ip_port = ip_port.strip()
                ip = ip_port.split(':')[0]
                port = int(ip_port.split(':')[1])
                logger.debug(f'Connecting to {ip} ......')
                logger.warning(f'Testing {ip_port} with password: "{password}" !')
                result = self.poc(ip, port, '', password)
                if result:
                    asset_io.save2file('redis_success', ip, port, '', password)


if __name__ == '__main__':
    rs = RedisScanner()
    rs.dia()

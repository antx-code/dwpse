from loguru import logger
from redis import Redis
from typing import Union
import re
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
        try:
            connection = Redis(host=args[0], password=args[3], port=args[1], db=0, socket_connect_timeout=self.timeout, socket_timeout=self.timeout)
        except Exception as e:
            connection = False
        return connection

    @logger.catch(level='ERROR')
    def dia(self, mode: str, target_file: str, passwords: Union[list, str] = None,
            fofa_grammar: str = None, fofa_key: str = None, fofa_email: str = None):
        asset_io = AssetIO()

        if mode != 'file':
            if not fofa_grammar or not fofa_key or not fofa_email:
                raise Exception('Fofa mode required fofa grammar, fofa key and fofa email.')
            ips = asset_io.get_fofa_assets(fofa_grammar, fofa_key, fofa_email, target_file)
        else:
            ips = asset_io.get_file_assets(target_file)

        if not passwords:
            passwords = weak_passwords('redis')
        elif isinstance(passwords, str):
            if re.search(r'\.(txt|csv)$', passwords):
                with open(passwords, 'r+') as f:
                    passwords = f.readlines()
            else:
                passwords = [passwords]
        else:
            raise Exception('Unsupported password types.')

        for password in passwords:
            for ip_port in ips:
                ip_port = ip_port.strip()
                ip = ip_port.split(':')[0]
                port = int(ip_port.split(':')[1])
                logger.debug(f'Connecting to {ip} ......')
                logger.warning(f'Testing {ip_port} with password: "{password.strip()}" !')
                result = self.poc(ip, port, '', password.strip())
                if result:
                    asset_io.save2file('redis_success', ip, port, '', password.strip())


if __name__ == '__main__':
    rs = RedisScanner()
    rs.dia()

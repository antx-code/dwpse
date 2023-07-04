from loguru import logger
from sqlalchemy import create_engine
from typing import Union
import re
import csv
from urllib.parse import quote_plus as urlquote
from psex import ScannerEngine
from psex.funcs.assetio import AssetIO
from psex.weaks import weak_passwords
from rich.console import Console
console = Console()


class PostgresqlScanner(ScannerEngine):
    def __init__(self):
        super(PostgresqlScanner, self).__init__()

    @logger.catch(level='ERROR')
    def is_connected(self, connection):
        try:
            connection.connect()
            return True
        except Exception as e:
            return False

    @logger.catch(level='ERROR')
    def create_connect(self, *args):
        try:
            connection = create_engine(f'postgresql://{args[2]}:{urlquote(args[3])}@{args[0]}:{args[1]}/postgres', connect_args={'connect_timeout': self.timeout})
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
            passwords = weak_passwords('postgresql')
        elif isinstance(passwords, str):
            if re.search(r'\.(txt|csv)$', passwords):
                with open(passwords, 'r+') as f:
                    if passwords.endswith('.txt'):
                        passwords = [line.strip().split() for line in f]
                    elif passwords.endswith('.csv'):
                        reader = csv.reader(f)
                        passwords = [row for row in reader]
                    else:
                        error_message = """
                        csv file content must be like: username,password
                        txt file content must be like: username password
                        """
                        console.print(error_message, style="bold red")
                        raise Exception('Unsupported file format.')
            else:
                passwords = [passwords]
        else:
            raise Exception('Unsupported password types.')

        for user_pwd in passwords:
            username, password = next(iter(user_pwd.items()))
            for ip_port in ips:
                ip, port = ip_port.strip().split(':')
                port = int(port)
                logger.debug(f'Connecting to {ip} ......')
                logger.warning(f'Testing {ip_port} with: {username}/{password} !')
                result = self.poc(ip, port, username, password)
                if result:
                    asset_io.save2file('postgresql_success', ip, port, username, password)


if __name__ == '__main__':
    ps = PostgresqlScanner()
    ps.dia()

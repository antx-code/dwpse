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
        try:
            connection = create_engine(f"clickhouse://{args[2]}:{urlquote(args[3])}@{args[0]}:{args[1]}/default?timeout={self.timeout}", connect_args={'connect_timeout': self.timeout})
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
            passwords = weak_passwords('clickhouse')
        elif isinstance(passwords, str):
            if re.search(r'\.(txt|csv)$', passwords):
                with open(passwords, 'r+') as f:
                    if passwords.endswith('.txt'):
                        passwords = [{pwd.split(' ')[0].strip(): pwd.split(' ')[1].strip()} for pwd in f.readlines()]
                    elif passwords.endswith('.csv'):
                        try:
                            passwords = [{pwd[0].strip(): pwd[1].strip()} for pwd in csv.reader(f.readlines())]
                        except Exception as e:
                            passwords = [{pwd.strip()[0].strip(): pwd.strip()[1].strip()} for pwd in f.readlines()]
                    else:
                        error_message = """
                        csv file content must be like: username,password
                        txt file content must be like: username password
                        """
                        console.print(error_message, style="bold red")
                        raise Exception('Unsupported file format.')
            else:
                pwd = passwords.split(',')
                passwords = [{pwd[0].strip(): pwd[1].strip()}]
        else:
            raise Exception('Unsupported password types.')

        for ip_port in ips:
            ip, port = ip_port.strip().split(':')
            port = int(port)
            logger.debug(f'Connecting to {ip} ......')
            for user_pwd in passwords:
                username, password = next(iter(user_pwd.items()))
                password = password.strip()
                logger.warning(f'Testing {ip_port} with: {username}/{password} !')
                result = self.poc(ip, port, username, password)
                if result:
                    asset_io.save2file('clickhouse_success', ip, port, username, password)
                    logger.success(f'Found {ip_port} with password: "{password}" !')
                    break


if __name__ == '__main__':
    cs = ClickhouseScanner()
    cs.dia()

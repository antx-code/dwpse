from loguru import logger
import typer
from typing import Optional, Union
from typing_extensions import Annotated
import importlib


app = typer.Typer(help='Database Weak Password Scanner Engine Tool')


def run(database: str, mode: str, target_file: str, passwords: Union[list, str] = None,
        fofa_grammar: str = None, fofa_key: str = None, fofa_email: str = None):
    db = database.capitalize()
    try:
        package = importlib.import_module(f"ps.{database}_scanner")
    except ImportError as e:
        package = importlib.import_module(f".{database}_scanner", package='ps')
    getattr(package, f'{db}Scanner')().dia(mode, target_file, passwords, fofa_grammar, fofa_key, fofa_email)


@app.command()
def dia(database: Annotated[str, typer.Argument()],
        targets: Annotated[str, typer.Argument()],
        mode: Annotated[Optional[str], typer.Argument(help="Use file or fofa mode to scan")] = 'file',
        passwords: Annotated[Optional[str], typer.Option(help="Password list or a file (txt or csv format).")] = '',
        fofa_grammar: Annotated[Optional[str], typer.Option(help="Fofa search grammar")] = '',
        fofa_key: Annotated[Optional[str], typer.Option(help="Fofa account api key")] = '',
        fofa_email: Annotated[Optional[str], typer.Option(help="Fofa account email")] = ''):
    typer.echo(f'Welcome to Antx Database Weak Password Scanner Engine Tool.')
    if mode not in ['file', 'fofa']:
        raise Exception('Unsupported mode.')
    if database not in ['redis', 'mongodb', 'mysql', 'postgresql', 'clickhouse', 'elasticsearch', 'mssql']:
        raise Exception('Unsupported database.')

    run(database, mode, targets, passwords, fofa_grammar, fofa_key, fofa_email)


if __name__ == '__main__':
    app()

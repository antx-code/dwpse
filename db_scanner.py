from loguru import logger
import typer
import importlib

app = typer.Typer(help='Database Weak Password Scanner Engine Tool')


@app.command()
def dia(database: str, target_file: str):
    logger.info(f'Welcome to Antx Database Weak Password Scanner Engine Tool.')
    db = database.capitalize()
    try:
        package = importlib.import_module(f"ps.{database}_scanner")
        getattr(package, f'{db}Scanner')().dia(target_file)
    except ImportError:
        package = importlib.import_module(f".{database}_scanner", package='ps')
        getattr(package, f'{db}Scanner')().dia(target_file)

if __name__ == '__main__':
    app()

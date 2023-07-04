# dwpse
A simple, fast and powerful database weak password scanner engine tool was built by antx, which based on psex.

## Description
dwpse is a simple, fast and powerful database weak password scanner engine tool was built by antx, which based on psex. 
psex also is a simple, fast and powerful password scanner engine tool was built by antx. psex also support some useful features, 
which like fofa search and parse assets to verify. psex has been built in some weak username and password.

## Install

```bash
git clone https://github.com/antx-code/dwpse.git
```

## Install Dependencies
```shell
poetry install
```

## Usage

You must have a target csv file to scan and the target csv file content format is as follows:

```csv
ip:port
```

If you want to use custom username and password, you can create a file named `username_password.txt`,
and the content format is as follows:

```text
username password
```

also you can use `username_password.csv` and the content format is as follows:

```csv
username,password
```

### DWPSE Sample:

#### command line sample:
See the help for more information.
```shell
python3 db_scanner.py --help
```
run with default username and password:
```shell
python3 db_scanner.py redis targets.csv
```
use custom username and password:
```shell
python3 db_scanner.py redis targets.csv --passwords=username_password.txt
```
use fofa search and parse assets to verify:
```shell
python3 db_scanner.py redis targets.csv --passwords=username_password.txt --fofa_grammar='title="redis"' --fofa_key='xxx' --fofa_email='xxx@email.com'
```
```

#### python3 lib sample:

```python
# Title: xxxxxxx
# Author: antx
# Email: 7877940+antx-code@users.noreply.github.com

from db_scanner import dia

if __name__ == '__main__':
    dia('redis', 'targets.csv')
```

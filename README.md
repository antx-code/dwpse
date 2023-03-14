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

### DWPSE Sample:

#### command line sample:

```shell
python3 db_scanner.py redis targets.csv
```

#### python3 lib sample:

```python
# Title: xxxxxxx
# Author: antx
# Email: wkaifeng2007@163.com

from db_scanner import dia

if __name__ == '__main__':
    dia('redis', 'input/targets.csv')
```

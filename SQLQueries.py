from dune_analytics import Dune
from keymanager import KeyManager as km

dune = Dune("davidthegardens", km().Easy_Key("dune_key"))

results = dune.query('''
    SELECT
        *
    FROM tornado_cash."eth_call_withdraw"
    LIMIT 100
''')
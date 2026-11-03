import psutil
print("CONN_CLOSED:", hasattr(psutil, 'CONN_CLOSED'))
print("CONN_TIME_WAIT:", hasattr(psutil, 'CONN_TIME_WAIT'))
print("CONN_NONE:", hasattr(psutil, 'CONN_NONE'))
print("All CONN_ attrs:", [a for a in dir(psutil) if a.startswith('CONN_')])

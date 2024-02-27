
class config():
    def sql_db_config():
        mysql={
            "host": "localhost",
            "user": "root",
            "passwd": "Nikhil1234$",
            "db": "renote_login_sql_db",
        }
        return mysql
    def azure_storage_string():
        return 'DefaultEndpointsProtocol=https;AccountName=necunblobstorage;AccountKey=hgzRK0zpgs+bXf4wnfvFLEJNbSMlbTNeJBuhYHS9jcTrRTzlh0lVlT7K59U8yG0Ojh65p/c4sV97+AStOXtFWw==;EndpointSuffix=core.windows.net'
    
    def container_name():
        return 'pictures'
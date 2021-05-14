import os
class config(object):
    SECRET_KEY = os.environ.get("SECRET_KEY") or "lames@17.com"
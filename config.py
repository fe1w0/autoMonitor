import yaml

def load_config_file(config_file):
    try:
        file = open(config_file, 'r', encoding="utf-8")
        data = yaml.load(file, Loader=yaml.SafeLoader)
        return data
    except:
        print("[!] Fail to read config file")

monitor_config = load_config_file("config/config.yaml")
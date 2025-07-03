import requests
import logging
from base64 import b64encode
import urllib3

# Отключаем предупреждения SSL для самоподписных сертификатов
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NetAppAPI:
    def __init__(self, api_username, api_password, api_ip, logger):
        self.api_user = api_username
        self.api_password = api_password
        self.api_ip = api_ip
        self.logger = logger
        self.base_url = f"https://{api_ip}/api"
        self.session = requests.Session()

        creds = f"{api_username}:{api_password}"
        token = b64encode(creds.encode()).decode()
        self.session.headers.update({
            'Authorization': f'Basic {token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })

    def __enter__(self):
        resp = self.session.get(f"{self.base_url}/cluster", verify=False, timeout=10)
        resp.raise_for_status()
        self.logger.info(f"Подключение к NetApp {self.api_ip} установлено")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()
        return False

    def get(self, endpoint, params=None):
        url = f"{self.base_url}/{endpoint}"
        resp = self.session.get(url, params=params, verify=False, timeout=15)
        self.logger.debug(f"GET {url} params={params} => {resp.status_code}")
        resp.raise_for_status()
        return resp.json()

    def get_aggregates(self):
        params = {'fields': 'name,space.block_storage'}
        data = self.get('storage/aggregates', params=params)
        return data.get('records', [])

    def get_volumes(self):
        params = {'fields': 'name,size,aggregates,svm'}
        data = self.get('storage/volumes', params=params)
        return data.get('records', [])

    def get_svms(self):
        params = {'fields': 'name,uuid,state'}
        data = self.get('svm/svms', params=params)
        return data.get('records', [])


def bytes_to_tib(val):
    try:
        return float(val) / (1024 ** 4)
    except Exception:
        return 0.0


def perform_netapp_discovery(api_username, api_password, storage_ip, storage_name, logger):
    logger.info(f"Начало discovery NetApp {storage_name} ({storage_ip})")
    pools = []
    volumes_list = []
    svms_list = []
    total_capacity = 0

    try:
        with NetAppAPI(api_username, api_password, storage_ip, logger) as api:
            # 1. Агрегаты
            aggs = api.get_aggregates()
            for agg in aggs:
                blk = agg.get('space', {}).get('block_storage', {})
                size = int(blk.get('size', 0))
                used = int(blk.get('used', 0))
                avail = int(blk.get('available', 0))
                total_capacity += size
                pools.append({
                    'storage_name': storage_name,
                    'pool_name': agg.get('name', ''),
                    'dataspace': round(bytes_to_tib(size), 2),
                    'used_capacity': round(bytes_to_tib(used), 2),
                    'free_capacity': round(bytes_to_tib(avail), 2),
                    'subscribed_capacity': 0.0
                })

            # 2. Тома
            vols = api.get_volumes()
            for vol in vols:
                vol_size = int(vol.get('size', 0))

                # Получаем имя агрегата
                agg_raw = vol.get('aggregates', [])
                aggregate_name = ''
                if agg_raw and isinstance(agg_raw[0], dict):
                    aggregate_name = agg_raw[0].get('name', '')
                elif isinstance(agg_raw, list):
                    aggregate_name = agg_raw[0] if isinstance(agg_raw[0], str) else ''

                # Имя SVM
                svm_obj = vol.get('svm')
                svm_name = svm_obj.get('name') if isinstance(svm_obj, dict) else svm_obj

                volume_entry = {
                    'storage_name': storage_name,
                    'name': vol.get('name', ''),
                    'size': round(bytes_to_tib(vol_size), 2),
                    'aggregate': aggregate_name,
                    'svm': svm_name
                }
                volumes_list.append(volume_entry)

                # Добавляем подписку в агрегат
                for pool in pools:
                    if pool['pool_name'] == aggregate_name:
                        pool['subscribed_capacity'] += round(bytes_to_tib(vol_size), 2)

            # сортировка томов по имени агрегата
            volumes_list.sort(key=lambda x: x['aggregate'] or '')

            # 3. SVM
            svms = api.get_svms()
            for svm in svms:
                svms_list.append({
                    'storage_name': storage_name,
                    'name': svm.get('name', ''),
                    'uuid': svm.get('uuid', ''),
                    'state': svm.get('state', '')
                })

    except Exception as e:
        logger.exception(f"Ошибка discovery NetApp для {storage_name}: {e}")
        return {
            'pools': [],
            'luns': [],
            'initiators': [],
            'storage_metrics': {storage_name: {'total_effective_tb': 0.0}}
        }

    return {
        'pools': pools,
        'luns': volumes_list,
        'initiators': svms_list,
        'storage_metrics': {
            storage_name: {
                'total_effective_tb': round(bytes_to_tib(total_capacity), 2)
            }
        }
    }

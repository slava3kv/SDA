# huawei.py
import requests
import json
import logging
import urllib3

# Отключаем предупреждения SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def sectors_to_tib(sectors):
    """Конвертирует секторы (512 байт) в TiB"""
    if sectors is None:
        return 0.0
    try:
        bytes_value = int(sectors) * 512
        return round(bytes_value / (1024**4), 3)
    except (ValueError, TypeError):
        return 0.0


class HuaweiAPI:
    def __init__(self, api_username, api_password, api_ip, api_port, logger):
        self.api_user = api_username
        self.api_password = api_password
        self.api_ip = api_ip
        self.api_port = api_port
        self.logger = logger
        self.device_id = None
        self.iBaseToken = None
        self.cookies = None
        self.base_url = f"https://{api_ip}:{api_port}/deviceManager/rest"

    def __enter__(self):
        login_url = f"{self.base_url}//sessions"
        payload = json.dumps({
            'scope': '0', 
            'username': self.api_user, 
            'password': self.api_password
        })
        headers = {
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        try:
            response = requests.post(
                login_url, verify=False, data=payload, 
                headers=headers, timeout=10
            )
            response.raise_for_status()
        except requests.exceptions.Timeout as te:
            self.logger.error(f"Connection Timeout Error during login to {self.api_ip}")
            raise Exception(
                f"Connection Timeout Error during login to {self.api_ip}"
            ) from te
        except Exception as e:
            self.logger.exception(f"Failed to connect to API at {self.api_ip}")
            raise Exception(
                f"Failed to connect to API at {self.api_ip}"
            ) from e

        try:
            data = response.json()
            self.device_id = data['data']['deviceid']
            self.iBaseToken = data['data']['iBaseToken']
            self.cookies = response.cookies
            self.logger.info(f"Logged in successfully to {self.api_ip}")
        except (KeyError, json.JSONDecodeError) as e:
            self.logger.exception(f"Invalid login response from {self.api_ip}")
            raise Exception(
                f"Invalid login response from {self.api_ip}"
            ) from e
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.iBaseToken or not self.device_id:
            return False
            
        logout_url = f"{self.base_url}/{self.device_id}//sessions"
        headers = {
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'iBaseToken': self.iBaseToken
        }
        try:
            response = requests.delete(
                logout_url, verify=False, headers=headers, 
                cookies=self.cookies, timeout=5
            )
            self.logger.info(f"Logged out successfully from {self.api_ip}")
        except Exception as e:
            self.logger.warning(f"Failed to logout from {self.api_ip}: {str(e)}")
        return False

    def get(self, endpoint, params=None, timeout=15):
        """Выполняет GET запрос к Huawei REST API"""
        url = f"{self.base_url}/{self.device_id}/{endpoint}"
        headers = {
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'iBaseToken': self.iBaseToken
        }
        try:
            response = requests.get(
                url, params=params, verify=False, headers=headers,
                cookies=self.cookies, timeout=timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout при GET {endpoint} от {self.api_ip}")
            raise Exception(f"Timeout при GET {endpoint} от {self.api_ip}")
        except Exception as e:
            self.logger.exception(f"Ошибка при GET {endpoint} от {self.api_ip}")
            raise Exception(f"Ошибка при GET {endpoint} от {self.api_ip}") from e

    def get_pools(self):
        """Получает список пулов хранения"""
        return self.get("storagepool")

    def get_luns(self):
        """Получает список LUN"""
        return self.get("lun")

    def get_initiators(self):
        """Получает список инициаторов"""
        return self.get("iscsi_initiator")

    def get_system_info(self):
        """Получает информацию о системе"""
        return self.get("system/")

    def get_effective_capacity_info(self):
        """Получает информацию об эффективной емкости"""
        return self.get("effective_capacity_info")


def perform_huawei_discovery(api_username, api_password, storage_ip, storage_name, logger):
    """
    Выполняет discovery для Huawei Dorado системы
    
    Returns:
        dict: Данные о пулах, LUN, инициаторах и метриках
    """
    logger.info(f"Запуск Huawei Discovery для {storage_name} ({storage_ip})")
    
    all_pools = []
    all_luns = []
    all_initiators = []
    storage_metrics = {}
    
    try:
        with HuaweiAPI(api_username, api_password, storage_ip, 8088, logger) as api:
            # 1) Получаем пулы
            logger.info(f"Получение пулов для {storage_name}")
            pools_response = api.get_pools()
            logger.info(f"Huawei pools response: {pools_response}")
            
            pools_dict = {}  # Для связи пулов с LUN
            
            for pool in pools_response.get('data', []):
                pool_size = pool.get('TOTALCAPACITY', '0')
                pool_free = pool.get('FREECAPACITY', '0')
                pool_used = pool.get('USEDCAPACITY', '0')
                
                logger.info(f"Huawei пул {pool.get('NAME', '')}: TOTALCAPACITY={pool_size}, FREECAPACITY={pool_free}, USEDCAPACITY={pool_used}")
                
                # Конвертируем в TiB
                size_tib = sectors_to_tib(pool_size)
                free_tib = sectors_to_tib(pool_free)
                used_tib = sectors_to_tib(pool_used)
                
                pool_name = pool.get('NAME', '')
                pool_id = pool.get('ID', '')
                pools_dict[pool_id] = {
                    'name': pool_name,
                    'capacity': size_tib,
                    'luns_size': 0  # Будет заполнено при обработке LUN
                }
                
                pool_info = {
                    "storage_name": storage_name,
                    "pool_name": pool_name,
                    "dataspace": size_tib,
                    "used_capacity": used_tib,
                    "free_capacity": free_tib,
                    "subscribed_capacity": 0  # Будет обновлено позже
                }
                all_pools.append(pool_info)
                logger.info(f"Huawei пул добавлен: {pool_info}")

            # 2) Получаем LUN
            logger.info(f"Получение LUN для {storage_name}")
            luns_response = api.get_luns()
            logger.info(f"Huawei LUN response: найдено {len(luns_response.get('data', []))} LUN")
            
            # Группируем LUN по пулам для расчета подписки
            luns_by_pool = {}
            
            for lun in luns_response.get('data', []):
                lun_capacity = lun.get('CAPACITY', '0')
                lun_size_tib = sectors_to_tib(lun_capacity)
                
                # Получаем ID пула
                parent_id = lun.get('PARENTID', '')
                
                if parent_id not in luns_by_pool:
                    luns_by_pool[parent_id] = 0
                luns_by_pool[parent_id] += lun_size_tib

                lun_info = {
                    "storage_name": storage_name,
                    "name": lun.get('NAME', ''),
                    "size": lun_size_tib,
                    "wwn": lun.get('WWN', ''),
                    "pool_id": parent_id
                }
                all_luns.append(lun_info)

            # 3) Обновляем информацию о подписке для пулов
            for pool in all_pools:
                # Находим ID пула по имени
                pool_id = None
                for pid, pinfo in pools_dict.items():
                    if pinfo['name'] == pool['pool_name']:
                        pool_id = pid
                        break
                
                if pool_id:
                    luns_total_size = luns_by_pool.get(pool_id, 0)
                    pool['subscribed_capacity'] = luns_total_size
                    logger.info(f"Huawei пул {pool['pool_name']}: подписка обновлена до {luns_total_size} TiB")

            # 4) Эффективная емкость
            logger.info(f"Получение эффективной емкости для {storage_name}")
            current_total_effective_tb = 0.0
            try:
                effective_capacity_response = api.get_effective_capacity_info()
                logger.info(f"Huawei effective capacity response: {effective_capacity_response}")
                
                if (effective_capacity_response and 
                    'data' in effective_capacity_response and 
                    effective_capacity_response['data']):
                    total_effective_sectors = effective_capacity_response['data'].get(
                        'totalEffectiveCapacity'
                    )
                    if total_effective_sectors is not None:
                        current_total_effective_tb = sectors_to_tib(total_effective_sectors)
                        logger.info(f"Эффективная емкость для {storage_name}: {current_total_effective_tb} TiB")
                    else:
                        logger.warning(
                            f"Поле 'totalEffectiveCapacity' отсутствует в ответе для "
                            f"{storage_name}. Ответ: {effective_capacity_response}"
                        )
                else:
                    logger.warning(
                        f"Не удалось получить данные 'effective_capacity_info' или "
                        f"они пусты для {storage_name}. Ответ: {effective_capacity_response}"
                    )
            except Exception as e:
                logger.warning(f"Ошибка получения эффективной емкости для {storage_name}: {e}")
            
            storage_metrics[storage_name] = {
                "total_effective_tb": current_total_effective_tb
            }

            # 5) Получаем инициаторы
            logger.info(f"Получение инициаторов для {storage_name}")
            try:
                initiators_response = api.get_initiators()
                logger.info(f"Huawei initiators response: найдено {len(initiators_response.get('data', []))} инициаторов")
                
                for initiator in initiators_response.get('data', []):
                    initiator_info = {
                        "storage_name": storage_name,
                        "iqn": initiator.get('ID', ''),
                        "host_name": initiator.get('USECHAP', ''),  # Может быть другое поле
                        "init_status": "Online" if initiator.get('RUNNINGSTATUS') == '28' else "Offline",
                        "hostIP": ""  # Huawei не всегда предоставляет IP
                    }
                    all_initiators.append(initiator_info)
                    
            except Exception as e:
                logger.warning(f"Не удалось получить инициаторы для {storage_name}: {e}")

            logger.info(
                f"Huawei Discovery завершен для {storage_name}: "
                f"пулов={len(all_pools)}, LUN={len(all_luns)}, инициаторов={len(all_initiators)}, "
                f"эффективная емкость={current_total_effective_tb} TiB"
            )

    except Exception as e:
        logger.exception(f"Huawei Discovery не выполнен для {storage_name} ({storage_ip}): {str(e)}")
        storage_metrics[storage_name] = {"total_effective_tb": 0.0}

    return {
        "pools": all_pools,
        "luns": all_luns,
        "initiators": all_initiators,
        "storage_metrics": storage_metrics
    }
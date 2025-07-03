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
        # Приводим к строке и очищаем от возможных пробелов
        sectors_str = str(sectors).strip()
        if not sectors_str or sectors_str == '0':
            return 0.0
        
        sectors_float = float(sectors_str)
        if sectors_float == 0:
            return 0.0
            
        bytes_value = sectors_float * 512
        tib_value = bytes_value / (1024**4)
        return round(tib_value, 3)
    except (ValueError, TypeError) as e:
        logging.getLogger("huawei").warning(f"Ошибка конвертации секторов {sectors}: {e}")
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

    def get_storagepools(self):
        """Получает список пулов хранения (используем правильный эндпоинт)"""
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
    Выполняет discovery для Huawei Dorado системы (основано на рабочей версии)
    
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
            # 1) Получаем пулы (используем правильный метод)
            logger.info(f"Получение пулов для {storage_name}")
            storagepools_response = api.get_storagepools()
            logger.info(f"Huawei pools response: {storagepools_response}")
            
            # Группируем LUN по пулам для расчета подписки
            pools_dict = {}
            
            for pool in storagepools_response.get('data', []):
                pool_name = pool.get('NAME', '').replace(' ', '_')
                pool_id = pool.get('ID', '')
                
                # Используем правильные поля из рабочей версии
                dataspace_sectors = pool.get('DATASPACE', 0)
                subscribed_sectors = pool.get('SUBSCRIBEDCAPACITY', 0)
                
                # Логируем для отладки
                logger.info(f"Пул {pool_name}: DATASPACE={dataspace_sectors}, SUBSCRIBEDCAPACITY={subscribed_sectors}")
                
                # Конвертируем в TiB
                dataspace_tib = sectors_to_tib(dataspace_sectors)
                subscribed_tib = sectors_to_tib(subscribed_sectors)
                
                # Для совместимости с интерфейсом рассчитываем used и free
                # Предполагаем, что subscribed ~ used, а free = dataspace - subscribed
                used_tib = subscribed_tib
                free_tib = max(0, dataspace_tib - subscribed_tib)
                
                pools_dict[pool_id] = {
                    'name': pool_name,
                    'capacity': dataspace_tib
                }
                
                pool_info = {
                    "storage_name": storage_name,
                    "pool_name": pool_name,
                    "dataspace": dataspace_tib,
                    "used_capacity": used_tib,
                    "free_capacity": free_tib,
                    "subscribed_capacity": subscribed_tib
                }
                all_pools.append(pool_info)
                logger.info(f"Добавлен пул: {pool_info}")

            # 2) Получаем LUN
            logger.info(f"Получение LUN для {storage_name}")
            luns_response = api.get_luns()
            logger.info(f"Huawei LUN response: найдено {len(luns_response.get('data', []))} LUN")
            
            for lun in luns_response.get('data', []):
                lun_name = lun.get('NAME', '').replace(' ', '_')
                lun_wwn = lun.get('WWN', '').replace(' ', '_')
                
                # Используем логику из рабочей версии для размера
                lun_capacity = lun.get('CAPACITY', 0)
                lun_sector_size = lun.get('SECTORSIZE', 512)
                
                if lun_capacity and lun_sector_size:
                    # (CAPACITY * SECTORSIZE) / (1024^4)
                    lun_size_tib = sectors_to_tib(int(lun_capacity) * (int(lun_sector_size) / 512.0))
                else:
                    lun_size_tib = 0.0
                
                # Получаем ID пула
                parent_id = lun.get('PARENTID', '')

                lun_info = {
                    "storage_name": storage_name,
                    "name": lun_name,
                    "size": lun_size_tib,
                    "wwn": lun_wwn,
                    "pool_id": parent_id
                }
                all_luns.append(lun_info)

            # 3) Получаем инициаторы (используем логику из рабочей версии)
            logger.info(f"Получение инициаторов для {storage_name}")
            try:
                inits_response = api.get_initiators()
                logger.info(f"Huawei initiators response: найдено {len(inits_response.get('data', []))} инициаторов")
                
                for init in inits_response.get('data', []):
                    initiator_id = init.get("ID", "")
                    parent_name = init.get("PARENTNAME", "")
                    host_ip = init.get("hostIP", "")
                    running_status = init.get("RUNNINGSTATUS", "")
                    
                    # Используем правильный маппинг статусов из рабочей версии
                    if running_status == "27":
                        init_status = "Online"
                    elif running_status == "28":
                        init_status = "Offline"
                    else:
                        init_status = running_status
                    
                    initiator_info = {
                        "storage_name": storage_name,
                        "iqn": initiator_id,
                        "host_name": parent_name,
                        "init_status": init_status,
                        "hostIP": host_ip
                    }
                    all_initiators.append(initiator_info)
                    
            except Exception as e:
                logger.warning(f"Не удалось получить инициаторы для {storage_name}: {e}")

            # 4) Эффективная емкость (как в рабочей версии)
            logger.info(f"Получение эффективной емкости для {storage_name}")
            current_total_effective_tb = 0.0
            try:
                effective_capacity_response = api.get_effective_capacity_info()
                
                if (effective_capacity_response and 
                    'data' in effective_capacity_response and 
                    effective_capacity_response['data']):
                    total_effective_sectors = effective_capacity_response['data'].get('totalEffectiveCapacity')
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
            
            # Если не удалось получить эффективную емкость, используем сумму dataspace пулов
            if current_total_effective_tb == 0:
                current_total_effective_tb = sum(pool['dataspace'] for pool in all_pools)
                logger.info(f"Используем сумму dataspace пулов как эффективную емкость: {current_total_effective_tb} TiB")
            
            storage_metrics[storage_name] = {
                "total_effective_tb": current_total_effective_tb
            }

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
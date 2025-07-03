# ibm.py
import requests
import json
import logging
import urllib3

# Отключаем предупреждения SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IBMAPI:
    def __init__(self, api_username, api_password, api_ip, logger):
        self.api_user = api_username
        self.api_password = api_password
        self.api_ip = api_ip
        self.logger = logger
        self.base_url = f"https://{api_ip}:7443/rest"
        self.session = requests.Session()
        self.auth_token = None

    def __enter__(self):
        # Авторизация для получения токена
        try:
            auth_data = {
                'username': self.api_user,
                'password': self.api_password
            }
            
            response = self.session.post(
                f"{self.base_url}/auth",
                json=auth_data,
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            
            # Получаем токен из заголовков
            self.auth_token = response.headers.get('X-Auth-Token')
            if not self.auth_token:
                raise Exception("Не удалось получить токен авторизации")
            
            # Настраиваем заголовки для дальнейших запросов
            self.session.headers.update({
                'X-Auth-Token': self.auth_token,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
            
            self.logger.info(f"Успешно подключился к IBM FlashSystem {self.api_ip}")
            return self
            
        except Exception as e:
            self.logger.exception(f"Не удалось подключиться к IBM FlashSystem {self.api_ip}")
            raise Exception(f"Не удалось подключиться к IBM FlashSystem {self.api_ip}") from e

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Выход из сессии
        if self.auth_token:
            try:
                self.session.delete(
                    f"{self.base_url}/auth",
                    verify=False,
                    timeout=5
                )
            except:
                pass  # Игнорируем ошибки при выходе
        self.session.close()
        return False

    def get(self, endpoint, params=None, timeout=15):
        """Выполняет GET запрос к IBM REST API"""
        url = f"{self.base_url}/{endpoint}"
        try:
            response = self.session.get(url, params=params, verify=False, timeout=timeout)
            response.raise_for_status()
            
            # IBM возвращает список объектов
            return response.json()
            
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout при GET {endpoint} от {self.api_ip}")
            raise Exception(f"Timeout при GET {endpoint} от {self.api_ip}")
        except Exception as e:
            self.logger.exception(f"Ошибка при GET {endpoint} от {self.api_ip}")
            raise Exception(f"Ошибка при GET {endpoint} от {self.api_ip}") from e

    def get_pools(self):
        """Получает список пулов (mdiskgrp)"""
        return self.get("lsmdiskgrp")

    def get_volumes(self):
        """Получает список томов"""
        return self.get("lsvdisk")

    def get_hosts(self):
        """Получает список хостов"""
        return self.get("lshost")


def bytes_to_tib(bytes_value):
    """Конвертирует байты в TiB"""
    if bytes_value is None:
        return 0.0
    try:
        # IBM часто возвращает значения в разных форматах
        if isinstance(bytes_value, str):
            # Убираем возможные суффиксы TB, GB и т.д.
            bytes_value = bytes_value.replace('TB', '').replace('GB', '').replace('MB', '').strip()
            bytes_value = float(bytes_value)
            
            # Если значение меньше 1024, вероятно это уже в GB или TB
            if bytes_value < 1024:
                return round(bytes_value, 3)  # Предполагаем что это уже в TB
        
        return round(float(bytes_value) / (1024**4), 3)
    except (ValueError, TypeError):
        return 0.0


# Исправленная функция perform_ibm_discovery в ibm.py
def perform_ibm_discovery(api_username, api_password, storage_ip, storage_name, logger):
    """
    Выполняет discovery для IBM FlashSystem
    
    Returns:
        dict: Данные о пулах, томах и метриках
    """
    logger.info(f"Запуск IBM Discovery для {storage_name} ({storage_ip})")
    
    all_pools = []
    all_volumes = []
    all_initiators = []
    storage_metrics = {}
    
    try:
        with IBMAPI(api_username, api_password, storage_ip, logger) as api:
            # 1) Получаем пулы
            logger.info(f"Получение пулов для {storage_name}")
            pools_response = api.get_pools()
            
            total_pool_capacity = 0
            pools_dict = {}  # Для связи пулов с томами
            
            for pool in pools_response:
                pool_capacity = pool.get('capacity', '0')
                pool_free = pool.get('free_capacity', '0')
                pool_used = pool.get('used_capacity', '0')
                
                # Конвертируем емкости
                capacity_tib = bytes_to_tib(pool_capacity)
                free_tib = bytes_to_tib(pool_free)
                used_tib = bytes_to_tib(pool_used)
                
                total_pool_capacity += capacity_tib
                
                pool_name = pool.get('name', '')
                pools_dict[pool_name] = {
                    'capacity': capacity_tib,
                    'volumes_size': 0  # Будет заполнено при обработке томов
                }
                
                pool_info = {
                    "storage_name": storage_name,
                    "pool_name": pool_name,
                    "dataspace": capacity_tib,
                    "used_capacity": used_tib,
                    "free_capacity": free_tib,
                    "subscribed_capacity": 0  # Будет обновлено позже
                }
                all_pools.append(pool_info)

            # 2) Получаем тома
            logger.info(f"Получение томов для {storage_name}")
            volumes_response = api.get_volumes()
            
            # Группируем тома по пулам для расчета подписки
            volumes_by_pool = {}
            
            for volume in volumes_response:
                volume_capacity = volume.get('capacity', '0')
                volume_size_tib = bytes_to_tib(volume_capacity)
                
                # Получаем имя пула
                pool_name = volume.get('mdisk_grp_name', 'unknown')
                
                if pool_name not in volumes_by_pool:
                    volumes_by_pool[pool_name] = 0
                volumes_by_pool[pool_name] += volume_size_tib
                
                volume_info = {
                    "storage_name": storage_name,
                    "name": volume.get('name', ''),
                    "size": volume_size_tib,
                    "wwn": volume.get('vdisk_UID', ''),
                    "pool": pool_name,
                    "status": volume.get('status', '')
                }
                all_volumes.append(volume_info)

            # 3) Обновляем информацию о подписке для пулов
            for pool in all_pools:
                pool_name = pool['pool_name']
                volumes_total_size = volumes_by_pool.get(pool_name, 0)
                pool['subscribed_capacity'] = volumes_total_size

            # 4) Попытка получить хосты (для совместимости с инициаторами)
            try:
                logger.info(f"Получение хостов для {storage_name}")
                hosts_response = api.get_hosts()
                
                for host in hosts_response:
                    host_info = {
                        "storage_name": storage_name,
                        "iqn": host.get('iscsi_name', ''),
                        "host_name": host.get('name', ''),
                        "init_status": "Online" if host.get('status') == 'online' else "Offline",
                        "hostIP": ""  # IBM не всегда предоставляет IP
                    }
                    all_initiators.append(host_info)
                    
            except Exception as e:
                logger.warning(f"Не удалось получить информацию о хостах: {e}")

            # 5) Метрики системы
            storage_metrics[storage_name] = {
                "total_effective_tb": total_pool_capacity
            }

            logger.info(
                f"IBM Discovery завершен для {storage_name}: "
                f"пулов={len(all_pools)}, томов={len(all_volumes)}, хостов={len(all_initiators)}"
            )

    except Exception as e:
        logger.exception(f"IBM Discovery не выполнен для {storage_name} ({storage_ip}): {str(e)}")
        storage_metrics[storage_name] = {"total_effective_tb": 0.0}

    return {
        "pools": all_pools,
        "luns": all_volumes,
        "initiators": all_initiators,
        "storage_metrics": storage_metrics
    }


# Пример использования
# if __name__ == "__main__":
#     logging.basicConfig(level=logging.INFO)
#     logger = logging.getLogger("ibm_test")
    
#     try:
#         result = perform_ibm_discovery(
#             api_username="admin",
#             api_password="password",
#             storage_ip="10.0.0.200",
#             storage_name="pd01-fs9100-001",
#             logger=logger
#         )
        
#         print("Pools:", len(result['pools']))
#         print("Volumes:", len(result['luns']))
#         print("Initiators:", len(result['initiators']))
#         print("Metrics:", result['storage_metrics'])
        
#     except Exception as e:
#         print(f"Ошибка: {e}")

# netbox.py
import pynetbox
import logging

# Настройка логирования
logger = logging.getLogger("netbox")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def fetch_storage_from_netbox(site, api_token, netbox_url="https://netbox.mng.sbercloud.tech/"):
    """
    Получает список систем хранения из NetBox для всех типов (Huawei, NetApp, IBM).
    
    Args:
        site (str): Имя площадки (например, 'pd01').
        api_token (str): API-токен для NetBox.
        netbox_url (str): URL NetBox (по умолчанию из макета).
        
    Returns:
        list: Список словарей с данными систем хранения.
    """
    try:
        # Инициализация API-клиента
        nb = pynetbox.api(netbox_url, token=api_token)
        logger.info(f"Подключение к NetBox: {netbox_url} с токеном {api_token[:10]}...")

        # Подстроки для поиска различных типов систем хранения
        device_substrings = [
            f"{site}-a400",    # NetApp AFF A400
            f"{site}-a800",    # NetApp AFF A800
            f"{site}-asa",     # NetApp ASA
            f"{site}-aff",     # NetApp AFF
            f"{site}-a700",    # NetApp AFF A700
            f"{site}-fas",     # NetApp FAS8xxx
            f"{site}-dor",     # Huawei Dorado
            f"{site}-fs9100"   # IBM FlashSystem 9100
        ]
        
        logger.info(f"Поиск устройств с подстроками: {device_substrings}")

        # Список для хранения данных
        storages = []

        # Поиск устройств по каждой подстроке
        for device_substring in device_substrings:
            logger.info(f"Поиск устройств с подстрокой '{device_substring}' на площадке '{site}'")
            
            try:
                filtered_devices = list(nb.dcim.devices.filter(device_substring, site))
                logger.info(f"Найдено {len(filtered_devices)} устройств для подстроки {device_substring}")

                for device in filtered_devices:
                    device_data = list(device)
                    if len(device_data) < 4:
                        logger.warning(f"Недостаточно данных для устройства: {device}")
                        continue

                    storage_info = {}
                    vendor = "Unknown"
                    
                    for element in device_data:
                        if element[0] == 'name':
                            element_name = element[1]
                            if "enc" in element_name.lower() or "encl" in element_name.lower():
                                logger.info(f"Пропущено устройство с именем '{element_name}' (содержит 'enc' или 'encl')")
                                break
                            storage_info['storage_name'] = element_name
                            
                            # Определение вендора по имени устройства
                            if any(x in element_name.lower() for x in ['dor', 'dorado']):
                                vendor = "Huawei"
                            elif any(x in element_name.lower() for x in ['a400', 'a800', 'asa', 'aff', 'a700', 'fas8']):
                                vendor = "NetApp"
                            elif any(x in element_name.lower() for x in ['fs9100', 'flashsystem']):
                                vendor = "IBM"
                                
                        elif element[0] == 'role':
                            storage_info['storage_role'] = element[1]['name']
                        elif element[0] == 'status':
                            storage_info['storage_status'] = element[1]['label']
                        elif element[0] == 'primary_ip4' and element[1]:
                            storage_info['ip_address'] = element[1]['address'].removesuffix('/26')

                    # Добавляем информацию о вендоре
                    storage_info['vendor'] = vendor

                    # Добавляем только если есть все обязательные поля
                    if 'storage_name' in storage_info and 'ip_address' in storage_info:
                        storages.append(storage_info)
                        logger.info(
                            f"Добавлено устройство: {storage_info['storage_name']} "
                            f"({storage_info['ip_address']}) - {vendor}"
                        )
                    else:
                        logger.warning(
                            f"Пропущено устройство из-за отсутствия обязательных полей: {storage_info}"
                        )
                        
            except Exception as e:
                logger.warning(f"Ошибка при поиске устройств с подстрокой {device_substring}: {str(e)}")
                continue

        logger.info(f"Всего найдено {len(storages)} систем хранения")
        return storages

    except Exception as e:
        logger.error(f"Ошибка при подключении к NetBox: {str(e)}")
        raise Exception(f"Ошибка при подключении к NetBox: {str(e)}")


# Пример использования (для тестирования)
if __name__ == "__main__":
    try:
        storage_list = fetch_storage_from_netbox(
            site="pd13", 
            api_token="43acbdc7a8aefa7c833381969f2bc43aa08014c7", 
            netbox_url="https://netbox.mng.sbercloud.tech/"
        )
        
        for storage in storage_list:
            print(f"Vendor: {storage.get('vendor', 'Unknown')}, "
                  f"Name: {storage.get('storage_name')}, "
                  f"IP: {storage.get('ip_address')}")
            
    except Exception as e:
        print(f"Ошибка: {e}")

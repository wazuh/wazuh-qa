import os, shutil

def check_existance(source, key):
    if not isinstance(source, dict) and not isinstance(source, list):
        return False

    if key in source:
        return True
    elif isinstance(source, dict):
        for item in source:
            if check_existance(source[item], key):
                return True
        return False
    elif isinstance(source, list):
        for item in source:
            if check_existance(item, key):
                return True
        return False
    else:
        return False

def remove_inexistent(source, check_list, stop_list=None):
    for element in list(source):
        if stop_list and element in stop_list:
            break
        if not check_existance(check_list, element):
            del source[element]
        elif isinstance(source[element], dict):
            remove_inexistent(source[element], check_list, stop_list)

def get_keys_dict(dic):
    keys = []
    for item in dic:
        value = dic[item]
        if isinstance(value, dict):
            result = get_keys_dict(value)
            keys.append({item : result})
        elif isinstance(value, list):
            result = get_keys_list(value)
            keys.append({item : result})
        else:
            keys.append(item)

    if len(keys) == 1:
        return keys[0]
    else:
        return keys

def get_keys_list(dic):
    keys = []
    for item in dic:
        if isinstance(item, dict):
            result = get_keys_dict(item)
            keys.append(result)
        elif isinstance(item, list):
            result = get_keys_list(item)
            keys.append(result)
        else:
            keys.append(item)

    if len(keys) == 1:
        return keys[0]
    else:
        return keys

def find_item(search_item, check):
    for item in check:
        if isinstance(item, dict):
            list_element = list(item.keys())
            if search_item == list_element[0]:
                return list(item.values())[0]
        else:
            if search_item == item:
                return item
    return None

def check_missing_field(source, check):
    missing_filed = None
    for source_field in source:
        if isinstance(source_field, dict):
            key = list(source_field.keys())[0]
            found_item = find_item(key, check)
            if not found_item:
                print(f"Missing key {source_field}")
                return key
            missing_filed = check_missing_field(source_field[key], found_item)
            if missing_filed:
                return missing_filed
        elif isinstance(source_field, list):
            missing_filed = None
            for check_element in check:
                missing_filed = check_missing_field(source_field, check_element)
                if not missing_filed:
                    break
            if missing_filed:
                return source_field
        else:
            found_item = find_item(source_field, check)
            if not found_item:
                print(f"Missing key {source_field}")
                return source_field
    return missing_filed

def clean_folder(folder):
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

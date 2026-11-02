"""Mining duty is configurable; zero must never disable the thermal governor."""
DEFAULT_DUTY = 25


def duty_percent(config):
    value = config.get('gpu_duty_percent', DEFAULT_DUTY)
    if type(value) is not int or not 5 <= value <= 100:
        raise ValueError('gpu_duty_percent debe ser un entero entre 5 y 100; no se permite desactivar el control térmico.')
    return value


def wait_mode(config):
    value = config.get('gpu_wait_mode', 'precise')
    if value not in ('precise', 'legacy'):
        raise ValueError('gpu_wait_mode debe ser precise o legacy.')
    return value


def mining_profile(config):
    return f'rx9070xt-duty{duty_percent(config)}-timer{wait_mode(config)}-halt80-resume60-search300-nodonate-v6'

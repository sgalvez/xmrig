"""Mining duty is configurable; zero must never disable the thermal governor."""
DEFAULT_DUTY = 25


def duty_percent(config):
    value = config.get('gpu_duty_percent', DEFAULT_DUTY)
    if type(value) is not int or not 5 <= value <= 100:
        raise ValueError('gpu_duty_percent debe ser un entero entre 5 y 100; no se permite desactivar el control térmico.')
    return value


def mining_profile(config):
    return f'rx9070xt-duty{duty_percent(config)}-halt80-resume60-search300-nodonate-v5'

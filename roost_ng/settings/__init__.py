# based on from https://github.com/samiconductor/modularsettings
import importlib
import inspect
import pkgutil


class DuplicateDefinition(BaseException):
    pass


def load_settings():
    var_source = {}

    def process_module(module, allow_duplicates=False):
        """ Extract uppercase module globals from module into top-level settings """
        for var_name, val in inspect.getmembers(module):
            if var_name.isupper():
                if var_name in var_source and not allow_duplicates:
                    raise DuplicateDefinition(
                        f"'{var_name}' is being defined by module '{module.__name__}', " +
                        f"was previously defined by module '{var_source[var_name]}'."
                    )
                var_source[var_name] = module.__name__
                globals().update({var_name: val})

    def import_module(module_name):
        """ Import a module relative to this module """
        return importlib.import_module(f'.{module_name}', __name__)

    # First, import everything but overrides.
    have_overrides = False
    for _, module_name, _ in pkgutil.walk_packages(__path__):
        if module_name == 'overrides':
            have_overrides = True
        else:
            process_module(import_module(module_name))

    # Finally, import overrides.
    if have_overrides:
        process_module(import_module('overrides'), allow_duplicates=True)


load_settings()

def only(lst):
    if isinstance(lst, (list, tuple)):
        if len(lst) > 1:
            raise ValueError(f'More than one element in {lst}')
        if lst:
            return lst[0]
    else:
        return lst
    return None


def _str_or_none(value):
    value = only(value)
    if isinstance(value, str) and value:
        return value
    return None


def _bool_or_none(value):
    value = only(value)
    if value and value is not None:
        return bool(value)
    return None


FIELDS = {
    'class_key': _str_or_none,
    'class_key_base': _str_or_none,
    'instance_key': _str_or_none,
    'instance_key_base': _str_or_none,
    'conversation': _str_or_none,
    'recipient': _str_or_none,
    'sender': _str_or_none,
    'is_personal': _bool_or_none,
}


class MessageFilter:
    def __init__(self, **kwargs):
        self.filter_dict = {}
        for field, xform in FIELDS.items():
            value = xform(kwargs.get(field))
            if value:
                self.filter_dict[field] = value

    def __str__(self):
        return f'<MessageFilter: {self.filter_dict}>'

    def apply_to_queryset(self, qs):
        if self.filter_dict:
            qs = qs.filter(**self.filter_dict)
        return qs

    def matches_message(self, msg):
        for field, value in self.filter_dict.items():
            if getattr(msg, field) != value:
                return False
        return True

    # roost defined, but did not use, an is_stricter_than(other) method.
    # I'm skipping it.

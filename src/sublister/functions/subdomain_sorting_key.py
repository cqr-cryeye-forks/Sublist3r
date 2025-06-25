def subdomain_sorting_key(hostname):
    """Sorting key for subdomains

    This sorting key orders subdomains from the top-level domain at the right
    reading left, then moving '^' and 'www' to the top of their group. For
    example, the following list is sorted correctly:

    [
        'example.com',
        'www.example.com',
        'a.example.com',
        'www.a.example.com',
        'b.a.example.com',
        'b.example.com',
        'example.net',
        'www.example.net',
        'a.example.net',
    ]

    """
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0

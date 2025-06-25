from src.subbrute.functions.run import run


def print_target(target, record_type = None, subdomains = "names.txt", resolve_list = "resolvers.txt", process_count = 16, output = False, json_output = False, found_subdomains=[],verbose=False):
    subdomains_list = []
    results_temp = []
    run(target, record_type, subdomains, resolve_list, process_count)
    for result in run(target, record_type, subdomains, resolve_list, process_count):
        (hostname, record_type, response) = result
        if not record_type:
            result = hostname
        else:
            result = "%s,%s" % (hostname, ",".join(response).strip(","))
        if result not in found_subdomains:
            if verbose:
                print(result)
            subdomains_list.append(result)

    return  set(subdomains_list)

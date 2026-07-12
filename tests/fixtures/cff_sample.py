def process_data(items):
    """Process a list of items."""
    result = []
    total = 0
    for item in items:
        if item > 0:
            total += item
            if item > 100:
                result.append("large")
            else:
                result.append("small")
        elif item == 0:
            continue
        else:
            break
    try:
        avg = total / len(result)
    except ZeroDivisionError:
        avg = 0
    return {"items": result, "total": total, "avg": avg}

def simple_add(a, b):
    return a + b

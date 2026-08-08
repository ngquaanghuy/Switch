
def calculate(x, y):
    """This is a docstring"""
    result = x + y
    return result

class MyClass:
    def __init__(self):
        self.value = 10
    
    def get_value(self):
        return self.value

print(calculate(5, 3))
obj = MyClass()
print(obj.get_value())


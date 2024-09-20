import random

def generate_member_id():
    base_id = ''.join([str(random.randint(0, 9)) for _ in range(9)])
    checksum = sum(int(digit) for digit in base_id) % 10
    return base_id + str(checksum)

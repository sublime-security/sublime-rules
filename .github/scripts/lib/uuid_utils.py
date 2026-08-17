"""
UUID generation utilities.
"""
import uuid


def generate_deterministic_uuid(seed_string):
    """
    Generate a deterministic UUID based on a seed string.
    This ensures the same input will always produce the same UUID.

    Args:
        seed_string (str): A string to use as a seed for UUID generation

    Returns:
        str: A UUID string in the format of XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    """
    # Create a namespace UUID (using the DNS namespace as a standard practice)
    namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')

    # Create a UUID using the namespace and the seed string
    deterministic_uuid = uuid.uuid5(namespace, seed_string)

    return str(deterministic_uuid)

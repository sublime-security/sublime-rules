import os
import yaml
import uuid

RULE_DIRS = ['detection-rules']


def _uuid_from_string(string):
    """
    Generates a UUID from a string. This is deterministic, so the same string will always generate the same UUID.
    :param string: string to generate UUID from
    :return: UUID
    """
    return uuid.uuid5(uuid.UUID('00000000-00000000-00000000-00000000'), string)


def generate_rule_ids():
    """
    Generates rule IDs for all rules that don't already have one. This is done by generating a UUID from the rule's
    file path. This is deterministic, so the same file path will always generate the same UUID.

    Also validates that not rule IDs are duplicated.
    """
    known_ids = set()

    for directory in RULE_DIRS:
        for root, dirs, files in os.walk(directory):
            for file in files:
                # CI validates that no .YAML files exist
                if file.endswith('.yml'):
                    # Read the file contents
                    full_file_path = os.path.join(root, file)
                    with open(full_file_path, 'r') as f:
                        contents = f.read()

                        # load the YAML and check if it already has an ID
                        parsed = yaml.safe_load(contents)
                        feed_rule_id = parsed.get('id')

                        if feed_rule_id:
                            # It's expected for this ID not to always match the path generated ID. The purpose of the
                            # ID is to track the rule across moves/renames so the ID is based on the original path.
                            print('Rule {} already assigned an ID of {}'.format(full_file_path, feed_rule_id))
                        else:
                            # Generate a UUID from the file path and write it to the file
                            feed_rule_id = str(_uuid_from_string(full_file_path))
                            if not contents.endswith('\n'):
                                contents += '\n'
                            write_buffer = '{}id: "{}"\n'.format(contents, feed_rule_id)
                            with open(full_file_path, 'w') as f:
                                f.write(write_buffer)

                        if feed_rule_id in known_ids:
                            raise ValueError("ID {} is duplicated. Delete the id field from your rule, and it will be "
                                             "automatically set".format(feed_rule_id))

                        known_ids.add(feed_rule_id)


if __name__ == '__main__':
    generate_rule_ids()
